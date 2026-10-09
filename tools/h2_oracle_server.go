// An HTTP/2 server made of Go's net/http (which is not ours), for checking pratique's HTTP/2 client against
// (tests/h2_client_interop.rs, and by hand for measuring). It makes a root and a leaf certificate for 127.0.0.1 and
// localhost, writes the root to -ca, listens on 127.0.0.1 (-port 0: any), and prints `listening 127.0.0.1:PORT`.
//
//	go run tools/h2_oracle_server.go -ca root.pem [-port N] [-streams N] [-idle 1s] [-h1] [-addr 127.0.0.1]
//
// The pages: /size/N (N bytes of a pattern, with Content-Length), /chunk/N (the same without it), /echo (the request
// body, flushed as it is read), /mirror (the request's header fields and its protocol, as lines of text),
// /headers/N (N response header fields of 100 bytes), /trailers, /early (103 Early Hints, then the answer),
// /reset (some body, then the handler aborts: RST_STREAM), /goaway (the answer with `Connection: close`, which
// makes Go's HTTP/2 server send GOAWAY), /delay/MS (an answer after MS milliseconds), /slow/N (N bytes, one every
// 10 ms), /status/N, /big-header (a response header field of 20000 bytes), /stats (the connections accepted so far, each
// with its protocol and the number of requests it has carried, as text) and /hello.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pattern is n bytes of the pattern, from the start: byte i is 'a' + i%26.
func pattern(n int) []byte { return patternFrom(0, n) }

// patternFrom is n bytes of the pattern from offset off.
func patternFrom(off, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte((off+i)%26)
	}
	return b
}

// cycle is the pattern for a whole number of periods, built once: the big downloads are written from it, a megabyte or so at a
// time, so that the server's own work is the encryption and the framing and not the making of the bytes (the benchmark in
// tools/bench_h2.sh would measure the server's loop otherwise).
var cycle = pattern(26 * 40000)

// writePattern writes n bytes of the pattern from offset 0, in pieces of the cycle.
func writePattern(w io.Writer, n int) {
	for sent := 0; sent < n; {
		k := min(n-sent, len(cycle))
		if _, err := w.Write(cycle[:k]); err != nil {
			return
		}
		sent += k
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func makeCerts(caPath string) tls.Certificate {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h2 oracle test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	ca, err := x509.ParseCertificate(caDER)
	must(err)
	must(os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	must(err)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func number(path, prefix string) (int, bool) {
	if !strings.HasPrefix(path, prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(path, prefix))
	return n, err == nil
}

func main() {
	caPath := flag.String("ca", "oracle-root.pem", "where to write the root certificate")
	port := flag.Int("port", 0, "port (0: any)")
	addr := flag.String("addr", "127.0.0.1", "address to listen on")
	streams := flag.Uint("streams", 0, "SETTINGS_MAX_CONCURRENT_STREAMS (0: Go's default, 250)")
	idle := flag.Duration("idle", 0, "idle timeout of a connection (0: none)")
	h1 := flag.Bool("h1", false, "do not offer HTTP/2: an HTTP/1.1 server")
	tls12 := flag.Bool("tls12", false, "speak TLS 1.2 only")
	flag.Parse()

	cert := makeCerts(*caPath)

	// per accepted connection (numbered from 0 in the order they were accepted): the protocol of the requests it has
	// carried, and how many
	type connInfo struct {
		proto    string
		requests int
	}
	var mu sync.Mutex
	var conns []*connInfo
	type connKey struct{}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "hello %s", r.URL.Path) })
	mux.HandleFunc("/size/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := number(r.URL.Path, "/size/")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		writePattern(w, n)
	})
	mux.HandleFunc("/chunk/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := number(r.URL.Path, "/chunk/")
		f, _ := w.(http.Flusher)
		for sent := 0; sent < n; {
			k := min(n-sent, 10000)
			w.Write(patternFrom(sent, k))
			if f != nil {
				f.Flush()
			}
			sent += k
		}
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		f, _ := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				if f != nil {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/mirror", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto %s\nmethod %s\nhost %s\nuri %s\n", r.Proto, r.Method, r.Host, r.RequestURI)
		var names []string
		for k := range r.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			for _, v := range r.Header[k] {
				if len(v) > 50 {
					v = fmt.Sprintf("<%d bytes>", len(v))
				}
				fmt.Fprintf(w, "%s: %s\n", k, v)
			}
		}
	})
	mux.HandleFunc("/headers/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := number(r.URL.Path, "/headers/")
		for i := 0; i < n; i++ {
			w.Header().Set(fmt.Sprintf("X-Header-%d", i), fmt.Sprintf("%0100d", i))
		}
		fmt.Fprint(w, "many headers\n")
	})
	mux.HandleFunc("/big-header", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("v", 20000))
		fmt.Fprint(w, "one big header\n")
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Sum")
		fmt.Fprint(w, "a body with trailers\n")
		w.Header().Set("X-Sum", "21")
	})
	mux.HandleFunc("/early", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", "</style.css>; rel=preload")
		w.WriteHeader(103)
		w.Header().Del("Link")
		fmt.Fprint(w, "after the early hints\n")
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		w.Write(pattern(1000))
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		panic(http.ErrAbortHandler)
	})
	mux.HandleFunc("/goaway", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "going away\n")
	})
	mux.HandleFunc("/delay/", func(w http.ResponseWriter, r *http.Request) {
		ms, _ := number(r.URL.Path, "/delay/")
		time.Sleep(time.Duration(ms) * time.Millisecond)
		fmt.Fprintf(w, "after %d ms", ms)
	})
	mux.HandleFunc("/slow/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := number(r.URL.Path, "/slow/")
		f, _ := w.(http.Flusher)
		for i := 0; i < n; i++ {
			w.Write([]byte{'a' + byte(i%26)})
			if f != nil {
				f.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := number(r.URL.Path, "/status/")
		w.WriteHeader(n)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "connections %d\n", len(conns))
		for i, c := range conns {
			fmt.Fprintf(w, "connection %d %s %d\n", i, c.proto, c.requests)
		}
	})

	srv := &http.Server{
		// each request is counted on its connection (the one /stats itself is on is counted too)
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, ok := r.Context().Value(connKey{}).(*connInfo); ok {
				mu.Lock()
				c.proto = r.Proto
				c.requests++
				mu.Unlock()
			}
			mux.ServeHTTP(w, r)
		}),
		IdleTimeout: *idle,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			mu.Lock()
			defer mu.Unlock()
			info := &connInfo{}
			conns = append(conns, info)
			return context.WithValue(ctx, connKey{}, info)
		},
	}
	if *tls12 {
		srv.TLSConfig.MinVersion = tls.VersionTLS12
		srv.TLSConfig.MaxVersion = tls.VersionTLS12
	}
	if *h1 {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	} else {
		srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
		srv.HTTP2 = &http.HTTP2Config{}
		if *streams > 0 {
			srv.HTTP2.MaxConcurrentStreams = int(*streams)
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *addr, *port))
	must(err)
	fmt.Printf("listening %s\n", ln.Addr())
	os.Stdout.Sync()
	must(srv.ServeTLS(ln, "", ""))
}
