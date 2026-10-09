// bench_server is the load test of pratique's HTTP server (BACKLOG B-112): a load generator, and Go's own net/http
// server to compare with, serving the same pages with the same certificate (tools/bench_server.sh runs both).
//
//	go run tools/bench_server.go serve -cert cert.pem -key key.pem -addr 127.0.0.1:8443
//	go run tools/bench_server.go load -ca cert.pem [-h1] -c 32 -d 5s URL
//
// load: -c workers send requests one after another for -d, over keep-alive connections (HTTP/1.1: a connection per
// worker; HTTP/2: the transport's one connection, the workers' requests as streams on it), and read each body to its end.
// It prints requests per second, the latency at the 50th, 99th and 99.9th percentiles, bytes per second and errors.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "bench_server serve|load ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "load":
		load(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "bench_server serve|load ...")
		os.Exit(2)
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// The pages of examples/serve.rs that the load test uses: /size/N, and / (a short text).
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cert := fs.String("cert", "cert.pem", "certificate (PEM)")
	key := fs.String("key", "key.pem", "key (PEM)")
	addr := fs.String("addr", "127.0.0.1:0", "address")
	fs.Parse(args)
	var cache sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/size/")); err == nil && strings.HasPrefix(r.URL.Path, "/size/") {
			body, ok := cache.Load(n)
			if !ok {
				body, _ = cache.LoadOrStore(n, pattern(n))
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(n))
			w.Write(body.([]byte))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "hello from go\n")
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	ln, err := tls.Listen("tcp", *addr, mustTLS(*cert, *key))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("listening %s\n", ln.Addr())
	srv.Serve(ln)
}

func mustTLS(cert, key string) *tls.Config {
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return &tls.Config{Certificates: []tls.Certificate{c}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13}
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	ca := fs.String("ca", "cert.pem", "the certificate to trust")
	h1 := fs.Bool("h1", false, "HTTP/1.1 only")
	workers := fs.Int("c", 32, "workers")
	dur := fs.Duration("d", 5*time.Second, "how long")
	fs.Parse(args)
	url := fs.Arg(0)
	pem, err := os.ReadFile(*ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tlsConf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	newTransport := func() *http.Transport {
		t := &http.Transport{TLSClientConfig: tlsConf.Clone(), MaxIdleConnsPerHost: *workers, MaxConnsPerHost: 0, DisableCompression: true}
		if *h1 {
			t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		} else {
			t.ForceAttemptHTTP2 = true
		}
		return t
	}
	shared := newTransport()
	var count, bytes, errors atomic.Int64
	lats := make([][]time.Duration, *workers)
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	buf := make([][]byte, *workers)
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		buf[w] = make([]byte, 64<<10)
		go func(w int) {
			defer wg.Done()
			client := &http.Client{Transport: shared, Timeout: 30 * time.Second}
			for time.Now().Before(deadline) {
				start := time.Now()
				resp, err := client.Get(url)
				if err != nil {
					errors.Add(1)
					continue
				}
				var n int64
				for {
					k, err := resp.Body.Read(buf[w])
					n += int64(k)
					if err != nil {
						break
					}
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					errors.Add(1)
					continue
				}
				lats[w] = append(lats[w], time.Since(start))
				count.Add(1)
				bytes.Add(n)
			}
		}(w)
	}
	wg.Wait()
	var all []time.Duration
	for _, l := range lats {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(p float64) time.Duration {
		if len(all) == 0 {
			return 0
		}
		i := int(p * float64(len(all)-1))
		return all[i]
	}
	secs := dur.Seconds()
	fmt.Printf("%.0f req/s  p50 %.2f ms  p99 %.2f ms  p99.9 %.2f ms  %.1f MB/s  errors %d\n",
		float64(count.Load())/secs, ms(pct(0.5)), ms(pct(0.99)), ms(pct(0.999)), float64(bytes.Load())/secs/1e6, errors.Load())
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
