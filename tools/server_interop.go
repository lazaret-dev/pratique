// A Go client for the interop check of pratique's TLS server (tools/server_interop.sh): crypto/tls and
// net/http, which are not ours, make requests against the `serve` example and report what they saw.
//
//	go run tools/server_interop.go -ca root.pem -addr 127.0.0.1:PORT [-name localhost] [-sizes 0,1,1000,100000,2000000]
//
// It prints one line per check, "ok ..." or "FAIL ...", and exits non-zero if any failed.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
)

var failed = false

func check(ok bool, format string, args ...any) {
	if ok {
		fmt.Printf("ok   "+format+"\n", args...)
	} else {
		failed = true
		fmt.Printf("FAIL "+format+"\n", args...)
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(i%26)
	}
	return b
}

func main() {
	caFile := flag.String("ca", "root.pem", "root certificate (PEM)")
	addr := flag.String("addr", "127.0.0.1:0", "server address")
	name := flag.String("name", "localhost", "server name to ask for and verify")
	sizes := flag.String("sizes", "0,1,1000,100000,2000000", "response sizes to fetch")
	wantALPN := flag.String("alpn", "", "ALPN protocol the server must select (empty: none)")
	wantSuite := flag.String("suite", "", "cipher suite the server must select, e.g. TLS_AES_128_GCM_SHA256 (empty: any)")
	flag.Parse()

	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fmt.Println("FAIL", err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	check(pool.AppendCertsFromPEM(pem), "the root certificate loads")

	// A raw crypto/tls connection: what was negotiated.
	var protos []string
	if *wantALPN != "" {
		protos = []string{*wantALPN, "http/1.1"}
	}
	conn, err := tls.Dial("tcp", *addr, &tls.Config{RootCAs: pool, ServerName: *name, NextProtos: protos, MinVersion: tls.VersionTLS13})
	if err != nil {
		check(false, "tls.Dial: %v", err)
		os.Exit(1)
	}
	st := conn.ConnectionState()
	check(st.Version == tls.VersionTLS13, "TLS 1.3 negotiated (%s)", tls.VersionName(st.Version))
	check(st.NegotiatedProtocol == *wantALPN, "ALPN %q (wanted %q)", st.NegotiatedProtocol, *wantALPN)
	check(*wantSuite == "" || tls.CipherSuiteName(st.CipherSuite) == *wantSuite, "cipher suite %s", tls.CipherSuiteName(st.CipherSuite))
	check(len(st.VerifiedChains) == 1 && len(st.PeerCertificates) >= 1, "the chain verified (%d certificate(s))", len(st.PeerCertificates))
	// a request by hand on this connection, then close_notify
	fmt.Fprintf(conn, "GET /size/10 HTTP/1.1\r\nHost: %s\r\n\r\n", *name)
	buf := make([]byte, 4096)
	got := 0
	for !bytes.HasSuffix(buf[:got], []byte("\r\n\r\nabcdefghij")) && got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			break
		}
	}
	check(bytes.HasSuffix(buf[:got], []byte("abcdefghij")), "a hand-written request is answered (%d bytes)", got)
	check(conn.Close() == nil, "close_notify is accepted")

	// the wrong name and an unknown root are refused by Go
	_, err = tls.Dial("tcp", *addr, &tls.Config{RootCAs: pool, ServerName: "wrong.example", MinVersion: tls.VersionTLS13})
	check(err != nil && strings.Contains(err.Error(), "certificate"), "a certificate for another name is refused (%v)", err)
	_, err = tls.Dial("tcp", *addr, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: *name, MinVersion: tls.VersionTLS13})
	check(err != nil && strings.Contains(err.Error(), "unknown authority"), "an unknown root is refused (%v)", err)

	// net/http: keep-alive, bodies of several sizes, POST, chunked, close
	connections := 0
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: *name, MinVersion: tls.VersionTLS13},
	}
	client := &http.Client{Transport: transport}
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if !i.Reused {
			connections++
		}
	}}
	url := func(path string) string { return "https://" + *addr + path }
	get := func(path string) ([]byte, *http.Response, error) {
		req, _ := http.NewRequest("GET", url(path), nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return body, resp, err
	}
	for _, s := range strings.Split(*sizes, ",") {
		n, _ := strconv.Atoi(s)
		body, resp, err := get("/size/" + s)
		check(err == nil && resp.StatusCode == 200 && bytes.Equal(body, pattern(n)), "GET /size/%d (%v)", n, err)
	}
	check(connections == 1, "all of those on one connection (%d)", connections)
	body, _, err := get("/chunked/5000")
	check(err == nil && bytes.Equal(body, pattern(5000)), "a chunked response (%v)", err)
	payload := pattern(300000)
	resp, err := client.Post(url("/echo"), "application/octet-stream", bytes.NewReader(payload))
	if err == nil {
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	check(err == nil && bytes.Equal(body, payload), "a 300000-byte POST is echoed (%v)", err)
	_, resp, err = get("/close")
	check(err == nil && resp.Close, "a response that closes the connection (%v)", err)
	_, _, err = get("/size/10")
	check(err == nil && connections == 2, "the next request opens a new connection (%d, %v)", connections, err)
	if failed {
		os.Exit(1)
	}
}
