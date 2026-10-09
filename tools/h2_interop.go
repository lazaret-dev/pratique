// A Go client for the interop check of pratique's HTTP/2 server (tools/h2_interop.sh): net/http's HTTP/2
// transport, which is not ours, makes requests against the `serve` example (started with alpn=h2,http/1.1) and
// reports what it saw. The things checked are the ones that have gone wrong in other servers: bodies that
// cross the frame and window sizes, many streams at once on one connection, header blocks that need
// CONTINUATION frames, trailers, interim responses, resets, GOAWAY, cancelled requests, PING.
//
//	go run tools/h2_interop.go -ca root.pem -addr 127.0.0.1:PORT [-name localhost]
//
// It prints one line per check, "ok ..." or "FAIL ...", and exits non-zero if any failed.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

type client struct {
	hc    *http.Client
	tr    *http.Transport
	dials atomic.Int32
	base  string
}

func newClient(pool *x509.CertPool, addr, name string, cfg *http.HTTP2Config) *client {
	c := &client{base: "https://" + name + addr[strings.LastIndex(addr, ":"):]}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	c.tr = &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: name},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c.dials.Add(1)
			return dialer.DialContext(ctx, network, addr)
		},
		HTTP2: cfg,
	}
	c.hc = &http.Client{Transport: c.tr, Timeout: 60 * time.Second}
	return c
}

func (c *client) get(path string) (*http.Response, []byte, error) {
	resp, err := c.hc.Get(c.base + path)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

func (c *client) post(path string, body []byte) (*http.Response, []byte, error) {
	resp, err := c.hc.Post(c.base+path, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	return resp, got, err
}

func main() {
	caFile := flag.String("ca", "root.pem", "root certificate (PEM)")
	addr := flag.String("addr", "127.0.0.1:0", "server address")
	name := flag.String("name", "localhost", "server name to ask for and verify")
	flag.Parse()

	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fmt.Println("FAIL", err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	check(pool.AppendCertsFromPEM(pem), "the root certificate loads")

	c := newClient(pool, *addr, *name, nil)

	// Bodies across the frame size (16384) and the initial window (65535).
	{
		all := true
		for _, n := range []int{0, 1, 100, 16383, 16384, 16385, 32768, 65535, 65536, 65537, 1000000, 5000000} {
			resp, body, err := c.get(fmt.Sprintf("/size/%d", n))
			good := err == nil && resp.ProtoMajor == 2 && resp.StatusCode == 200 && bytes.Equal(body, pattern(n)) && resp.ContentLength == int64(n)
			if !good {
				all = false
				check(false, "GET /size/%d: err=%v", n, err)
			}
		}
		if all {
			check(true, "GET /size/N for 12 sizes from 0 to 5000000, over HTTP/2, bodies and Content-Length right")
		}
	}

	// Uploads: the server's receive window must be opened as the body is consumed.
	{
		all := true
		for _, n := range []int{0, 1, 16384, 65535, 65536, 1 << 20, 5 << 20} {
			body := make([]byte, n)
			rand.Read(body)
			resp, got, err := c.post("/echo", body)
			if err != nil || resp.ProtoMajor != 2 || !bytes.Equal(got, body) {
				all = false
				check(false, "POST /echo %d bytes: err=%v", n, err)
			}
		}
		if all {
			check(true, "POST /echo of 7 sizes up to 5 MiB comes back unchanged")
		}
	}

	// A body of unknown length, in pieces with pauses: DATA frames as they are written, then END_STREAM.
	{
		pr, pw := io.Pipe()
		var want bytes.Buffer
		go func() {
			for i := 0; i < 20; i++ {
				piece := bytes.Repeat([]byte{byte('A' + i)}, 1000+i)
				want.Write(piece)
				pw.Write(piece)
				time.Sleep(5 * time.Millisecond)
			}
			pw.Close()
		}()
		resp, err := c.hc.Post(c.base+"/echo", "text/plain", pr)
		var got []byte
		if err == nil {
			got, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		check(err == nil && bytes.Equal(got, want.Bytes()) && len(got) > 20000, "a streamed POST body of unknown length (%d bytes) comes back: err=%v", len(got), err)
	}

	// Many streams at once on the one connection.
	{
		before := c.dials.Load()
		var wg sync.WaitGroup
		var bad atomic.Int32
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n := 1000 + i*7919
				if i%2 == 0 {
					_, body, err := c.get(fmt.Sprintf("/size/%d", n*5))
					if err != nil || !bytes.Equal(body, pattern(n*5)) {
						bad.Add(1)
					}
				} else {
					up := make([]byte, n*3)
					rand.Read(up)
					_, body, err := c.post("/echo", up)
					if err != nil || !bytes.Equal(body, up) {
						bad.Add(1)
					}
				}
			}(i)
		}
		wg.Wait()
		check(bad.Load() == 0, "32 concurrent requests (16 downloads, 16 echoes), %d wrong", bad.Load())
		check(c.dials.Load() == before, "... on the connection that was already open (%d new connections)", c.dials.Load()-before)
	}

	// The slow page: a body that arrives a byte at a time over a second.
	{
		start := time.Now()
		_, body, err := c.get("/slow/20")
		check(err == nil && bytes.Equal(body, pattern(20)) && time.Since(start) > 300*time.Millisecond, "GET /slow/20: 20 bytes, one DATA frame each (%v, err=%v)", time.Since(start).Round(10*time.Millisecond), err)
	}

	// HEAD: the length, no body, and the stream still ends.
	{
		resp, err := c.hc.Head(c.base + "/size/1000")
		ok := err == nil && resp.StatusCode == 200 && resp.ContentLength == 1000
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ok = ok && len(b) == 0
		}
		check(ok, "HEAD /size/1000: Content-Length 1000, empty body (err=%v)", err)
	}

	// Statuses without a body.
	for _, code := range []int{204, 304, 404, 500} {
		resp, body, err := c.get(fmt.Sprintf("/status/%d", code))
		check(err == nil && resp.StatusCode == code && len(body) == 0, "GET /status/%d (err=%v)", code, err)
	}

	// Response headers that need CONTINUATION frames.
	{
		resp, body, err := c.get("/headers/300")
		n := 0
		if err == nil {
			for k := range resp.Header {
				if strings.HasPrefix(k, "X-Header-") {
					n++
				}
			}
		}
		check(err == nil && n == 300 && string(body) == "many headers\n", "GET /headers/300: 300 header fields of 100 bytes in HEADERS+CONTINUATION (got %d, err=%v)", n, err)
	}

	// Request headers that need CONTINUATION frames: 40 fields of 1000 bytes.
	{
		req, _ := http.NewRequest("GET", c.base+"/size/10", nil)
		for i := 0; i < 40; i++ {
			req.Header.Set(fmt.Sprintf("X-Big-%d", i), strings.Repeat("v", 1000))
		}
		resp, err := c.hc.Do(req)
		ok := err == nil && resp.StatusCode == 200
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		check(ok, "a request with 40 header fields of 1000 bytes (HEADERS+CONTINUATION from Go) is answered (err=%v)", err)
	}

	// Trailers.
	{
		resp, body, err := c.get("/trailers")
		check(err == nil && string(body) == "a body with trailers\n" && resp.Trailer.Get("X-Sum") == "21", "trailers: body %q, X-Sum=%q (err=%v)", body, func() string {
			if resp != nil {
				return resp.Trailer.Get("X-Sum")
			}
			return ""
		}(), err)
	}

	// An interim response before the final one.
	{
		var interim atomic.Int32
		trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			if code == 103 && len(h["Link"]) == 1 {
				interim.Add(1)
			}
			return nil
		}}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", c.base+"/interim", nil)
		resp, err := c.hc.Do(req)
		var body []byte
		if err == nil {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		check(err == nil && resp.StatusCode == 200 && interim.Load() == 1 && string(body) == "after the interim response\n", "103 Early Hints seen once, then 200 and the body (err=%v)", err)
	}

	// A stream reset by the server in the middle of a body: an error for that request only.
	{
		before := c.dials.Load()
		resp, err := c.hc.Get(c.base + "/reset")
		var readErr error
		if err == nil {
			_, readErr = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		check(err == nil && readErr != nil && strings.Contains(readErr.Error(), "INTERNAL_ERROR"), "RST_STREAM INTERNAL_ERROR in the middle of a body reaches the body read: %v", readErr)
		resp2, body, err := c.get("/size/10")
		check(err == nil && resp2.StatusCode == 200 && len(body) == 10 && c.dials.Load() == before, "... and the connection goes on serving (new connections: %d)", c.dials.Load()-before)
	}

	// A request cancelled while the body is coming: RST_STREAM(CANCEL); the other streams are not hurt.
	{
		before := c.dials.Load()
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/size/60000000", nil)
		resp, err := c.hc.Do(req)
		got := 0
		if err == nil {
			buf := make([]byte, 32768)
			for got < 200000 {
				n, err := resp.Body.Read(buf)
				got += n
				if err != nil {
					break
				}
			}
			cancel()
			resp.Body.Close()
		} else {
			cancel()
		}
		time.Sleep(100 * time.Millisecond)
		resp2, body, err2 := c.get("/size/70000")
		check(err == nil && got >= 200000 && err2 == nil && resp2.StatusCode == 200 && bytes.Equal(body, pattern(70000)) && c.dials.Load() == before,
			"a 60 MB download cancelled after %d bytes; the next request on the same connection works (err=%v, %v)", got, err, err2)
	}

	// A PUSH_PROMISE to a client that switched push off is a connection error; Go must see an error, not hang.
	{
		c2 := newClient(pool, *addr, *name, nil)
		_, _, err := c2.get("/push")
		check(err != nil, "PUSH_PROMISE from the server fails the request (%v)", err)
		c2.tr.CloseIdleConnections()
	}

	// The server must answer PING: a client that pings after 200 ms of quiet and drops the connection if there is
	// no answer within a second.
	{
		c3 := newClient(pool, *addr, *name, &http.HTTP2Config{SendPingTimeout: 200 * time.Millisecond, PingTimeout: time.Second})
		_, _, err := c3.get("/size/10")
		time.Sleep(1500 * time.Millisecond)
		_, body, err2 := c3.get("/size/20")
		check(err == nil && err2 == nil && len(body) == 20 && c3.dials.Load() == 1, "after 1.5 s of quiet with 200 ms pings, the connection is still the same one (dials %d, %v, %v)", c3.dials.Load(), err, err2)
		c3.tr.CloseIdleConnections()
	}

	// Small flow-control windows on Go's side: the server has to stop at the window and go on with each update.
	{
		c4 := newClient(pool, *addr, *name, &http.HTTP2Config{MaxReceiveBufferPerStream: 1 << 10, MaxReceiveBufferPerConnection: 1 << 16, MaxReadFrameSize: 1 << 14})
		all := true
		for _, n := range []int{1, 1000, 1025, 100000, 1000000} {
			_, body, err := c4.get(fmt.Sprintf("/size/%d", n))
			if err != nil || !bytes.Equal(body, pattern(n)) {
				all = false
				check(false, "small windows: GET /size/%d: %v", n, err)
			}
		}
		if all {
			check(true, "downloads of 5 sizes with Go's stream window at 1 KiB")
		}
		c4.tr.CloseIdleConnections()
	}

	// Go's own idea of when to stop: GOAWAY with no error after an answer. The answer arrives, and the next
	// request goes to a new connection.
	{
		before := c.dials.Load()
		resp, body, err := c.get("/goaway")
		check(err == nil && resp.StatusCode == 200 && string(body) == "going away\n", "GET /goaway: the answer arrives (err=%v)", err)
		time.Sleep(100 * time.Millisecond)
		resp2, body2, err2 := c.get("/size/10")
		check(err2 == nil && resp2.StatusCode == 200 && len(body2) == 10 && c.dials.Load() == before+1, "... and the next request opens a new connection (new connections: %d, err=%v)", c.dials.Load()-before, err2)
	}

	if failed {
		fmt.Println("h2 go interop: FAIL")
		os.Exit(1)
	}
	fmt.Println("h2 go interop: PASS")
}
