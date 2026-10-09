// bench_client is the yardstick for the benchmark in tools/bench_h2.sh: Go's own net/http client doing what
// examples/fetch.rs does (the whole body read into memory), so that pratique can be compared with it, HTTP/1.1 against
// HTTP/1.1 and HTTP/2 against HTTP/2, on the same server and the same cores.
//
//	go run tools/bench_client.go -ca root.pem [-h1] [-stream] [-parallel N] [-repeat N] URL
//
// With -stream the body is read in pieces of 64 KiB and thrown away instead (the way a download to a file reads it). With neither -parallel nor -repeat: one request. -parallel N: N requests at once. -repeat N: N requests in a row
// (split over -parallel goroutines if that is given too). It prints the wall time and the CPU time of the process.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"
)

func cpu() float64 {
	var r syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6 + float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
}

func main() {
	ca := flag.String("ca", "root.pem", "the root certificate to trust")
	h1 := flag.Bool("h1", false, "HTTP/1.1 only")
	parallel := flag.Int("parallel", 0, "requests at once")
	repeat := flag.Int("repeat", 0, "requests in a row")
	stream := flag.Bool("stream", false, "read the body in pieces of 64 KiB and throw it away")
	flag.Parse()
	url := flag.Arg(0)
	pem, err := os.ReadFile(*ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2:   !*h1,
		MaxIdleConnsPerHost: 64,
	}
	if *h1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: tr}
	get := func() (int, string) {
		resp, err := client.Get(url)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		if *stream {
			n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{resp.Body}, make([]byte, 64*1024))
			if err != nil {
				return 0, err.Error()
			}
			return int(n), resp.Proto
		}
		// the way a Go program reads a whole body quickest when the server says how long it is: into a buffer of that size
		// (io.ReadAll, which grows its buffer as it goes, takes several times as long for a body of 100 MB)
		var body []byte
		if resp.ContentLength >= 0 {
			body = make([]byte, resp.ContentLength)
			_, err = io.ReadFull(resp.Body, body)
		} else {
			body, err = io.ReadAll(resp.Body)
		}
		if err != nil {
			return 0, err.Error()
		}
		return len(body), resp.Proto
	}
	threads, per := 1, 1
	switch {
	case *repeat > 0:
		threads = max(*parallel, 1)
		per = (*repeat + threads - 1) / threads
	case *parallel > 0:
		threads = *parallel
	}
	started, c0 := time.Now(), cpu()
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed, proto, size := "", "", 0
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				n, p := get()
				mu.Lock()
				if n == 0 && failed == "" {
					failed = p
				}
				proto, size = p, n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	wall := time.Since(started)
	if failed != "" {
		fmt.Fprintln(os.Stderr, "error:", failed)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "go %s: %d requests (%d at once): wall %.3f s, cpu %.3f s, %.0f us per request; last answer %d bytes\n",
		proto, per*threads, threads, wall.Seconds(), cpu()-c0, wall.Seconds()*1e6/float64(per*threads), size)
}
