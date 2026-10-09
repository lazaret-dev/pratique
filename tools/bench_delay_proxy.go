// bench_delay_proxy is a TCP forwarder that delays every chunk by -delay in each direction (a path with a round trip of
// twice that), with room in flight for whatever the delay and the rate need. tools/bench_h2.sh puts it between the
// client and the oracle server to measure over a path with a round trip, where HTTP/2's one connection and its windows
// matter.
//
//	go run tools/bench_delay_proxy.go -listen 127.0.0.1:0 -target 127.0.0.1:PORT -delay 10ms
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type chunk struct {
	data []byte
	at   time.Time
}

func pipe(dst, src net.Conn, d time.Duration) {
	ch := make(chan chunk, 8192)
	go func() {
		for c := range ch {
			time.Sleep(time.Until(c.at))
			if _, err := dst.Write(c.data); err != nil {
				break
			}
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		io.Copy(io.Discard, ch2reader(ch))
	}()
	for {
		b := make([]byte, 64*1024)
		n, err := src.Read(b)
		if n > 0 {
			ch <- chunk{b[:n], time.Now().Add(d)}
		}
		if err != nil {
			close(ch)
			return
		}
	}
}

type chreader struct{ ch chan chunk }

func ch2reader(ch chan chunk) io.Reader { return &chreader{ch} }
func (r *chreader) Read(p []byte) (int, error) {
	for range r.ch {
	}
	return 0, io.EOF
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19000", "")
	target := flag.String("target", "127.0.0.1:18443", "")
	delay := flag.Duration("delay", 10*time.Millisecond, "one way")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("listening", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			s, err := net.Dial("tcp", *target)
			if err != nil {
				c.Close()
				return
			}
			go pipe(s, c, *delay)
			pipe(c, s, *delay)
			c.Close()
			s.Close()
		}()
	}
}
