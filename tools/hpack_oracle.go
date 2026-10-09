// Cross-checks pratique's HPACK (src/http/h2/hpack.rs) against Go's, the implementation inside net/http's
// HTTP/2 (golang.org/x/net/http2/hpack, vendored in the Go distribution). Run it with tools/hpack_oracle_go.sh,
// which puts a copy of that package beside this file:
//
//	sh tools/hpack_oracle_go.sh gen tests/data/hpack_go.txt     blocks made by Go's encoder, for the Rust test
//	sh tools/hpack_oracle_go.sh check corpus.txt                what Go's decoder makes of the Rust encoder's blocks
//
// The file format is the one of tools/hpack_oracle.py (see there).
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"hpackoracle/hpack"
)

type field struct{ name, value []byte }

type block struct {
	bytes  []byte
	fields []field
}

type seq struct {
	allowed int
	blocks  []block
}

var common = [][2]string{
	{":method", "GET"}, {":method", "POST"}, {":scheme", "https"}, {":path", "/"}, {":path", "/index.html"},
	{":authority", "www.example.com"}, {":status", "200"}, {":status", "404"}, {"accept-encoding", "gzip, deflate"},
	{"user-agent", "tiny_https/0.1"}, {"content-type", "application/json"}, {"content-length", "0"},
	{"cache-control", "no-cache"}, {"cache-control", "max-age=3600"}, {"etag", "\"abc123\""},
	{"x-request-id", "7f3a9c"}, {"set-cookie", "a=b; Path=/; HttpOnly"},
}

func randBytes(r *rand.Rand, lo, hi int, alphabet []byte) []byte {
	n := lo + r.Intn(hi-lo+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return b
}

func gen(path string) {
	r := rand.New(rand.NewSource(7541))
	lower := []byte("abcdefghijklmnopqrstuvwxyz-")
	var text, any []byte
	for i := 0x20; i < 0x7f; i++ {
		text = append(text, byte(i))
	}
	for i := 0; i < 256; i++ {
		any = append(any, byte(i))
	}
	var out strings.Builder
	var pool [][2][]byte
	for s := 0; s < 40; s++ {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		sizes := []uint32{4096, 4096, 256, 64, 0, 100}
		enc.SetMaxDynamicTableSize(sizes[r.Intn(len(sizes))])
		pool = pool[:0]
		out.WriteString("seq 4096\n")
		nblocks := 2 + r.Intn(5)
		for b := 0; b < nblocks; b++ {
			if b > 0 && r.Intn(5) == 0 {
				c := []uint32{0, 32, 64, 256, 1000, 4096}
				enc.SetMaxDynamicTableSize(c[r.Intn(len(c))])
			}
			buf.Reset()
			var fields []field
			for i, n := 0, r.Intn(13); i < n; i++ {
				var name, value []byte
				switch p := r.Intn(100); {
				case p < 40:
					c := common[r.Intn(len(common))]
					name, value = []byte(c[0]), []byte(c[1])
				case p < 60 && len(pool) > 0:
					e := pool[r.Intn(len(pool))]
					name, value = e[0], e[1]
				case p < 85:
					name, value = randBytes(r, 1, 14, lower), randBytes(r, 0, 40, text)
				case p < 95:
					name, value = []byte(common[r.Intn(len(common))][0]), randBytes(r, 0, 30, text)
				default:
					name, value = randBytes(r, 1, 6, lower), randBytes(r, 0, 20, any)
				}
				if len(pool) < 40 {
					pool = append(pool, [2][]byte{name, value})
				} else {
					pool[r.Intn(40)] = [2][]byte{name, value}
				}
				sensitive := r.Intn(10) == 0
				if err := enc.WriteField(hpack.HeaderField{Name: string(name), Value: string(value), Sensitive: sensitive}); err != nil {
					panic(err)
				}
				fields = append(fields, field{name, value})
			}
			fmt.Fprintf(&out, "block %s\n", hex.EncodeToString(buf.Bytes()))
			for _, f := range fields {
				fmt.Fprintf(&out, "field %s %s\n", hex.EncodeToString(f.name), hex.EncodeToString(f.value))
			}
		}
		out.WriteString("end\n")
	}
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", path)
}

func parse(path string) []seq {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var seqs []seq
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Fields(line)
		if len(p) == 0 {
			continue
		}
		dec := func(i int) []byte {
			if i >= len(p) {
				return nil
			}
			b, err := hex.DecodeString(p[i])
			if err != nil {
				panic(err)
			}
			return b
		}
		switch p[0] {
		case "seq":
			n, _ := strconv.Atoi(p[1])
			seqs = append(seqs, seq{allowed: n})
		case "block":
			s := &seqs[len(seqs)-1]
			s.blocks = append(s.blocks, block{bytes: dec(1)})
		case "field":
			s := &seqs[len(seqs)-1]
			b := &s.blocks[len(s.blocks)-1]
			b.fields = append(b.fields, field{dec(1), dec(2)})
		}
	}
	return seqs
}

func check(path string) {
	bad, total := 0, 0
	for i, s := range parse(path) {
		dec := hpack.NewDecoder(uint32(s.allowed), nil)
		for j, b := range s.blocks {
			total++
			got, err := dec.DecodeFull(b.bytes)
			if err != nil {
				fmt.Printf("FAIL seq %d block %d: %v\n", i, j, err)
				bad++
				continue
			}
			ok := len(got) == len(b.fields)
			for k := 0; ok && k < len(got); k++ {
				ok = got[k].Name == string(b.fields[k].name) && got[k].Value == string(b.fields[k].value)
			}
			if !ok {
				fmt.Printf("FAIL seq %d block %d: fields differ\n  want %q\n  got  %q\n", i, j, b.fields, got)
				bad++
			}
		}
	}
	fmt.Printf("%d blocks checked by Go hpack, %d failed\n", total, bad)
	if bad > 0 {
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: hpack_oracle gen FILE | check FILE")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		gen(os.Args[2])
	case "check":
		check(os.Args[2])
	default:
		fmt.Println("usage: hpack_oracle gen FILE | check FILE")
		os.Exit(2)
	}
}
