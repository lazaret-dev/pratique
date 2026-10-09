// Go's compress/flate, compress/zlib and compress/gzip as an independent compressor and decompressor for
// tools/gen_inflate_vectors.py. Nothing from Go is copied into the repository, only what it says.
//
//	go run tools/inflate_oracle.go gen DIR     for each file in DIR, streams made by Go's writers, as lines
//	                                           "NAME FORMAT HEX" (NAME is "go.VARIANT.FILE")
//	go run tools/inflate_oracle.go judge       reads lines "NAME FORMAT HEX" on stdin (HEX is - for no data) and prints, for each,
//	                                           "NAME ok LENGTH SHA256" or "NAME err WHY": whether Go's reader takes
//	                                           the whole of the data as one stream of the format (any number of
//	                                           members for gzip, as gzip.Reader does) and, if so, what it gives
//
// FORMAT is deflate, zlib or gzip.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "inflate_oracle:", err)
		os.Exit(1)
	}
}

// judge decodes data as a whole stream of the format.
func judge(format string, data []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	rd := bytes.NewReader(data)
	switch format {
	case "deflate":
		r := flate.NewReader(rd)
		out, err = io.ReadAll(r)
	case "zlib":
		r, e := zlib.NewReader(rd)
		if e != nil {
			return nil, e
		}
		out, err = io.ReadAll(r)
	case "gzip":
		r, e := gzip.NewReader(rd)
		if e != nil {
			return nil, e
		}
		out, err = io.ReadAll(r)
	default:
		return nil, fmt.Errorf("format %q", format)
	}
	if err == nil && rd.Len() != 0 {
		err = fmt.Errorf("%d bytes follow the stream", rd.Len())
	}
	return out, err
}

func emit(name, format string, data []byte, corpus []byte) {
	// what Go made must be what Go reads back
	out, err := judge(format, data)
	must(err)
	if !bytes.Equal(out, corpus) {
		must(fmt.Errorf("%s does not read back", name))
	}
	fmt.Printf("%s %s %s\n", name, format, hex.EncodeToString(data))
}

func gen(dir string) {
	names, err := filepath.Glob(filepath.Join(dir, "*"))
	must(err)
	sort.Strings(names)
	for _, path := range names {
		corpus, err := os.ReadFile(path)
		must(err)
		base := filepath.Base(path)
		// DEFLATE at every level Go has, and its Huffman-only mode
		// (not the two levels that do not shrink what is long, in a file that keeps the streams)
		for _, level := range []int{flate.HuffmanOnly, flate.NoCompression, flate.BestSpeed, 4, flate.DefaultCompression, flate.BestCompression} {
			if len(corpus) > 3000 && (level == flate.HuffmanOnly || level == flate.NoCompression) {
				continue
			}
			var b bytes.Buffer
			w, err := flate.NewWriter(&b, level)
			must(err)
			_, err = w.Write(corpus)
			must(err)
			must(w.Close())
			emit(fmt.Sprintf("go.flate%d.%s", level, base), "deflate", b.Bytes(), corpus)
		}
		// zlib and gzip with a few levels
		for _, level := range []int{zlib.BestSpeed, zlib.DefaultCompression, zlib.BestCompression} {
			var b bytes.Buffer
			w, err := zlib.NewWriterLevel(&b, level)
			must(err)
			_, err = w.Write(corpus)
			must(err)
			must(w.Close())
			emit(fmt.Sprintf("go.zlib%d.%s", level, base), "zlib", b.Bytes(), corpus)
			b.Reset()
			g, err := gzip.NewWriterLevel(&b, level)
			must(err)
			g.Name = "oracle-" + base
			g.Comment = "made by Go"
			_, err = g.Write(corpus)
			must(err)
			must(g.Close())
			emit(fmt.Sprintf("go.gzip%d.%s", level, base), "gzip", b.Bytes(), corpus)
		}
		// flushes every 700 bytes (empty stored blocks between the pieces) and a stream cut into members
		if len(corpus) <= 3000 {
			var b bytes.Buffer
			w, err := flate.NewWriter(&b, 6)
			must(err)
			for off := 0; off < len(corpus); off += 700 {
				end := off + 700
				if end > len(corpus) {
					end = len(corpus)
				}
				_, err = w.Write(corpus[off:end])
				must(err)
				must(w.Flush())
			}
			must(w.Close())
			emit("go.flush700."+base, "deflate", b.Bytes(), corpus)
		}
		if len(corpus) <= 3000 {
			var b bytes.Buffer
			for off := 0; off < len(corpus) || off == 0; off += 1000 {
				end := off + 1000
				if end > len(corpus) {
					end = len(corpus)
				}
				g := gzip.NewWriter(&b)
				_, err = g.Write(corpus[off:end])
				must(err)
				must(g.Close())
			}
			emit("go.members1000."+base, "gzip", b.Bytes(), corpus)
		}
	}
}

func judgeLines() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			must(fmt.Errorf("line %q", sc.Text()))
		}
		data, err := hex.DecodeString(strings.TrimPrefix(f[2], "-"))
		must(err)
		out, err := judge(f[1], data)
		if err != nil {
			fmt.Printf("%s err %s\n", f[0], strings.ReplaceAll(err.Error(), " ", "_"))
			continue
		}
		sum := sha256.Sum256(out)
		fmt.Printf("%s ok %d %s\n", f[0], len(out), hex.EncodeToString(sum[:]))
	}
	must(sc.Err())
}

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "gen" {
		gen(os.Args[2])
	} else if len(os.Args) == 2 && os.Args[1] == "judge" {
		judgeLines()
	} else {
		fmt.Fprintln(os.Stderr, "usage: inflate_oracle.go gen DIR | judge")
		os.Exit(2)
	}
}
