// Prints tests/data/sumdb_vectors.txt: signed notes, tree heads and lookup records, each damaged in
// random ways, with the verdict of Go's golang.org/x/mod/sumdb packages (note.Open, tlog.ParseTree,
// tlog.ParseRecord). Run through tools/go_oracle.sh, see tools/gen_sumdb_vectors.sh.
//
// A base is written once (as hex) and every case says how it was damaged, as a list of edits:
//
//	x:OFFSET:HEXBYTE   xor the byte at OFFSET
//	d:OFFSET:LENGTH    delete LENGTH bytes at OFFSET
//	i:OFFSET:HEX       insert bytes before OFFSET
//	t:LENGTH           cut the data to LENGTH bytes
//
// where a case has `-` for no edits. Where this crate is meant to be stricter than Go (canonical
// Base64, tree sizes up to 2^62, plain decimal numbers) the verdict of a tree head or record is
// `bad-strict`: Go accepts it, this crate must refuse it. Notes whose signatures only Go's lenient
// Base64 decoder reads are left out, since the order of the errors matters there.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"oracle/note"
	"oracle/tlog"
)

var rng = rand.New(rand.NewSource(20261005))

type edit struct {
	kind string
	off  int
	arg  string // hex for insert, decimal for delete and xor
}

func (e edit) String() string { return fmt.Sprintf("%s:%d:%s", e.kind, e.off, e.arg) }

func apply(b []byte, edits []edit) []byte {
	b = append([]byte(nil), b...)
	for _, e := range edits {
		switch e.kind {
		case "x":
			v, _ := hex.DecodeString(e.arg)
			b[e.off] ^= v[0]
		case "d":
			n, _ := strconv.Atoi(e.arg)
			b = append(b[:e.off], b[e.off+n:]...)
		case "i":
			v, _ := hex.DecodeString(e.arg)
			b = append(b[:e.off], append(append([]byte(nil), v...), b[e.off:]...)...)
		case "t":
			b = b[:e.off]
		}
	}
	return b
}

var inserts = []string{
	"0a", "0a0a", "20", "e28094", "e2809420", "2b", "00", "1f", "7f", "ff", "0d", "3d", "41", "30", "2d", "c2a0",
	"e28083", "e38080", "c285", "e2808b", "e1a08e", "f09f9880", "eda080", "c0af", "09", "2e",
}

func randomEdits(n int, size int) []edit {
	var out []edit
	cur := size
	for len(out) < n {
		if cur <= 2 {
			break
		}
		switch rng.Intn(6) {
		case 0, 1:
			out = append(out, edit{"x", rng.Intn(cur), fmt.Sprintf("%02x", 1<<uint(rng.Intn(8)))})
		case 2:
			l := 1 + rng.Intn(3)
			off := rng.Intn(cur - l + 1)
			out = append(out, edit{"d", off, strconv.Itoa(l)})
			cur -= l
		case 3, 4:
			v := inserts[rng.Intn(len(inserts))]
			out = append(out, edit{"i", rng.Intn(cur + 1), v})
			cur += len(v) / 2
		case 5:
			if rng.Intn(4) == 0 {
				l := 1 + rng.Intn(cur-1)
				out = append(out, edit{"t", l, ""})
				cur = l
			}
		}
	}
	return out
}

func editsString(es []edit) string {
	if len(es) == 0 {
		return "-"
	}
	var parts []string
	for _, e := range es {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, ",")
}

// strictOK reports whether Go's decoder and a canonical one agree on s: Go ignores carriage returns
// and newlines and tolerates stray bits in the last character, which this crate refuses.
func strictOK(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err != nil || base64.StdEncoding.EncodeToString(b) == s
}

// noteHasNonCanonicalSignature: after the last blank line, a signature line whose Base64 Go decodes but not strictly.
func noteHasNonCanonicalSignature(msg []byte) bool {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return false
	}
	for _, line := range strings.Split(string(msg[i+2:]), "\n") {
		line = strings.TrimPrefix(line, "— ")
		if j := strings.Index(line, " "); j >= 0 {
			if !strictOK(line[j+1:]) {
				return true
			}
		}
	}
	return false
}

type fixtures struct {
	keys  map[string]note.Verifier
	texts map[string][]byte
	sigs  map[[2]string]string
}

func loadFixtures(repo string) *fixtures {
	f := &fixtures{keys: map[string]note.Verifier{}, texts: map[string][]byte{}, sigs: map[[2]string]string{}}
	file, err := os.Open(filepath.Join(repo, "tests/data/note_fixtures.txt"))
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		p := strings.SplitN(line, " ", 4)
		switch p[0] {
		case "key":
			v, err := note.NewVerifier(p[2])
			if err != nil {
				panic(err)
			}
			f.keys[p[1]] = v
		case "text":
			f.texts[p[1]], _ = hex.DecodeString(p[2])
		case "sig":
			f.sigs[[2]string{p[1], p[2]}] = p[3]
		}
	}
	return f
}

func (f *fixtures) note(text string, signers ...string) []byte {
	b := append([]byte(nil), f.texts[text]...)
	b = append(b, '\n')
	for _, s := range signers {
		b = append(b, f.sigs[[2]string{text, s}]...)
		b = append(b, '\n')
	}
	return b
}

func noteVerdict(msg []byte, known []note.Verifier) string {
	n, err := note.Open(msg, note.VerifierList(known...))
	if err != nil {
		switch e := err.(type) {
		case *note.UnverifiedNoteError:
			_ = e
			return "unverified"
		case *note.InvalidSignatureError:
			return "invalid"
		}
		if err.Error() == "malformed note" {
			return "malformed"
		}
		if strings.HasPrefix(err.Error(), "ambiguous key") {
			return "ambiguous"
		}
		return "other:" + err.Error()
	}
	var names []string
	for _, s := range n.Sigs {
		names = append(names, s.Name)
	}
	return fmt.Sprintf("ok:%s:%d", strings.Join(names, ","), len(n.UnverifiedSigs))
}

func main() {
	repo := os.Getenv("REPO")
	f := loadFixtures(repo)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	fmt.Fprintln(out, "# generated by tools/sumdb_vectors.go through tools/go_oracle.sh; verdicts are Go's (golang.org/x/mod sumdb/note, sumdb/tlog)")

	sumdbKey, err := note.NewVerifier("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8")
	if err != nil {
		panic(err)
	}
	latest, _ := os.ReadFile(filepath.Join(repo, "tests/data/sumdb/latest.txt"))
	lookup, _ := os.ReadFile(filepath.Join(repo, "tests/data/sumdb/lookup.txt"))
	lookupNote := lookup[bytes.Index(lookup, []byte("\n\n"))+2:]

	type base struct {
		id    string
		keys  string // labels, "sumdb" for the real key
		known []note.Verifier
		msg   []byte
	}
	var bases []base
	known := func(labels string) []note.Verifier {
		var ks []note.Verifier
		for _, l := range strings.Split(labels, ",") {
			if l == "sumdb" {
				ks = append(ks, sumdbKey)
			} else {
				ks = append(ks, f.keys[l])
			}
		}
		return ks
	}
	add := func(id, keys string, msg []byte) { bases = append(bases, base{id, keys, known(keys), msg}) }
	add("real1", "sumdb", latest)
	add("real2", "sumdb", lookupNote)
	add("fx1", "alpha", f.note("plain", "alpha"))
	add("fx2", "alpha,beta", f.note("tree", "alpha", "beta", "gamma"))
	add("fx3", "beta,gamma", f.note("unicode", "alpha", "beta"))
	add("fx4", "gamma", f.note("lines", "gamma", "gamma", "alpha"))
	add("fx5", "alpha,alpha", f.note("plain", "alpha"))

	for _, b := range bases {
		fmt.Fprintf(out, "base %s %s %s\n", b.id, b.keys, hex.EncodeToString(b.msg))
	}
	counts := map[string]int{}
	skipped := 0
	for _, b := range bases {
		// the undamaged note, and then damaged ones
		fmt.Fprintf(out, "note %s - %s\n", b.id, noteVerdict(b.msg, b.known))
		for n := 0; n < 110; n++ {
			es := randomEdits(1+rng.Intn(3), len(b.msg))
			msg := apply(b.msg, es)
			if noteHasNonCanonicalSignature(msg) {
				skipped++
				continue
			}
			v := noteVerdict(msg, b.known)
			counts[strings.SplitN(v, ":", 2)[0]]++
			fmt.Fprintf(out, "note %s %s %s\n", b.id, editsString(es), v)
		}
	}

	// tree heads
	trees := [][]byte{
		[]byte("go.sum database tree\n66746981\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n"),
		[]byte("go.sum database tree\n0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"),
		[]byte("go.sum database tree\n1234567\ndZ4n3o/nb32Y8rCuyUc1VeuATkhefsubWOYVhA9QIc8=\nextra line\nand another\n"),
	}
	for i, t := range trees {
		fmt.Fprintf(out, "treebase t%d %s\n", i, hex.EncodeToString(t))
	}
	treeVerdict := func(text []byte) (string, bool) {
		if !utf8.Valid(text) {
			return "", false
		}
		tr, err := tlog.ParseTree(text)
		if err != nil {
			return "bad", true
		}
		lines := strings.SplitN(string(text), "\n", 4)
		if tr.N > 1<<62 || !strictOK(lines[2]) {
			return "bad-strict", true
		}
		return fmt.Sprintf("ok:%d:%s", tr.N, hex.EncodeToString(tr.Hash[:])), true
	}
	for i, t := range trees {
		if v, ok := treeVerdict(t); ok {
			fmt.Fprintf(out, "tree t%d - %s\n", i, v)
		}
		for n := 0; n < 150; n++ {
			es := randomEdits(1+rng.Intn(2), len(t))
			text := apply(t, es)
			if v, ok := treeVerdict(text); ok {
				fmt.Fprintf(out, "tree t%d %s %s\n", i, editsString(es), v)
			}
		}
	}
	// a few sizes at the edges
	for _, size := range []string{"4611686018427387904", "4611686018427387905", "9223372036854775807", "9223372036854775808", "-0", "00", "0"} {
		text := []byte("go.sum database tree\n" + size + "\n3E4F4lzMBMmNFStdxyb64UKtphbJa3CNHeaauHIvkzQ=\n")
		v, _ := treeVerdict(text)
		fmt.Fprintf(out, "treetext %s %s\n", hex.EncodeToString(text), v)
	}

	// lookup responses (the record, a blank line and then whatever follows)
	recs := [][]byte{
		lookup,
		[]byte("7\nline one\nline two\n\ngo.sum database tree\n"),
		[]byte("0\nonly\n\n"),
	}
	for i, r := range recs {
		fmt.Fprintf(out, "recbase r%d %s\n", i, hex.EncodeToString(r))
	}
	recVerdict := func(msg []byte) string {
		id, text, rest, err := tlog.ParseRecord(msg)
		if err != nil {
			return "bad"
		}
		nl := bytes.IndexByte(msg, '\n')
		if line := string(msg[:nl]); line != strconv.FormatInt(id, 10) || id < 0 {
			return "bad-strict"
		}
		return fmt.Sprintf("ok:%d:%s:%s", id, hex.EncodeToString(text), hex.EncodeToString(rest))
	}
	for i, r := range recs {
		fmt.Fprintf(out, "rec r%d - %s\n", i, recVerdict(r))
		for n := 0; n < 150; n++ {
			es := randomEdits(1+rng.Intn(2), len(r))
			fmt.Fprintf(out, "rec r%d %s %s\n", i, editsString(es), recVerdict(apply(r, es)))
		}
	}
	for _, id := range []string{"0", "5", "05", "+5", "-5", "-0", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "5 ", " 5", "5x", ""} {
		msg := []byte(id + "\nline\n\nrest")
		fmt.Fprintf(out, "recraw %s %s\n", hex.EncodeToString(msg), recVerdict(msg))
	}
	fmt.Fprintf(os.Stderr, "notes: %v, skipped (non-canonical Base64): %d\n", counts, skipped)
}
