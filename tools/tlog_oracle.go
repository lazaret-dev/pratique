// Reads candidate proof cases from standard input (see tools/tlog_vectors.py), has Go's
// golang.org/x/mod/sumdb/tlog judge each one (CheckRecord for `incl`, CheckTree for `cons`), and
// prints the lines with Go's verdict in place of the candidate's. Exits with an error if Go and the
// candidate's own verdict differ anywhere: the Python reference and Go are two independent
// implementations of RFC 6962/9162. Run through tools/go_oracle.sh, see tools/gen_tlog_vectors.sh.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"oracle/tlog"
)

func hash(s string) tlog.Hash {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != tlog.HashSize {
		panic("bad hash " + s)
	}
	var h tlog.Hash
	copy(h[:], b)
	return h
}

func proof(s string) []tlog.Hash {
	if s == "-" {
		return nil
	}
	var p []tlog.Hash
	for _, h := range strings.Split(s, ",") {
		p = append(p, hash(h))
	}
	return p
}

func num(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return n
}

func verdict(err error) string {
	if err != nil {
		return "bad"
	}
	return "ok"
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	mismatches, counts := 0, map[string]int{}
	for in.Scan() {
		line := in.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			fmt.Fprintln(out, line)
			continue
		}
		f := strings.Split(line, " ")
		var v string
		switch f[0] {
		case "incl": // incl SIZE INDEX LEAF ROOT PROOF VERDICT
			v = verdict(tlog.CheckRecord(proof(f[5]), num(f[1]), hash(f[4]), num(f[2]), hash(f[3])))
		case "cons": // cons OLD OLDROOT NEW NEWROOT PROOF VERDICT
			v = verdict(tlog.CheckTree(proof(f[5]), num(f[3]), hash(f[4]), num(f[1]), hash(f[2])))
		default:
			panic(line)
		}
		if want := f[len(f)-1]; want != v {
			mismatches++
			fmt.Fprintf(os.Stderr, "Go says %s, the reference %s: %.100s\n", v, want, line)
		}
		counts[f[0]+" "+v]++
		f[len(f)-1] = v
		fmt.Fprintln(out, strings.Join(f, " "))
	}
	fmt.Fprintf(os.Stderr, "%v, %d disagreements\n", counts, mismatches)
	if mismatches > 0 {
		out.Flush()
		os.Exit(1)
	}
}
