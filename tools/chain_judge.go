// Go's crypto/x509 as one of the judges of tools/chain_judges.sh (BACKLOG B-92, part 3): for each chain in a directory laid
// out as tests/data/real_chains and tests/data/chain_cases are (fixtures.tsv, chains/NAME.pem, the anchors' files), whether
// Go accepts it as a TLS server's chain for the case's host at the case's time, against a pool of that case's anchors alone
// (and the rest of the chain as intermediates).
//
//	go run tools/chain_judge.go DIR
//
// One line for each case: NAME<TAB>ok, or NAME<TAB>no<TAB>why.
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func certsIn(path string) ([]*x509.Certificate, []error, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var out []*x509.Certificate
	var bad []error
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			bad = append(bad, err)
			out = append(out, nil)
			continue
		}
		out = append(out, c)
	}
	return out, bad, nil
}

func judge(dir, name, host string, when int64, anchor string) error {
	chain, _, err := certsIn(filepath.Join(dir, "chains", name+".pem"))
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("the chain file holds no certificate")
	}
	if chain[0] == nil {
		_, bad, _ := certsIn(filepath.Join(dir, "chains", name+".pem"))
		return fmt.Errorf("the leaf does not parse: %v", bad[0])
	}
	roots := x509.NewCertPool()
	if anchor != "-" {
		anchors, bad, err := certsIn(filepath.Join(dir, anchor))
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return fmt.Errorf("an anchor does not parse: %v", bad[0])
		}
		for _, a := range anchors {
			roots.AddCert(a)
		}
	}
	inter := x509.NewCertPool()
	// (an intermediate that does not parse is left out, as a server's junk would be)
	for _, c := range chain[1:] {
		if c != nil {
			inter.AddCert(c)
		}
	}
	_, err = chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   time.Unix(when, 0),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run tools/chain_judge.go DIR")
		os.Exit(2)
	}
	dir := os.Args[1]
	f, err := os.Open(filepath.Join(dir, "fixtures.tsv"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		line := lines.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) < 5 {
			fmt.Fprintln(os.Stderr, "fixtures.tsv: a line with fewer than 5 columns:", line)
			os.Exit(2)
		}
		var verdict error
		when, err := strconv.ParseInt(c[2], 10, 64)
		if err != nil {
			verdict = fmt.Errorf("bad time %s", c[2])
		} else {
			verdict = judge(dir, c[0], c[1], when, c[4])
		}
		if verdict == nil {
			fmt.Printf("%s\tok\n", c[0])
		} else {
			why := strings.NewReplacer("\t", " ", "\n", " ").Replace(verdict.Error())
			fmt.Printf("%s\tno\t%s\n", c[0], why)
		}
	}
}
