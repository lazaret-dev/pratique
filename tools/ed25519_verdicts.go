// Reads lines "family:A:sig:message" (hex) on stdin and prints, one per line, 1 if Go's crypto/ed25519
// accepts the signature and 0 if it does not. Used by tools/ed25519_vectors.py; not part of the library.
//
//	go run tools/ed25519_verdicts.go < inputs
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 4 {
			fmt.Fprintln(os.Stderr, "bad line:", sc.Text())
			os.Exit(1)
		}
		a, err1 := hex.DecodeString(parts[1])
		sig, err2 := hex.DecodeString(parts[2])
		msg, err3 := hex.DecodeString(parts[3])
		if err1 != nil || err2 != nil || err3 != nil {
			fmt.Fprintln(os.Stderr, "bad hex:", sc.Text())
			os.Exit(1)
		}
		if len(a) == ed25519.PublicKeySize && ed25519.Verify(a, msg, sig) {
			fmt.Println(1)
		} else {
			fmt.Println(0)
		}
	}
}
