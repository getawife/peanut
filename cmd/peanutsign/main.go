package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: peanutsign keygen | peanutsign sign <file>")
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail(err.Error())
		}
		fmt.Println("private key:")
		fmt.Println(base64.StdEncoding.EncodeToString(priv))
		fmt.Println()
		fmt.Println("public key:")
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
	case "sign":
		if len(os.Args) != 3 {
			fail("usage: peanutsign sign <file>")
		}
		sign(os.Args[2])
	default:
		fail("unknown command " + os.Args[1])
	}
}

func sign(path string) {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("PEANUT_SIGNING_KEY"))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		fail("PEANUT_SIGNING_KEY is missing or invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), data))
	if err := os.WriteFile(path+".sig", []byte(sig+"\n"), 0o644); err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}