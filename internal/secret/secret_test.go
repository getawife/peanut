package secret

import (
	"encoding/hex"
	"testing"
)

func TestPBKDF2KnownVector(t *testing.T) {
	got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), 4096, 32))
	want := "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func TestVerify(t *testing.T) {
	salt := NewSalt()
	h := Hash("hunter22", salt, 1000)
	if !Verify("hunter22", salt, h, 1000) || Verify("hunter23", salt, h, 1000) {
		t.Fatal("verify mismatch")
	}
}
