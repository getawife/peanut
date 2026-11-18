package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

const (
	DefaultIterations = 600_000
	keyLen            = 32
	saltLen           = 16
)

func NewSalt() []byte {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

func Hash(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, keyLen)
}

func Verify(password string, salt, want []byte, iterations int) bool {
	return subtle.ConstantTimeCompare(Hash(password, salt, iterations), want) == 1
}

func pbkdf2(password, salt []byte, iterations, length int) []byte {
	prf := hmac.New(sha256.New, password)
	blocks := (length + prf.Size() - 1) / prf.Size()
	out := make([]byte, 0, blocks*prf.Size())
	index := make([]byte, 4)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(index, uint32(b))
		prf.Write(index)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:length]
}
