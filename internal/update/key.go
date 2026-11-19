package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

var PublicKeyBase64 = "Go6PSs/HeDE5OC76nhl5oTQBsd+Wp6Kcnw3VlTR+pHE="

func PublicKey() ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(PublicKeyBase64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}