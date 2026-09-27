package verify

import (
	"encoding/base64"
	"strings"
)

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func short(hexDigest string) string {
	if len(hexDigest) <= 16 {
		return hexDigest
	}
	var b strings.Builder
	b.WriteString(hexDigest[:8])
	b.WriteString("…")
	b.WriteString(hexDigest[len(hexDigest)-8:])
	return b.String()
}
