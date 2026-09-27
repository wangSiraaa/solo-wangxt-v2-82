// Package dsse implements parsing and cryptographic verification of
// DSSE (Dead Simple Signing Envelope) v1.0 envelopes.
//
// The signing payload is constructed strictly per the DSSE specification
// ("PAE", pre-authentication encoding), so the signature can never be
// confused with a signature over the statement JSON alone.
package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// MediaType is the standard payload type for in-toto statements in DSSE.
const MediaType = "application/vnd.in-toto+json"

// Envelope is the JSON representation of a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is a single signature on the envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Decode parses a raw DSSE envelope JSON and base64-decodes the payload,
// returning the decoded payload bytes for further in-toto parsing.
func Decode(raw []byte) (*Envelope, []byte, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("envelope is not valid JSON: %w", err)
	}
	if env.PayloadType == "" {
		return nil, nil, fmt.Errorf("envelope missing payloadType")
	}
	if env.Payload == "" {
		return nil, nil, fmt.Errorf("envelope missing payload")
	}
	if len(env.Signatures) == 0 {
		return nil, nil, fmt.Errorf("envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("payload is not valid base64: %w", err)
	}
	return &env, payload, nil
}

// PAE returns the DSSE Pre-Authentication Encoding:
//
//	"DSSEv1" + SP + len(type) + SP + type + SP + len(body) + SP + body
//
// where SP is a space and lengths are byte counts.
func PAE(payloadType string, body []byte) []byte {
	const dsseVersion = "DSSEv1"
	out := []byte(dsseVersion + " ")
	out = append(out, []byte(fmt.Sprintf("%d", len(payloadType)))...)
	out = append(out, ' ')
	out = append(out, []byte(payloadType)...)
	out = append(out, ' ')
	out = append(out, []byte(fmt.Sprintf("%d", len(body)))...)
	out = append(out, ' ')
	out = append(out, body...)
	return out
}

// SigResult is the verification outcome for one signature.
type SigResult struct {
	KeyID        string `json:"keyId"`
	Valid        bool   `json:"valid"`
	Trusted      bool   `json:"trusted"`
	Detail       string `json:"detail"`
	SignerSHA256 string `json:"signerSha256,omitempty"`
}

// PublicKey is a trusted verification key (Ed25519 only in this workbench).
type PublicKey struct {
	KeyID     string
	BuilderID string
	Raw       ed25519.PublicKey
}

// ParseEd25519PublicKey accepts a PEM-encoded PKIX public key, raw DER, or a
// base64 string of either, and returns the ed25519 public key.
func ParseEd25519PublicKey(data string) (ed25519.PublicKey, error) {
	rest := []byte(data)
	if block, _ := pem.Decode(rest); block != nil {
		rest = block.Bytes
	} else {
		// Try raw base64 DER.
		if der, err := base64.StdEncoding.DecodeString(data); err == nil {
			rest = der
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(rest)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519")
	}
	return pub, nil
}

// KeyIDFromPublic returns the canonical key id used by this workbench:
// hex(sha256 of the raw 32-byte ed25519 public key), prefixed for clarity.
func KeyIDFromPublic(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verify checks every signature against the PAE bytes using the supplied
// trusted key ring. A signature whose key is not in the ring is reported with
// Valid=true (cryptographically intact) but Trusted=false, which lets the UI
// distinguish "bad signature" from "unknown/untrusted signer".
func Verify(env *Envelope, payload []byte, ring map[string]PublicKey) ([]SigResult, error) {
	signingBytes := PAE(env.PayloadType, payload)
	results := make([]SigResult, 0, len(env.Signatures))
	for i, sig := range env.Signatures {
		r := SigResult{KeyID: sig.KeyID}
		if sig.Sig == "" {
			r.Detail = fmt.Sprintf("signatures[%d].sig is empty", i)
			results = append(results, r)
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			r.Detail = fmt.Sprintf("signatures[%d].sig is not valid base64: %s", i, err.Error())
			results = append(results, r)
			continue
		}
		key, known := ring[sig.KeyID]
		// We always verify with the key named by keyid when trusted; if the
		// key is unknown we cannot verify cryptographically against the ring.
		if !known {
			r.Valid = false
			r.Trusted = false
			r.Detail = fmt.Sprintf("signatures[%d].keyid %q is not present in the trust root", i, sig.KeyID)
			results = append(results, r)
			continue
		}
		if !ed25519.Verify(key.Raw, signingBytes, sigBytes) {
			r.Valid = false
			r.Trusted = true
			r.Detail = fmt.Sprintf("signatures[%d]: ed25519 verification failed against trusted key %s (payload or signature was modified)", i, sig.KeyID)
			results = append(results, r)
			continue
		}
		sum := sha256.Sum256(key.Raw)
		r.Valid = true
		r.Trusted = true
		r.SignerSHA256 = hex.EncodeToString(sum[:])
		r.Detail = fmt.Sprintf("signatures[%d]: valid ed25519 signature over PAE, key %s, builder %s", i, sig.KeyID, key.BuilderID)
		results = append(results, r)
	}
	return results, nil
}
