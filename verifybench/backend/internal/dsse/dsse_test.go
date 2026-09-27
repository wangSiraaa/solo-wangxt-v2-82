package dsse_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/example/verifybench/internal/dsse"
)

func TestPAESpecExample(t *testing.T) {
	// The canonical PAE sanity shape: DSSEv1 SP len SP type SP len SP body.
	got := string(dsse.PAE("application/vnd.in-toto+json", []byte("{}")))
	if !strings.HasPrefix(got, "DSSEv1 ") {
		t.Fatalf("PAE must start with DSSEv1, got %q", got)
	}
	if !strings.Contains(got, "application/vnd.in-toto+json") {
		t.Fatalf("PAE must embed payload type, got %q", got)
	}
	if !strings.HasSuffix(got, " {}") {
		t.Fatalf("PAE must end with body length and body, got %q", got)
	}
}

func TestVerifyRoundTripAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := dsse.KeyIDFromPublic(pub)
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	sig := ed25519.Sign(priv, dsse.PAE(dsse.MediaType, payload))

	ring := map[string]dsse.PublicKey{
		keyID: {KeyID: keyID, BuilderID: "b/1", Raw: pub},
	}

	env := dsse.Envelope{
		PayloadType: dsse.MediaType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsse.Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	raw, _ := json.Marshal(env)

	decoded, decodedPayload, err := dsse.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	res, err := dsse.Verify(decoded, decodedPayload, ring)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 1 || !res[0].Valid || !res[0].Trusted {
		t.Fatalf("expected one valid trusted signature, got %+v", res)
	}

	// Tamper with the payload: signature must fail even though the key is trusted.
	env.Payload = base64.StdEncoding.EncodeToString(append(payload, 'x'))
	rawTampered, _ := json.Marshal(env)
	dec2, pay2, _ := dsse.Decode(rawTampered)
	res2, _ := dsse.Verify(dec2, pay2, ring)
	if res2[0].Valid || !res2[0].Trusted {
		t.Fatalf("expected invalid-but-trusted-key result after payload tamper, got %+v", res2)
	}

	// Unknown key id: not trusted.
	env2 := dsse.Envelope{
		PayloadType: dsse.MediaType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsse.Signature{{KeyID: "sha256:deadbeef", Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	raw2, _ := json.Marshal(env2)
	dec3, pay3, _ := dsse.Decode(raw2)
	res3, _ := dsse.Verify(dec3, pay3, ring)
	if res3[0].Valid || res3[0].Trusted {
		t.Fatalf("unknown key must be invalid+untrusted, got %+v", res3)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"not json":        []byte("garbage"),
		"no payloadType":  []byte(`{"payload":"e30=","signatures":[{"keyid":"k","sig":""}]}`),
		"no signatures":   []byte(`{"payloadType":"t","payload":"e30=","signatures":[]}`),
		"bad payload b64": []byte(`{"payloadType":"t","payload":"!!!","signatures":[{"keyid":"k","sig":""}]}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := dsse.Decode(data); err == nil {
				t.Fatal("expected decode error")
			}
		})
	}
}
