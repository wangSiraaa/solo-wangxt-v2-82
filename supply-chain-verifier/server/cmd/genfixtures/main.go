// genfixtures 生成三组固定演示数据:
//
//	fixtures/valid/             正常文件:受信构建者签名,摘要一致 -> 预期 allow
//	fixtures/tampered/          被改过的文件:信封合法但产物被篡改 -> 摘要不一致,预期 deny
//	fixtures/untrusted-builder/ 不受信任构建者:签名有效但 keyid 不受信 -> 预期 deny
//
// 同时生成 fixtures/keys/keyring.json(已知公钥,含可信与不可信)供服务端验签。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/example/supply-chain-verifier/internal/dsse"
)

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const (
	trustedKeyID  = "trusted-builder-01"
	untrustedKeyID = "intern-builder-07"
	builderID     = "https://builders.example.com/github-actions-release"
	payloadType   = "application/vnd.in-toto+json"
)

type keyEntry struct {
	KeyID string `json:"keyid"`
	Owner string `json:"owner"`
	Algo  string `json:"algo"`
	Pub   string `json:"pub"`
	priv  ed25519.PrivateKey
}

func main() {
	out := "fixtures"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	trusted := genKey(trustedKeyID, "release-team")
	untrusted := genKey(untrustedKeyID, "intern (未授权)")

	// 密钥环:服务端已知的全部公钥(可信与否由 OPA 数据决定)
	writeJSON(filepath.Join(out, "keys", "keyring.json"), []keyEntry{trusted.public(), untrusted.public()})

	// --- 用例 1:正常文件 ---
	goodArtifact := []byte("demo-artifact: release build output v1.2.3\n")
	validEnv := sign(trusted, statement("app.tar.gz", sha256hex(goodArtifact), builderID))
	writeCase(out, "valid", goodArtifact, validEnv,
		"正常文件:受信构建者签名,产物摘要与声明一致", "allow")

	// --- 用例 2:被改过的文件 ---
	// 信封与用例 1 完全相同(签名有效),但本地产物内容被篡改
	tampered := []byte("demo-artifact: release build output v1.2.3 [INJECTED PAYLOAD]\n")
	writeCase(out, "tampered", tampered, validEnv,
		"被改过的文件:证据合法但本地产物摘要与声明不符", "deny")

	// --- 用例 3:不受信任构建者 ---
	// 产物与摘要一致,但签名密钥不在受信列表
	untrustedArtifact := []byte("demo-artifact: built on intern laptop\n")
	untrustedEnv := sign(untrusted, statement("app.tar.gz", sha256hex(untrustedArtifact), "https://builders.example.com/intern-laptop"))
	writeCase(out, "untrusted-builder", untrustedArtifact, untrustedEnv,
		"不受信任构建者:签名有效但签发者与构建流程均不受信", "deny")

	fmt.Println("fixtures written to", out)
}

func genKey(keyid, owner string) keyEntry {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return keyEntry{KeyID: keyid, Owner: owner, Algo: "ed25519",
		Pub: base64.StdEncoding.EncodeToString(pub), priv: priv}
}

func (k keyEntry) public() keyEntry { k.priv = nil; return k }

func statement(name, sha256, builder string) []byte {
	st := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   name,
			"digest": map[string]string{"sha256": sha256},
		}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": "https://example.com/buildtypes/release/v1",
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builder},
			},
		},
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func sign(k keyEntry, payload []byte) []byte {
	sig := ed25519.Sign(k.priv, dsse.PAE(payloadType, payload))
	env := map[string]any{
		"payloadType": payloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]string{
			"keyid": k.KeyID,
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func writeCase(base, name string, artifact, envelope []byte, desc, expect string) {
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	must(os.WriteFile(filepath.Join(dir, "artifact.bin"), artifact, 0o644))
	must(os.WriteFile(filepath.Join(dir, "envelope.json"), envelope, 0o644))
	writeJSON(filepath.Join(dir, "case.json"), map[string]string{
		"name": name, "desc": desc, "expect": expect,
	})
}

func writeJSON(path string, v any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	must(os.WriteFile(path, b, 0o644))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
