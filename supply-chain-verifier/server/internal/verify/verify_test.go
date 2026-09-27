package verify_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/supply-chain-verifier/internal/verify"
)

// 以 fixtures 三组固定演示数据驱动端到端核验:
// valid -> allow,tampered / untrusted-builder -> deny,且失败定位到预期字段。
func TestDemoFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	keyringBytes, err := os.ReadFile(filepath.Join(root, "fixtures", "keys", "keyring.json"))
	if err != nil {
		t.Skipf("fixtures 未生成,跳过(先运行 make fixtures): %v", err)
	}
	var keys []verify.Key
	if err := json.Unmarshal(keyringBytes, &keys); err != nil {
		t.Fatal(err)
	}

	eval, err := verify.NewPolicyEvaluator(context.Background(),
		filepath.Join(root, "policy", "trust.rego"),
		filepath.Join(root, "policy", "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := verify.New(keys, eval)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		wantDecision string
		wantField    string // 期望出现在 violations 中的字段,allow 时为空
	}{
		{"valid", "allow", ""},
		{"tampered", "deny", "subject[0].digest.sha256"},
		{"untrusted-builder", "deny", "signatures[0].keyid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(root, "fixtures", tc.name)
			artifact, err := os.ReadFile(filepath.Join(dir, "artifact.bin"))
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := os.ReadFile(filepath.Join(dir, "envelope.json"))
			if err != nil {
				t.Fatal(err)
			}
			res, err := v.Run(context.Background(), "artifact.bin", artifact, envelope)
			if err != nil {
				t.Fatal(err)
			}
			if res.Decision != tc.wantDecision {
				t.Fatalf("decision = %s, want %s", res.Decision, tc.wantDecision)
			}
			if tc.wantField == "" {
				if len(res.Policy.Violations) != 0 {
					t.Fatalf("unexpected violations: %+v", res.Policy.Violations)
				}
				return
			}
			found := false
			for _, vio := range res.Policy.Violations {
				if vio.Field == tc.wantField {
					found = true
				}
			}
			if !found {
				t.Fatalf("violations 中未找到字段 %s: %+v", tc.wantField, res.Policy.Violations)
			}
		})
	}
}
