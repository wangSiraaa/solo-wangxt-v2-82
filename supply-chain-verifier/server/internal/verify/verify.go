// Package verify 串联完整核验流水线:
// DSSE 解析 -> Ed25519 验签 -> in-toto 声明解析 -> 产物摘要比对 -> OPA 策略判定。
// 安全约束:产物字节只用于计算 SHA-256,绝不被执行、解压或解释。
package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/example/supply-chain-verifier/internal/dsse"
	"github.com/example/supply-chain-verifier/internal/intoto"
)

// Key 是密钥环中一个已知构建者的公钥。
type Key struct {
	KeyID string `json:"keyid"`
	Owner string `json:"owner"`
	Algo  string `json:"algo"`
	Pub   string `json:"pub"` // base64 ed25519 公钥
}

// Violation 是一条策略违反记录,Field 指向证据中的具体字段(JSON 路径)。
type Violation struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// SignaturePanel 签名有效性面板数据。
type SignaturePanel struct {
	OK        bool                 `json:"ok"`
	Results   []dsse.VerifyResult  `json:"results"`
	PayloadType string             `json:"payloadType,omitempty"`
	Error     string               `json:"error,omitempty"`
}

// IssuerPanel 签发者信任面板数据。
type IssuerPanel struct {
	OK      bool   `json:"ok"`
	KeyID   string `json:"keyid"`
	Owner   string `json:"owner,omitempty"`
	Field   string `json:"field"`
	Message string `json:"message,omitempty"`
}

// DigestPanel 摘要一致性面板数据。
type DigestPanel struct {
	OK       bool   `json:"ok"`
	Expected string `json:"expected"` // 声明中的摘要
	Actual   string `json:"actual"`   // 本地产物实际摘要
	Field    string `json:"field"`
	Message  string `json:"message,omitempty"`
}

// PolicyPanel 策略结论面板数据。
type PolicyPanel struct {
	Allow      bool        `json:"allow"`
	Violations []Violation `json:"violations"`
}

// Result 是一次核验的完整判定结果。
type Result struct {
	ArtifactName   string          `json:"artifactName"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	ArtifactSize   int             `json:"artifactSize"`
	Envelope       json.RawMessage `json:"envelope"`
	Statement      json.RawMessage `json:"statement,omitempty"`
	Signature      SignaturePanel  `json:"signature"`
	Issuer         IssuerPanel     `json:"issuer"`
	Digest         DigestPanel     `json:"digest"`
	Policy         PolicyPanel     `json:"policy"`
	Decision       string          `json:"decision"` // "allow" | "deny"
}

// Verifier 持有密钥环与 OPA 求值器。
type Verifier struct {
	keys map[string]Key // keyid -> key
	eval *PolicyEvaluator
}

// New 构造核验器。keys 为已知公钥(含可信与不可信),eval 为 OPA 策略求值器。
func New(keys []Key, eval *PolicyEvaluator) (*Verifier, error) {
	m := map[string]Key{}
	for _, k := range keys {
		if k.Algo != "ed25519" {
			return nil, fmt.Errorf("keyid=%q 使用不支持的算法 %q(仅支持 ed25519)", k.KeyID, k.Algo)
		}
		m[k.KeyID] = k
	}
	return &Verifier{keys: m, eval: eval}, nil
}

// Run 对一份本地产物与一份 DSSE 证据执行完整核验。
// artifact 内容只参与 SHA-256 计算,函数内不存在任何执行产物的路径。
func (v *Verifier) Run(ctx context.Context, artifactName string, artifact []byte, envelopeRaw []byte) (*Result, error) {
	sum := sha256.Sum256(artifact)
	res := &Result{
		ArtifactName:   artifactName,
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		ArtifactSize:   len(artifact),
		Envelope:       json.RawMessage(envelopeRaw),
	}

	// 1. 解析 DSSE 信封
	env, payload, err := dsse.Parse(envelopeRaw)
	if err != nil {
		res.Signature.Error = err.Error()
		res.Signature.OK = false
		return v.finish(ctx, res, nil)
	}
	res.Signature.PayloadType = env.PayloadType

	// 2. 逐条验签(Ed25519,成熟标准库密码实现)
	allOK := true
	for i := range env.Signatures {
		keyid := env.Signatures[i].KeyID
		var pub ed25519.PublicKey
		if k, known := v.keys[keyid]; known {
			pub = decodePub(k.Pub)
		}
		r := dsse.VerifySignature(env, payload, i, pub)
		if !r.Valid {
			allOK = false
		}
		res.Signature.Results = append(res.Signature.Results, r)
	}
	res.Signature.OK = allOK

	// 3. 解析 in-toto 声明
	st, err := intoto.ParseStatement(payload)
	if err != nil {
		res.Digest = DigestPanel{OK: false, Actual: res.ArtifactSHA256, Field: "subject[0].digest.sha256", Message: err.Error()}
		res.Statement = json.RawMessage(payload)
		return v.finish(ctx, res, nil)
	}
	res.Statement = json.RawMessage(payload)

	prov, _ := intoto.ParseProvenance(st) // 解析失败时 builder 为空,交给策略拒绝
	builderID := ""
	if prov != nil {
		builderID = prov.RunDetails.Builder.ID
	}

	// 4. 摘要一致性:声明中的 subject 摘要 vs 本地产物实际摘要
	expected := st.Subject[0].Digest["sha256"]
	digestOK := expected == res.ArtifactSHA256
	res.Digest = DigestPanel{
		OK:       digestOK,
		Expected: expected,
		Actual:   res.ArtifactSHA256,
		Field:    "subject[0].digest.sha256",
	}
	if !digestOK {
		res.Digest.Message = fmt.Sprintf("声明摘要 %s 与本地产物实际摘要 %s 不一致,产物可能被篡改", short(expected), short(res.ArtifactSHA256))
	}

	// 5. 签发者信任 + 整体策略结论,统一交给 OPA 判定
	signerKeyID := ""
	if len(env.Signatures) > 0 {
		signerKeyID = env.Signatures[0].KeyID
	}
	input := map[string]any{
		"signature_valid": res.Signature.OK,
		"signer_keyid":    signerKeyID,
		"builder_id":      builderID,
		"digest_match":    digestOK,
		"statement_type":  st.Type,
		"predicate_type":  st.PredicateType,
		"artifact_name":   artifactName,
		"artifact_sha256": res.ArtifactSHA256,
	}
	decision, err := v.eval.Evaluate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("OPA 策略求值失败: %w", err)
	}
	res.Policy = PolicyPanel{Allow: decision.Allow, Violations: decision.Violations}

	// 签发者面板:从策略违反中定位 keyid 字段,或从密钥环取 owner
	res.Issuer = IssuerPanel{OK: true, KeyID: signerKeyID, Field: "signatures[0].keyid"}
	if k, known := v.keys[signerKeyID]; known {
		res.Issuer.Owner = k.Owner
	}
	for _, vio := range decision.Violations {
		if vio.Field == "signatures[0].keyid" || vio.Field == "builder_id" {
			res.Issuer.OK = false
			res.Issuer.Message = vio.Message
			break
		}
	}

	return v.finish(ctx, res, decision)
}

// finish 汇总最终判定。任何一步失败都走 deny,且全程不执行产物内容。
func (v *Verifier) finish(ctx context.Context, res *Result, decision *Decision) (*Result, error) {
	switch {
	case res.Signature.Error != "" || !res.Signature.OK:
		res.Decision = "deny"
		if len(res.Policy.Violations) == 0 {
			for _, r := range res.Signature.Results {
				if !r.Valid {
					res.Policy.Violations = append(res.Policy.Violations, Violation{Field: r.Field, Message: r.Reason})
				}
			}
			if res.Signature.Error != "" {
				res.Policy.Violations = append(res.Policy.Violations, Violation{Field: "payloadType", Message: res.Signature.Error})
			}
		}
	case decision == nil:
		// 声明解析失败,无法进入策略评估
		res.Decision = "deny"
		res.Policy.Violations = append(res.Policy.Violations, Violation{Field: res.Digest.Field, Message: res.Digest.Message})
	case decision.Allow:
		res.Decision = "allow"
	default:
		res.Decision = "deny"
	}
	if res.Policy.Violations == nil {
		res.Policy.Violations = []Violation{}
	}
	return res, nil
}

func decodePub(b64 string) ed25519.PublicKey {
	raw, err := base64Decode(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}
