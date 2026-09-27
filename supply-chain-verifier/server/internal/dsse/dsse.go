// Package dsse 实现 DSSE(Dead Simple Signing Envelope)封装的解析与验签。
// 规范: https://github.com/secure-systems-lab/dsse
package dsse

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope 是 DSSE 封装的线格式。
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64
	Signatures  []Signature `json:"signatures"`
}

// Signature 是信封上的一条签名记录。
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
}

// Parse 解析并做基础结构校验,返回信封与解码后的载荷。
func Parse(raw []byte) (*Envelope, []byte, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("DSSE 信封不是合法 JSON: %w", err)
	}
	if env.PayloadType == "" {
		return nil, nil, errors.New("DSSE 信封缺少 payloadType 字段")
	}
	if len(env.Signatures) == 0 {
		return nil, nil, errors.New("DSSE 信封 signatures 为空,没有任何签名")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("DSSE payload 不是合法 base64: %w", err)
	}
	for i, s := range env.Signatures {
		if _, err := base64.StdEncoding.DecodeString(s.Sig); err != nil {
			return nil, nil, fmt.Errorf("signatures[%d].sig 不是合法 base64: %w", i, err)
		}
	}
	return &env, payload, nil
}

// PAE 按 DSSE 规范构造预认证编码(Pre-Auth Encoding):
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
func PAE(payloadType string, payload []byte) []byte {
	out := []byte("DSSEv1")
	out = append(out, ' ')
	out = append(out, []byte(fmt.Sprintf("%d", len(payloadType)))...)
	out = append(out, ' ')
	out = append(out, []byte(payloadType)...)
	out = append(out, ' ')
	out = append(out, []byte(fmt.Sprintf("%d", len(payload)))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// VerifyResult 记录单条签名的密码学校验结果。
type VerifyResult struct {
	KeyID   string `json:"keyid"`
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason,omitempty"`
	Field   string `json:"field"` // 指向证据中的具体字段
	Index   int    `json:"index"`
}

// VerifySignature 用给定的 Ed25519 公钥校验信封上第 index 条签名。
// pub 为 nil 表示密钥环中找不到 keyid 对应的公钥。
func VerifySignature(env *Envelope, payload []byte, index int, pub ed25519.PublicKey) VerifyResult {
	sig := env.Signatures[index]
	res := VerifyResult{
		KeyID: sig.KeyID,
		Index: index,
		Field: fmt.Sprintf("signatures[%d].sig", index),
	}
	if pub == nil {
		res.Reason = fmt.Sprintf("密钥环中不存在 keyid=%q 的公钥,无法验签", sig.KeyID)
		return res
	}
	sigBytes, _ := base64.StdEncoding.DecodeString(sig.Sig)
	if len(sigBytes) != ed25519.SignatureSize {
		res.Reason = fmt.Sprintf("签名长度 %d 字节,不是合法的 Ed25519 签名(64 字节)", len(sigBytes))
		return res
	}
	if !ed25519.Verify(pub, PAE(env.PayloadType, payload), sigBytes) {
		res.Reason = "Ed25519 签名校验失败,载荷或签名被篡改"
		return res
	}
	res.Valid = true
	return res
}
