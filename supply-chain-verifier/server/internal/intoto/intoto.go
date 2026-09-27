// Package intoto 解析 in-toto Attestation(SLSA Provenance)声明。
// 规范: https://github.com/in-toto/attestation
package intoto

import (
	"encoding/json"
	"fmt"
)

// Statement 是 in-toto Statement 层结构。
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject 描述声明所针对的产物及其摘要。
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Provenance 是 SLSA v1 Provenance 谓词中我们关心的子集。
type Provenance struct {
	BuildDefinition struct {
		BuildType string `json:"buildType"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

// ParseStatement 解析 in-toto 声明并做结构校验。
func ParseStatement(payload []byte) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("DSSE 载荷不是合法 JSON: %w", err)
	}
	if st.Type == "" {
		return nil, fmt.Errorf("声明缺少 _type 字段")
	}
	if len(st.Subject) == 0 {
		return nil, fmt.Errorf("声明 subject 为空,无法核对产物摘要")
	}
	if st.Subject[0].Digest["sha256"] == "" {
		return nil, fmt.Errorf("声明 subject[0].digest 缺少 sha256 项")
	}
	if st.PredicateType == "" {
		return nil, fmt.Errorf("声明缺少 predicateType 字段")
	}
	return &st, nil
}

// ParseProvenance 从声明谓词中解析 SLSA Provenance,提取构建者身份。
func ParseProvenance(st *Statement) (*Provenance, error) {
	var p Provenance
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, fmt.Errorf("predicate 不是合法的 SLSA Provenance: %w", err)
	}
	return &p, nil
}
