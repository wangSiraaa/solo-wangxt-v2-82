// Package intoto parses in-toto v1 statements carrying a SLSA provenance
// predicate and exposes the fields the trust policy needs.
package intoto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// StatementType is the in-toto statement _type.
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateType is the SLSA provenance v1 predicate type.
const PredicateType = "https://slsa.dev/provenance/v1"

// Statement is a minimal in-toto v1 statement.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject is one in-toto subject (the artifact the statement attests to).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is a SLSA provenance v1 predicate (subset of fields we enforce).
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes how the artifact was built.
type BuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   map[string]interface{} `json:"externalParameters"`
	InternalParameters   map[string]interface{} `json:"internalParameters"`
	ResolvedDependencies []ResourceDescriptor   `json:"resolvedDependencies"`
}

// RunDetails describes the build run.
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   BuildMetadata        `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts"`
}

// Builder identifies the build system / actor.
type Builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

// BuildMetadata holds build timing info.
type BuildMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// ResourceDescriptor is an in-toto resource descriptor.
type ResourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
	Name   string            `json:"name,omitempty"`
}

// Parse decodes an in-toto statement from JSON and validates required fields.
func Parse(payload []byte) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("payload is not valid JSON: %w", err)
	}
	if st.Type == "" {
		return nil, fmt.Errorf("statement missing _type")
	}
	if st.Type != StatementType {
		return nil, fmt.Errorf("statement _type %q is not %q", st.Type, StatementType)
	}
	if len(st.Subject) == 0 {
		return nil, fmt.Errorf("statement has no subject")
	}
	if st.PredicateType == "" {
		return nil, fmt.Errorf("statement missing predicateType")
	}
	if st.PredicateType != PredicateType {
		return nil, fmt.Errorf("predicateType %q is not %q", st.PredicateType, PredicateType)
	}
	if st.Predicate.BuildDefinition.BuildType == "" {
		return nil, fmt.Errorf("predicate.buildDefinition.buildType is empty")
	}
	if st.Predicate.RunDetails.Builder.ID == "" {
		return nil, fmt.Errorf("predicate.runDetails.builder.id is empty")
	}
	return &st, nil
}

// Sha256Hex computes the hex sha256 of data (helper used by verifier).
func Sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// FindSubject returns the subject whose name matches the artifact filename,
// or nil if none matches.
func (s *Statement) FindSubject(name string) *Subject {
	for i := range s.Subject {
		if s.Subject[i].Name == name {
			return &s.Subject[i]
		}
	}
	return nil
}

// SourceDigest returns the sha256 digest of the first resolved dependency
// whose URI looks like a git source (used to pin the source commit).
func (s *Statement) SourceDigest() (string, string) {
	for _, dep := range s.Predicate.BuildDefinition.ResolvedDependencies {
		if strings.HasPrefix(dep.URI, "git+") || strings.Contains(dep.URI, ".git") {
			if d, ok := dep.Digest["sha256"]; ok {
				return dep.URI, d
			}
			if d, ok := dep.Digest["gitCommit"]; ok {
				return dep.URI, d
			}
		}
	}
	return "", ""
}
