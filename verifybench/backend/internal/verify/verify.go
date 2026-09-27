// Package verify orchestrates the full verification pipeline:
// parse DSSE envelope -> parse in-toto statement -> verify signatures ->
// hash artifact -> evaluate OPA trust policy -> produce a record.
//
// The pipeline NEVER executes artifact content; bytes are only hashed.
package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/example/verifybench/internal/dsse"
	"github.com/example/verifybench/internal/intoto"
	"github.com/example/verifybench/internal/policy"
	"github.com/example/verifybench/internal/trust"
)

// Record is the persisted verification outcome.
type Record struct {
	ID             string             `json:"id"`
	CreatedAt      time.Time          `json:"createdAt"`
	ArtifactName   string             `json:"artifactName"`
	ArtifactSize   int64              `json:"artifactSize"`
	ArtifactSHA256 string             `json:"artifactSha256"`
	EnvelopeRaw    RawJSON            `json:"envelopeRaw"`
	Statement      json.RawMessage    `json:"statement"`
	PayloadType    string             `json:"payloadType"`
	Signatures     []dsse.SigResult   `json:"signatures"`
	BuilderID      string             `json:"builderId"`
	BuildType      string             `json:"buildType"`
	SourceURI      string             `json:"sourceUri"`
	SourceCommit   string             `json:"sourceCommit"`
	SubjectDigest  string             `json:"subjectDigest"`
	Checks         map[string]bool    `json:"checks"`
	Violations     []policy.Violation `json:"violations"`
	Allow          bool               `json:"allow"`
	// Fatal, if set, means parsing/verification could not even reach policy
	// evaluation (e.g. malformed envelope). The field points at the evidence
	// location that failed.
	Fatal *FatalError `json:"fatal,omitempty"`
}

// FatalError is a pre-policy failure located at an evidence field.
type FatalError struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Verifier bundles the trust root and policy evaluator.
type Verifier struct {
	root *trust.Root
	eval *policy.Evaluator
}

// New builds a Verifier.
func New(root *trust.Root, eval *policy.Evaluator) *Verifier {
	return &Verifier{root: root, eval: eval}
}

// Verify runs the full pipeline. artifactName is the client-supplied file
// name (used to match the statement subject); artifact is the raw bytes.
func (v *Verifier) Verify(ctx context.Context, artifactName string, artifact, envelopeRaw []byte) (*Record, error) {
	rec := &Record{
		CreatedAt:    time.Now().UTC(),
		ArtifactName: artifactName,
		ArtifactSize: int64(len(artifact)),
		EnvelopeRaw:  RawJSON(envelopeRaw),
	}
	sum := sha256.Sum256(artifact)
	rec.ArtifactSHA256 = hex.EncodeToString(sum[:])

	// 1. Parse the DSSE envelope.
	env, payload, err := dsse.Decode(envelopeRaw)
	if err != nil {
		rec.Fatal = &FatalError{Code: "envelope_parse_error", Field: "(envelope)", Message: err.Error()}
		return rec, nil
	}
	rec.PayloadType = env.PayloadType

	// 2. Verify signatures cryptographically (mature crypto: crypto/ed25519).
	sigs, err := dsse.Verify(env, payload, v.root.Ring)
	if err != nil {
		rec.Fatal = &FatalError{Code: "signature_verify_error", Field: "signatures", Message: err.Error()}
		return rec, nil
	}
	rec.Signatures = sigs

	// 3. Parse the in-toto statement.
	st, err := intoto.Parse(payload)
	if err != nil {
		rec.Fatal = &FatalError{Code: "statement_parse_error", Field: "payload", Message: err.Error()}
		return rec, nil
	}
	stmtJSON, _ := json.Marshal(st)
	rec.Statement = stmtJSON
	rec.BuilderID = st.Predicate.RunDetails.Builder.ID
	rec.BuildType = st.Predicate.BuildDefinition.BuildType
	if uri, commit := st.SourceDigest(); uri != "" {
		rec.SourceURI = uri
		rec.SourceCommit = commit
	}
	if sub := st.FindSubject(artifactName); sub != nil {
		rec.SubjectDigest = sub.Digest["sha256"]
	}

	// 4. Build policy input and evaluate the OPA trust policy.
	builders := map[string]map[string]string{}
	for id, k := range v.root.ByBuilder {
		builders[id] = map[string]string{"keyId": k.KeyID}
	}
	input := map[string]interface{}{
		"payloadType": rec.PayloadType,
		"artifact": map[string]interface{}{
			"name":   artifactName,
			"sha256": rec.ArtifactSHA256,
		},
		"statement":  st,
		"signatures": sigs,
		"trust": map[string]interface{}{
			"builders":           builders,
			"allowedSourceHosts": v.root.Config.AllowedSourceHosts,
			"allowedBuildTypes":  v.root.Config.AllowedBuildTypes,
		},
	}
	res, err := v.eval.Eval(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	rec.Checks = res.Checks
	rec.Violations = res.Violations
	rec.Allow = res.Allow
	return rec, nil
}
