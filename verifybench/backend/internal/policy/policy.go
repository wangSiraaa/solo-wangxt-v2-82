// Package policy compiles and evaluates the OPA Rego trust policy.
package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed supplychain.rego
var source string

// Violation is one policy denial mapped to the evidence field that caused it.
type Violation struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Result is the policy decision.
type Result struct {
	Allow      bool            `json:"allow"`
	Violations []Violation     `json:"violations"`
	Checks     map[string]bool `json:"checks"`
}

// Evaluator holds a prepared OPA query.
type Evaluator struct {
	query rego.PreparedEvalQuery
}

// New compiles the embedded policy and prepares the result query.
func New() (*Evaluator, error) {
	r := rego.New(
		rego.Query("data.supplychain.verify.result"),
		rego.Module("supplychain.rego", source),
		rego.StrictBuiltinErrors(true),
	)
	q, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile rego policy: %w", err)
	}
	return &Evaluator{query: q}, nil
}

// Eval runs the prepared query against the verifier-built input.
func (e *Evaluator) Eval(ctx context.Context, input interface{}) (*Result, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluate rego policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("policy returned no result")
	}
	val, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("marshal policy result: %w", err)
	}
	var out Result
	if err := json.Unmarshal(val, &out); err != nil {
		return nil, fmt.Errorf("decode policy result: %w", err)
	}
	// Deterministic violation ordering for stable UI/storage output.
	sort.SliceStable(out.Violations, func(i, j int) bool {
		if out.Violations[i].Code != out.Violations[j].Code {
			return out.Violations[i].Code < out.Violations[j].Code
		}
		return out.Violations[i].Field < out.Violations[j].Field
	})
	if out.Checks == nil {
		out.Checks = map[string]bool{}
	}
	return &out, nil
}

// PolicySource returns the Rego source (for display in the UI).
func PolicySource() string { return source }
