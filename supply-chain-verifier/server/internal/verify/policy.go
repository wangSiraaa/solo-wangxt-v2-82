package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// Decision 是 OPA 策略返回的判定。
type Decision struct {
	Allow      bool        `json:"allow"`
	Violations []Violation `json:"violations"`
}

// PolicyEvaluator 封装 OPA 的预编译查询。
type PolicyEvaluator struct {
	pq rego.PreparedEvalQuery
}

// NewPolicyEvaluator 从 rego 文件与 data JSON 文件加载信任策略。
func NewPolicyEvaluator(ctx context.Context, regoPath, dataPath string) (*PolicyEvaluator, error) {
	dataBytes, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, fmt.Errorf("读取策略数据 %s 失败: %w", dataPath, err)
	}
	var data map[string]any
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return nil, fmt.Errorf("策略数据 %s 不是合法 JSON: %w", dataPath, err)
	}
	regoBytes, err := os.ReadFile(regoPath)
	if err != nil {
		return nil, fmt.Errorf("读取策略文件 %s 失败: %w", regoPath, err)
	}
	pq, err := rego.New(
		rego.Query("data.supplychain.decision"),
		rego.Module("trust.rego", string(regoBytes)),
		rego.Store(inmem.NewFromObject(data)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("编译 OPA 策略失败: %w", err)
	}
	return &PolicyEvaluator{pq: pq}, nil
}

// Evaluate 用核验事实作为 input 求值策略。
func (e *PolicyEvaluator) Evaluate(ctx context.Context, input map[string]any) (*Decision, error) {
	rs, err := e.pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("策略未返回 decision 文档")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("解析策略输出失败: %w", err)
	}
	if d.Violations == nil {
		d.Violations = []Violation{}
	}
	return &d, nil
}
