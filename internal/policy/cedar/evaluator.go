package cedar

import (
	"context"
)

// Decision represents the result of a Cedar policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "Allow"
	DecisionDeny  Decision = "Deny"
)

// Request defines the Cedar authorization request shape.
type Request struct {
	Principal string
	Action    string
	Resource  string
	Context   map[string]interface{}
}

// Response defines the Cedar authorization response shape.
type Response struct {
	Decision Decision
	Reasons  []string
	Errors   []string
}

// Evaluator is the interface for AWS Cedar policy evaluation.
type Evaluator interface {
	IsAuthorized(ctx context.Context, req Request) (Response, error)
}

// MockEvaluator provides a stubbed Cedar evaluator for FP1-1.
// In a future PR, this will be replaced with CGO/WASM bindings to the Rust engine.
type MockEvaluator struct {
	Policies []string
}

func NewMockEvaluator(policies []string) *MockEvaluator {
	return &MockEvaluator{Policies: policies}
}

func (e *MockEvaluator) IsAuthorized(ctx context.Context, req Request) (Response, error) {
	// Hardcoded mock logic to unblock development
	// Denies any action against .git/* to simulate a strict policy
	if req.Resource == ".git/credentials" || req.Resource == ".ssh/id_rsa" {
		return Response{
			Decision: DecisionDeny,
			Reasons:  []string{"policy0: deny access to sensitive keys"},
		}, nil
	}

	return Response{
		Decision: DecisionAllow,
		Reasons:  []string{"policy1: default allow"},
	}, nil
}
