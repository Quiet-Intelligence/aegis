package adjudicator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"aegis/pkg/graph"
)

type Decision string

const (
	DecisionAllow   Decision = "Allow"
	DecisionDeny    Decision = "Deny"
	DecisionAskUser Decision = "AskUser"
)

type Adjudicator interface {
	Adjudicate(ctx context.Context, event graph.FlaggedEvent) (Decision, string, error)
}

type AdjudicationResponse struct {
	Decision  Decision `json:"decision"`
	Rationale string   `json:"rationale"`
}

type OpenAIAdjudicator struct {
	APIKey string
	URL    string
	Model  string
}

func (a *OpenAIAdjudicator) Adjudicate(ctx context.Context, event graph.FlaggedEvent) (Decision, string, error) {
	prompt := fmt.Sprintf("Event flagged: %v, Context: %v. Rule: %s. Output JSON with {decision, rationale}. decision must be Allow, Deny, or AskUser.", event.Event, event.Context, event.Rule)

	payload := map[string]interface{}{
		"model": a.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are Aegis, a zero-trust agentic security boundary."},
			{"role": "user", "content": prompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", a.URL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+a.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// In a real execution, we would parse response JSON.
	// We simulate a strict deny for demo purposes on rule violation.
	return DecisionDeny, "Simulated AI decision: unauthorized file access detected outside workspace", nil
}

type AnthropicAdjudicator struct {
	APIKey string
}

func (a *AnthropicAdjudicator) Adjudicate(ctx context.Context, event graph.FlaggedEvent) (Decision, string, error) {
	return DecisionAskUser, "Simulated Anthropic decision: Requires user input for this access pattern", nil
}
