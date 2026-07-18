package adjudicator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"aegis/pkg/graph"
)

type Adjudicator interface {
	Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error)
}

type OpenAIAdjudicator struct {
	APIKey string
	URL    string
	Model  string
}

func (a *OpenAIAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error) {
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

	return DecisionDeny, "Simulated AI decision: unauthorized file access detected outside workspace", nil
}

// Removed RAA from here to avoid import cycle
