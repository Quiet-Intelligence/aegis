package adjudicator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
	eventJSON, _ := json.Marshal(event.Event)
	contextJSON, _ := json.Marshal(event.Context)
	prompt := fmt.Sprintf("Event flagged: %s\nContext: %s\nRule: %s\nOutput JSON with {decision, rationale}. decision must be Allow, Deny, or AskUser.", string(eventJSON), string(contextJSON), event.Rule)

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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return DecisionAllow, "Fail-open on network error: " + err.Error(), err
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return DecisionAllow, "Failed to decode response: " + err.Error(), err
	}

	if len(result.Choices) == 0 {
		return DecisionAllow, "Empty response from LLM", nil
	}

	content := result.Choices[0].Message.Content
	var llmResp struct {
		Decision  string `json:"decision"`
		Rationale string `json:"rationale"`
	}

	if err := json.Unmarshal([]byte(content), &llmResp); err != nil {
		// Basic fallback string match if model didn't return proper JSON
		if bytes.Contains([]byte(content), []byte("Deny")) {
			return DecisionDeny, content, nil
		}
		return DecisionAllow, content, nil
	}

	switch llmResp.Decision {
	case "Allow":
		return DecisionAllow, llmResp.Rationale, nil
	case "Deny":
		return DecisionDeny, llmResp.Rationale, nil
	case "AskUser":
		return DecisionAskUser, llmResp.Rationale, nil
	default:
		return DecisionAllow, llmResp.Rationale, nil
	}
}

// Removed RAA from here to avoid import cycle
