package proxy

import (
	"context"
	"strings"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
)

type RLMCascade struct {
	CheapLLM    adjudicator.Adjudicator
	FlagshipLLM adjudicator.Adjudicator
}

func (c *RLMCascade) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (adjudicator.Decision, string, error) {
	// Simple heuristic for risk routing:
	// If it's a cold start or explicitly touching sensitive files, it's high risk
	isHighRisk := false
	if strings.Contains(event.Rule, "outside workspace") || strings.Contains(event.Rule, "Execution of high-risk binary") || strings.Contains(event.Rule, "repository configuration") {
		isHighRisk = true
	}

	// Also if the context length is very long, escalate to flagship
	if len(event.Context) >= 5 {
		isHighRisk = true
	}

	if isHighRisk && c.FlagshipLLM != nil {
		return c.FlagshipLLM.Adjudicate(ctx, repoID, event)
	}

	if c.CheapLLM != nil {
		return c.CheapLLM.Adjudicate(ctx, repoID, event)
	}

	// Fallback to Flagship if Cheap isn't configured
	if c.FlagshipLLM != nil {
		return c.FlagshipLLM.Adjudicate(ctx, repoID, event)
	}

	return adjudicator.DecisionAllow, "No models configured in RLM Cascade", nil
}
