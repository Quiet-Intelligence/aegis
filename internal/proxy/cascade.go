package proxy

import (
	"context"
	"strings"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
)

type RLMCascade struct {
	SFTTier     adjudicator.Adjudicator // Fine-tuned local model (e.g. Llama 3 8B)
	CheapLLM    adjudicator.Adjudicator
	FlagshipLLM adjudicator.Adjudicator
	
	// SFTEnabled is the config flag to disable the SFT tier by default.
	// REQUIREMENT (RL2-10): A fresh full run of both the static evals harness 
	// and the trajectory harness must be logged and reviewed before enabling this.
	SFTEnabled  bool
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

	if c.SFTEnabled && c.SFTTier != nil {
		// Attempt SFT Tier first for low-risk events
		dec, rat, err := c.SFTTier.Adjudicate(ctx, repoID, event)
		if err == nil {
			return dec, rat, nil
		}
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
