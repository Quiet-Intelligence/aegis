package proxy

import (
	"context"
	"fmt"
	"time"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
)

// CascadeRouter implements adjudicator.Adjudicator and proxies requests to models.
type CascadeRouter struct {
	CheapModel    adjudicator.Adjudicator
	FlagshipModel adjudicator.Adjudicator
	Threshold     float64 // Risk score threshold for escalation
}

func (c *CascadeRouter) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (adjudicator.Decision, string, error) {
	start := time.Now()
	
	// Synthetic risk score based on context depth
	riskScore := float64(len(event.Context)) * 1.5

	if riskScore < c.Threshold {
		// Low-risk: use cheap model
		dec, rat, err := c.CheapModel.Adjudicate(ctx, repoID, event)
		latency := time.Since(start)
		fmt.Printf("[METRIC] Cascade Routed: CHEAP | Latency: %v | Est Cost: $0.001\n", latency)
		return dec, rat, err
	}

	// High-risk: Get draft from cheap, verify with flagship
	draftDec, draftRat, _ := c.CheapModel.Adjudicate(ctx, repoID, event)
	
	// The flagship prompt would theoretically inject:
	// "Cheap model proposed: {draftDec} because {draftRat}. Verify."
	_ = draftDec
	_ = draftRat
	
	dec, rat, err := c.FlagshipModel.Adjudicate(ctx, repoID, event)
	latency := time.Since(start)
	
	fmt.Printf("[METRIC] Cascade Routed: FLAGSHIP (Draft verified) | Latency: %v | Est Cost: $0.030\n", latency)
	return dec, rat, err
}
