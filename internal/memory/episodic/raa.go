package episodic

import (
	"context"
	"fmt"

	"aegis/internal/memory/embed"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
)

type RetrievalAugmentedAdjudicator struct {
	LLM      adjudicator.Adjudicator
	Store    *Store
	Embedder embed.Embedder
}

func (r *RetrievalAugmentedAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (adjudicator.Decision, string, error) {
	fv := embed.BuildFeatureVector(event)
	vec, err := r.Embedder.Embed(ctx, fv)
	if err == nil {
		cases, err := r.Store.Query(ctx, repoID, vec, 5)
		if err == nil && len(cases) > 0 {
			for _, c := range cases {
				if c.Decision != adjudicator.DecisionAskUser {
					rationale := fmt.Sprintf("Auto-recalled decision based on PastCase ID: %d. Original: %s", c.ID, c.Rationale)
					_ = r.Store.RecordCase(ctx, repoID, event.SessionID, event, c.Decision, rationale, "auto_recall")
					return c.Decision, rationale, nil
				}
			}
		}
	}

	dec, rat, err := r.LLM.Adjudicate(ctx, repoID, event)
	if err == nil {
		_ = r.Store.RecordCase(ctx, repoID, event.SessionID, event, dec, rat, "llm")
	}
	return dec, rat, err
}
