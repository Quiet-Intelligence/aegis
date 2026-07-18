package adjudicator

import (
	"context"
	"errors"
	"sync"
	"time"

	"aegis/pkg/graph"
)

// RateLimitedAdjudicator wraps an Adjudicator with a fixed-window call
// budget. Calls beyond the budget fail closed WITHOUT touching the
// network — a hard cap on LLM spend no matter how noisy the monitored
// workload gets. Wraps the base LLM only: memory auto-recall (RAA cache
// hits) happens upstream and stays free.
type RateLimitedAdjudicator struct {
	Inner  Adjudicator
	Limit  int           // max adjudications per Window; <=0 means unlimited
	Window time.Duration // budget window; defaults to 1 minute

	mu          sync.Mutex
	windowStart time.Time
	count       int
}

func (r *RateLimitedAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error) {
	if r.Limit > 0 {
		window := r.Window
		if window <= 0 {
			window = time.Minute
		}

		r.mu.Lock()
		now := time.Now()
		if now.Sub(r.windowStart) >= window {
			r.windowStart = now
			r.count = 0
		}
		if r.count >= r.Limit {
			r.mu.Unlock()
			return DecisionAskUser, "adjudication rate limit reached; human review required (no automatic block added)",
				errors.New("adjudication rate limit exceeded")
		}
		r.count++
		r.mu.Unlock()
	}
	return r.Inner.Adjudicate(ctx, repoID, event)
}
