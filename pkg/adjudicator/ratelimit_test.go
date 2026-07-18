package adjudicator

import (
	"context"
	"testing"
	"time"

	"aegis/pkg/graph"
)

type stubAdjudicator struct {
	calls int
	dec   Decision
}

func (s *stubAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (Decision, string, error) {
	s.calls++
	return s.dec, "stub", nil
}

func TestRateLimit_AllowsWithinBudget(t *testing.T) {
	stub := &stubAdjudicator{dec: DecisionAllow}
	rl := &RateLimitedAdjudicator{Inner: stub, Limit: 3, Window: time.Minute}

	for i := 0; i < 3; i++ {
		dec, _, err := rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{})
		if err != nil || dec != DecisionAllow {
			t.Fatalf("call %d should pass through, got dec=%q err=%v", i, dec, err)
		}
	}
	if stub.calls != 3 {
		t.Fatalf("expected 3 inner calls, got %d", stub.calls)
	}
}

func TestRateLimit_FailsClosedOverBudget(t *testing.T) {
	stub := &stubAdjudicator{dec: DecisionAllow}
	rl := &RateLimitedAdjudicator{Inner: stub, Limit: 2, Window: time.Minute}

	rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{})
	rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{})

	dec, _, err := rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if dec != DecisionDeny {
		t.Fatalf("expected fail-closed Deny, got %q", dec)
	}
	if stub.calls != 2 {
		t.Fatalf("inner must not be called over budget, got %d calls", stub.calls)
	}
}

func TestRateLimit_WindowReset(t *testing.T) {
	stub := &stubAdjudicator{dec: DecisionAllow}
	rl := &RateLimitedAdjudicator{Inner: stub, Limit: 1, Window: 50 * time.Millisecond}

	rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{})
	if _, _, err := rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{}); err == nil {
		t.Fatal("expected second call to be limited")
	}

	time.Sleep(60 * time.Millisecond)

	if _, _, err := rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{}); err != nil {
		t.Fatalf("expected call after window reset to pass, got %v", err)
	}
	if stub.calls != 2 {
		t.Fatalf("expected 2 inner calls total, got %d", stub.calls)
	}
}

func TestRateLimit_UnlimitedWhenZero(t *testing.T) {
	stub := &stubAdjudicator{dec: DecisionAllow}
	rl := &RateLimitedAdjudicator{Inner: stub, Limit: 0}

	for i := 0; i < 100; i++ {
		if _, _, err := rl.Adjudicate(context.Background(), 1, graph.FlaggedEvent{}); err != nil {
			t.Fatalf("unlimited limiter errored: %v", err)
		}
	}
	if stub.calls != 100 {
		t.Fatalf("expected 100 inner calls, got %d", stub.calls)
	}
}
