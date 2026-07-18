package graph

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

func fileEvent(pid uint32, path string) *telemetry.Event {
	ev := &telemetry.Event{Type: "file_open", FileOpen: &telemetry.FileOpenEvent{Pid: pid, CgroupId: 1}}
	copy(ev.FileOpen.Path[:], path)
	return ev
}

func newTestScorer(t *testing.T) *Scorer {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := memory.InitSchema(db); err != nil {
		t.Fatal(err)
	}
	return NewScorer(db, 1, "/workspace")
}

func flagWithin(s *Scorer, d time.Duration) bool {
	select {
	case <-s.Flagged():
		return true
	case <-time.After(d):
		return false
	}
}

func TestScorer_FlagsFirstOffense(t *testing.T) {
	s := newTestScorer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *telemetry.Event, 10)
	go s.Consume(ctx, ch)

	ch <- fileEvent(100, "/etc/shadow")
	if !flagWithin(s, 200*time.Millisecond) {
		t.Fatal("expected first out-of-workspace open to be flagged")
	}
}

func TestScorer_CooldownSuppressesRepeats(t *testing.T) {
	s := newTestScorer(t)
	s.FlagCooldown = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *telemetry.Event, 10)
	go s.Consume(ctx, ch)

	ch <- fileEvent(100, "/etc/shadow")
	if !flagWithin(s, 200*time.Millisecond) {
		t.Fatal("expected first offense to be flagged")
	}

	// Same session, same rule, inside the window: suppressed.
	ch <- fileEvent(100, "/etc/passwd")
	if flagWithin(s, 200*time.Millisecond) {
		t.Fatal("expected repeat flag within cooldown to be suppressed")
	}

	// Different session: unaffected by the first session's cooldown.
	ch <- fileEvent(200, "/etc/passwd")
	if !flagWithin(s, 200*time.Millisecond) {
		t.Fatal("expected other session to still be flagged")
	}
}

func TestScorer_CooldownExpiry(t *testing.T) {
	s := newTestScorer(t)
	s.FlagCooldown = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *telemetry.Event, 10)
	go s.Consume(ctx, ch)

	ch <- fileEvent(100, "/etc/shadow")
	if !flagWithin(s, 200*time.Millisecond) {
		t.Fatal("expected first offense to be flagged")
	}

	time.Sleep(150 * time.Millisecond) // let the window expire

	ch <- fileEvent(100, "/etc/shadow")
	if !flagWithin(s, 300*time.Millisecond) {
		t.Fatal("expected flag to fire again after cooldown expiry")
	}
}

func TestScorer_WorkspacePathsNotFlagged(t *testing.T) {
	s := newTestScorer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *telemetry.Event, 10)
	go s.Consume(ctx, ch)

	ch <- fileEvent(100, "/workspace/src/main.go")
	if flagWithin(s, 150*time.Millisecond) {
		t.Fatal("workspace path should never be flagged")
	}
}
