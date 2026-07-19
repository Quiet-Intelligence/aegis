package episodic

import (
	"context"
	"database/sql"
	"testing"

	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

func TestQueryExactExecDoesNotCrossCommands(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := memory.InitSchema(db); err != nil {
		t.Fatal(err)
	}

	store := NewStore(db, &embed.MockEmbedder{})
	ls := graph.FlaggedEvent{
		SessionID:  "1-1",
		Event:      &telemetry.Event{Type: "exec", Exec: &telemetry.ExecEvent{}},
		Rule:       "Command execution",
		Resource:   "/usr/bin/ls -la",
		BinaryHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := store.RecordCase(context.Background(), 1, ls.SessionID, ls, adjudicator.DecisionAllow, "safe directory listing", "llm"); err != nil {
		t.Fatal(err)
	}

	got, err := store.QueryExactExec(context.Background(), 1, ls)
	if err != nil || got == nil || got.Decision != adjudicator.DecisionAllow {
		t.Fatalf("exact ls recall failed: case=%+v err=%v", got, err)
	}

	rm := ls
	rm.Resource = "/usr/bin/rm -rf /"
	got, err = store.QueryExactExec(context.Background(), 1, rm)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("ls decision must never recall for rm: %+v", got)
	}

	modified := ls
	modified.BinaryHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	got, err = store.QueryExactExec(context.Background(), 1, modified)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("modified binary at same path must force fresh review: %+v", got)
	}
}
