package graph

import (
	"database/sql"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

// benchScorer returns a scorer over an in-memory SQLite database with a very large semantic baseline, so benign
// events stay on the steady-state path (rules evaluated, session graph appended, baseline row read) and never flag.
func benchScorer(b *testing.B) *Scorer {
	b.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	b.Cleanup(func() { db.Close() })
	if err := memory.InitSchema(db); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO repos (id, remote_url_hash, first_seen) VALUES (1, 'bench', ?)", time.Now()); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO semantic_baseline (repo_id, feature_key, ema_value, updated_at) VALUES (1, 'flagged_event_count', 1e12, ?)", time.Now()); err != nil {
		b.Fatal(err)
	}
	s := NewScorer(db, 1, "/workspace")
	s.AdjudicateAllExec = false
	return s
}

// BenchmarkScorerProcessEvent measures the userspace cost of scoring one benign kernel event end to end
// (session lookup, rule evaluation, graph update, SQLite baseline read). It excludes the eBPF ring buffer.
func BenchmarkScorerProcessEvent(b *testing.B) {
	b.Run("file_open_in_workspace", func(b *testing.B) {
		s := benchScorer(b)
		ev := fileEvent(100, "/workspace/src/main.c", 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.processEvent(ev)
			if len(s.graphs["100-1"].Nodes) > 4096 { // keep the session graph bounded so the benchmark measures steady state
				s.graphs["100-1"].Nodes, s.graphs["100-1"].Edges, s.graphs["100-1"].Events = nil, nil, nil
			}
		}
	})
	b.Run("exec_benign", func(b *testing.B) {
		s := benchScorer(b)
		ev := execEvent(101, "/usr/bin/ls", "ls\x00-la", 2)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.processEvent(ev)
			if len(s.graphs["101-1"].Nodes) > 4096 {
				s.graphs["101-1"].Nodes, s.graphs["101-1"].Edges, s.graphs["101-1"].Events = nil, nil, nil
			}
		}
	})
	b.Run("file_open_flagged_outside_workspace", func(b *testing.B) {
		s := benchScorer(b)
		s.FlagCooldown = 0
		go func() {
			for range s.Flagged() { // drain
			}
		}()
		ev := fileEvent(102, "/etc/shadow", 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.processEvent(ev)
			if len(s.graphs["102-1"].Nodes) > 4096 {
				s.graphs["102-1"].Nodes, s.graphs["102-1"].Edges, s.graphs["102-1"].Events = nil, nil, nil
			}
		}
	})
}

var _ = telemetry.MaxPathLen
