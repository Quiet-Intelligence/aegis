package episodic

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	"aegis/pkg/adjudicator"
	_ "github.com/mattn/go-sqlite3"
)

func TestVectorRoundTripBinaryAndLegacyJSON(t *testing.T) {
	v := []float32{0, 1, -1, 3.14159, 1e-7, -2.5e9}
	got, err := decodeVector(encodeVector(v), nil)
	if err != nil || len(got) != len(v) {
		t.Fatalf("binary decode failed: %v %v", got, err)
	}
	for i := range v {
		if got[i] != v[i] {
			t.Fatalf("binary round trip mismatch at %d: %v != %v", i, got[i], v[i])
		}
	}
	legacy, _ := json.Marshal(v)
	got, err = decodeVector(legacy, nil)
	if err != nil || len(got) != len(v) || got[3] != v[3] {
		t.Fatalf("legacy JSON decode failed: %v %v", got, err)
	}
	if _, err := decodeVector([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("expected an error for a length that is not a multiple of 4")
	}
}

func TestQueryReturnsMostSimilarFirstAndHonoursThreshold(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := memory.InitSchema(db); err != nil {
		t.Fatal(err)
	}
	db.Exec("INSERT INTO repos (id, remote_url_hash, first_seen) VALUES (1, 'h', ?)", time.Now())
	db.Exec("INSERT INTO sessions (id, repo_id, started_at) VALUES ('s', 1, ?)", time.Now())

	q := []float32{1, 0, 0, 0}
	// similarity to q: 0.9701 (below threshold? no: > 0.95), 0.9998, 0.5 -> only two pass, the closer one must rank first
	cands := [][]float32{{1, 0.25, 0, 0}, {1, 0.02, 0, 0}, {1, 1.7, 0, 0}}
	for _, v := range cands {
		res, _ := db.Exec("INSERT INTO embeddings (vector, dims) VALUES (?, 4)", encodeVector(v))
		id, _ := res.LastInsertId()
		db.Exec(`INSERT INTO flagged_events (session_id, repo_id, event_context_json, embedding_id, decision, rationale, decided_at, decided_by)
			VALUES ('s', 1, '{}', ?, ?, 'r', ?, 'llm')`, id, string(adjudicator.DecisionDeny), time.Now())
	}
	store := NewStore(db, &embed.MockEmbedder{})
	got, err := store.Query(context.Background(), 1, q, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 matches above the 0.95 threshold, got %d", len(got))
	}
	if !(got[0].Similarity > got[1].Similarity) || got[0].ID != 2 {
		t.Fatalf("results not ordered by similarity: %+v", got)
	}
	top1, _ := store.Query(context.Background(), 1, q, 1)
	if len(top1) != 1 || top1[0].ID != 2 {
		t.Fatalf("topK=1 must return the closest match, got %+v", top1)
	}
}
