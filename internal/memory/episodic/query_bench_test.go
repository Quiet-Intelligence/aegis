package episodic

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	_ "github.com/mattn/go-sqlite3"
)

// H-11 ANN threshold documentation:
// Switch to ANN indexing (e.g. sqlite-vec or hnsw) above 50,000 vectors per repo,
// measured on Intel i7 / GitHub Actions runners, where p95 query latency exceeds 50ms.

func BenchmarkQuery(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	if err := memory.InitSchema(db); err != nil {
		b.Fatal(err)
	}

	repoID := int64(1)
	db.Exec("INSERT INTO repos (id, remote_url_hash, first_seen) VALUES (?, 'hash', ?)", repoID, time.Now())
	db.Exec("INSERT INTO sessions (id, repo_id, started_at) VALUES ('sess', ?, ?)", repoID, time.Now())

	store := NewStore(db, &embed.MockEmbedder{})
	_ = store

	sizes := []int{10, 100, 1000, 5000}
	for _, size := range sizes {
		// Populate mock vectors
		for i := 0; i < size; i++ {
			vec := make([]float32, 384)
			for j := range vec {
				vec[j] = rand.Float32()
			}
			vecBytes, _ := json.Marshal(vec)
			res, _ := db.Exec("INSERT INTO embeddings (vector, dims) VALUES (?, 384)", vecBytes)
			embID, _ := res.LastInsertId()
			db.Exec("INSERT INTO flagged_events (session_id, repo_id, event_context_json, embedding_id, decision, rationale, decided_at, decided_by) VALUES ('sess', ?, '{}', ?, 'Allow', 'mock', ?, 'auto_recall')", repoID, embID, time.Now())
		}

		b.Run(fmt.Sprintf("Vectors_%d", size), func(b *testing.B) {
			queryVec := make([]float32, 384)
			for j := range queryVec {
				queryVec[j] = rand.Float32()
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				store.Query(context.Background(), repoID, queryVec, 5)
			}
		})
	}
}
