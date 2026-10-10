package episodic

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	_ "github.com/mattn/go-sqlite3"
)

// Brute-force recall scans every stored embedding of the repository. Measured on an i7-14650HX (384-d float32 BLOBs,
// in-memory SQLite): about 24 us at 10 vectors, 1.8 ms at 1,000, 11 ms at 5,000 and 47 ms at 20,000 per query, i.e. linear,
// ~2.3 us per stored vector. Move to an ANN index (sqlite-vec / HNSW) before a repository accumulates tens of thousands of cases.

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

	sizes := []int{10, 100, 1000, 5000, 20000}
	for _, size := range sizes {
		// Populate mock vectors
		for i := 0; i < size; i++ {
			vec := make([]float32, 384)
			for j := range vec {
				vec[j] = rand.Float32()
			}
			vecBytes := encodeVector(vec)
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
