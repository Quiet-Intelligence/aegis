package episodic

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"time"

	"aegis/internal/memory/embed"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
)

type PastCase struct {
	ID        int64
	Decision  adjudicator.Decision
	Rationale string
	DecidedBy string
}

// QueryExactExec recalls an exec decision only when the complete command
// resource and rule match exactly. Approximate vector recall is unsafe for
// commands: /usr/bin/ls and /usr/bin/rm normalize to the same directory
// shape, so an allowed ls must never auto-allow rm -rf /.
func (s *Store) QueryExactExec(ctx context.Context, repoID int64, event graph.FlaggedEvent) (*PastCase, error) {
	if event.BinaryHash == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, decision, rationale, decided_by, event_context_json
		FROM flagged_events
		WHERE repo_id = ? AND decided_by IN ('llm', 'human')
		ORDER BY id DESC`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var dec, rat, by, eventJSON string
		if err := rows.Scan(&id, &dec, &rat, &by, &eventJSON); err != nil {
			continue
		}
		// Decode only the fields used for exact matching. telemetry events
		// have custom JSON rendering (Path/Args as strings), so decoding the
		// whole value back into graph.FlaggedEvent would fail on its fixed
		// byte arrays.
		var prior struct {
			Resource   string `json:"Resource"`
			Rule       string `json:"Rule"`
			BinaryHash string `json:"BinaryHash"`
			Event      *struct {
				Type string `json:"Type"`
			} `json:"Event"`
		}
		if err := json.Unmarshal([]byte(eventJSON), &prior); err != nil {
			continue
		}
		if prior.Event != nil && prior.Event.Type == "exec" && prior.Resource == event.Resource && prior.Rule == event.Rule && prior.BinaryHash == event.BinaryHash {
			return &PastCase{ID: id, Decision: adjudicator.Decision(dec), Rationale: rat, DecidedBy: by}, nil
		}
	}
	return nil, nil
}

type Store struct {
	db       *sql.DB
	embedder embed.Embedder
}

func NewStore(db *sql.DB, embedder embed.Embedder) *Store {
	return &Store{db: db, embedder: embedder}
}

func (s *Store) RecordCase(ctx context.Context, repoID int64, sessionID string, event graph.FlaggedEvent, decision adjudicator.Decision, rationale string, decidedBy string) error {
	fv := embed.BuildFeatureVector(event)
	vector, err := s.embedder.Embed(ctx, fv)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	vecBytes, _ := json.Marshal(vector)

	res, err := tx.Exec(`INSERT INTO embeddings (vector, dims) VALUES (?, ?)`, vecBytes, len(vector))
	if err != nil {
		return err
	}
	embID, _ := res.LastInsertId()

	evJSON, _ := json.Marshal(event)

	_, err = tx.Exec(`INSERT INTO flagged_events 
		(session_id, repo_id, event_context_json, embedding_id, decision, rationale, decided_at, decided_by) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, repoID, string(evJSON), embID, string(decision), rationale, time.Now(), decidedBy)

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) Query(ctx context.Context, repoID int64, queryVector []float32, topK int) ([]PastCase, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT fe.id, fe.decision, fe.rationale, fe.decided_by, e.vector 
		FROM flagged_events fe 
		JOIN embeddings e ON fe.embedding_id = e.id 
		WHERE fe.repo_id = ?`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []PastCase

	for rows.Next() {
		var id int64
		var dec, rat, by string
		var vecBytes []byte
		if err := rows.Scan(&id, &dec, &rat, &by, &vecBytes); err != nil {
			continue
		}

		var vec []float32
		if err := json.Unmarshal(vecBytes, &vec); err != nil {
			continue
		}

		sim := cosineSimilarity(queryVector, vec)
		if sim > 0.95 {
			cases = append(cases, PastCase{
				ID:        id,
				Decision:  adjudicator.Decision(dec),
				Rationale: rat,
				DecidedBy: by,
			})
		}
	}

	if len(cases) > topK {
		cases = cases[:topK]
	}

	return cases, nil
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float32
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}
