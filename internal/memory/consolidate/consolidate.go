package consolidate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// SessionEnd is called when a session finishes to consolidate memory (Prompt 5).
func SessionEnd(ctx context.Context, db *sql.DB, repoID int64, sessionID string, alpha float32) {
	go func() {
		// H-13: Run as goroutine, never blocking live path
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()

		var count int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM flagged_events WHERE session_id = ?`, sessionID).Scan(&count)
		if err == nil && count > 0 {
			featureKey := "flagged_event_count"
			var currentEma float64
			err := tx.QueryRowContext(ctx, `SELECT ema_value FROM semantic_baseline WHERE repo_id = ? AND feature_key = ?`, repoID, featureKey).Scan(&currentEma)
			if err == sql.ErrNoRows {
				currentEma = float64(count)
			} else {
				currentEma = float64(alpha)*float64(count) + (1-float64(alpha))*currentEma
			}

			tx.ExecContext(ctx, `
				INSERT INTO semantic_baseline (repo_id, feature_key, ema_value, updated_at) 
				VALUES (?, ?, ?, ?) 
				ON CONFLICT(repo_id, feature_key) 
				DO UPDATE SET ema_value = excluded.ema_value, updated_at = excluded.updated_at
			`, repoID, featureKey, currentEma, time.Now())
		}

		// Check Promotion eligibility (deny signature in >= 2 distinct sessions)
		rows, err := tx.QueryContext(ctx, `
			SELECT rationale, COUNT(DISTINCT session_id) as session_count, MAX(id)
			FROM flagged_events 
			WHERE repo_id = ? AND decision = 'Deny'
			GROUP BY rationale 
			HAVING session_count >= 2
		`, repoID)

		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var rationale string
				var sc int
				var eventID int64
				rows.Scan(&rationale, &sc, &eventID)

				// The blocked value must be the event's resource (a file
				// path), NOT the human-readable rationale text. The old
				// code inserted the rationale as a 'path', which could
				// never match a real file and produced dead policy rows.
				var evJSON string
				err := tx.QueryRowContext(ctx, `SELECT event_context_json FROM flagged_events WHERE id = ?`, eventID).Scan(&evJSON)
				if err != nil {
					continue
				}
				var flagged struct {
					Resource string `json:"Resource"`
				}
				if err := json.Unmarshal([]byte(evJSON), &flagged); err != nil {
					continue
				}
				path := flagged.Resource
				// Only promote clean absolute paths (file_open denies).
				// Exec resources carry argv ("... -rf /") and net
				// resources carry ip:port; neither is a blockable path.
				if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t") {
					continue
				}

				tx.ExecContext(ctx, `
					INSERT INTO policy_entries (repo_id, match_type, match_value, promoted_from_event_id, created_at, expires_at)
					SELECT ?, 'path', ?, ?, ?, ?
					WHERE NOT EXISTS (
						SELECT 1 FROM policy_entries WHERE repo_id = ? AND match_value = ? AND revoked_at IS NULL
					)
				`, repoID, path, eventID, time.Now(), time.Now().AddDate(0, 0, 30), repoID, path)
			}
		}

		tx.Commit()
	}()
}
