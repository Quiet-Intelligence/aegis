package memory

import (
	"database/sql"
	"fmt"
)

// InitSchema initializes the SQLite schema for the memory layer.
func InitSchema(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS repos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			remote_url_hash TEXT NOT NULL UNIQUE,
			first_seen DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			repo_id INTEGER NOT NULL,
			started_at DATETIME NOT NULL,
			ended_at DATETIME,
			FOREIGN KEY(repo_id) REFERENCES repos(id)
		);`,
		`CREATE TABLE IF NOT EXISTS embeddings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vector BLOB NOT NULL,
			dims INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS flagged_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			event_context_json TEXT NOT NULL,
			embedding_id INTEGER NOT NULL,
			decision TEXT CHECK(decision IN ('Allow', 'Deny', 'AskUser')) NOT NULL,
			rationale TEXT NOT NULL,
			decided_at DATETIME NOT NULL,
			decided_by TEXT CHECK(decided_by IN ('llm', 'auto_recall', 'human')) NOT NULL,
			FOREIGN KEY(session_id) REFERENCES sessions(id),
			FOREIGN KEY(repo_id) REFERENCES repos(id),
			FOREIGN KEY(embedding_id) REFERENCES embeddings(id)
		);`,
		`CREATE TABLE IF NOT EXISTS decision_traces (
			session_id TEXT PRIMARY KEY,
			repo_id INTEGER NOT NULL,
			context_events_json TEXT NOT NULL,
			retrieved_cases_json TEXT NOT NULL,
			decision TEXT NOT NULL,
			rationale TEXT NOT NULL,
			FOREIGN KEY(session_id) REFERENCES sessions(id),
			FOREIGN KEY(repo_id) REFERENCES repos(id)
		);`,
		`CREATE TABLE IF NOT EXISTS prm_labels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			trajectory_id TEXT NOT NULL,
			step_index INTEGER NOT NULL,
			event_context_json TEXT NOT NULL,
			prm_score REAL,
			label_source TEXT CHECK(label_source IN ('human', 'redteam_self_label')) NOT NULL,
			labeled_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_prm_labels_traj ON prm_labels(trajectory_id);`,
		`CREATE TABLE IF NOT EXISTS semantic_baseline (
			repo_id INTEGER NOT NULL,
			feature_key TEXT NOT NULL,
			ema_value REAL NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (repo_id, feature_key),
			FOREIGN KEY(repo_id) REFERENCES repos(id)
		);`,
		`CREATE TABLE IF NOT EXISTS policy_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo_id INTEGER NOT NULL,
			match_type TEXT CHECK(match_type IN ('hash', 'path')) NOT NULL,
			match_value TEXT NOT NULL,
			promoted_from_event_id INTEGER NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			FOREIGN KEY(repo_id) REFERENCES repos(id),
			FOREIGN KEY(promoted_from_event_id) REFERENCES flagged_events(id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_flagged_repo ON flagged_events(repo_id);`,
		`CREATE INDEX IF NOT EXISTS idx_policy_expires ON policy_entries(expires_at);`,
		`CREATE TABLE IF NOT EXISTS decision_traces (
			session_id TEXT PRIMARY KEY,
			repo_id INTEGER NOT NULL,
			context_events_json TEXT NOT NULL,
			retrieved_cases_json TEXT NOT NULL,
			decision TEXT NOT NULL,
			rationale TEXT NOT NULL,
			FOREIGN KEY(session_id) REFERENCES sessions(id),
			FOREIGN KEY(repo_id) REFERENCES repos(id)
		);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("failed to execute query: %w\nQuery: %s", err, q)
		}
	}
	return nil
}
