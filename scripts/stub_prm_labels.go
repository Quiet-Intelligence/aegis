//go:build ignore

package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// STUB: Since feature/trajectory-evals (Step 8) is not yet merged, we mock the 
// adversarial generator's redteam self-labels to unblock PRM training (RL2-3).
func main() {
	db, err := sql.Open("sqlite3", "aegis.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Ensure table exists (in case it wasn't initialized)
	db.Exec(`CREATE TABLE IF NOT EXISTS prm_labels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		trajectory_id TEXT NOT NULL,
		step_index INTEGER NOT NULL,
		event_context_json TEXT NOT NULL,
		prm_score REAL,
		label_source TEXT CHECK(label_source IN ('human', 'redteam_self_label')) NOT NULL,
		labeled_at DATETIME NOT NULL
	)`)

	trajectoryID := uuid.New().String()
	fmt.Printf("[*] Generating mock redteam self-labels for Trajectory ID: %s\n", trajectoryID)

	// Step 1: Benign setup (Meaningful? False, Score: 0.0)
	db.Exec(`INSERT INTO prm_labels (trajectory_id, step_index, event_context_json, prm_score, label_source, labeled_at)
		VALUES (?, 1, '{"Action": "touch benign.txt"}', 0.0, 'redteam_self_label', ?)`, trajectoryID, time.Now())

	// Step 2: Worktree creation (Meaningful? True, Score: 1.0)
	db.Exec(`INSERT INTO prm_labels (trajectory_id, step_index, event_context_json, prm_score, label_source, labeled_at)
		VALUES (?, 2, '{"Action": "git worktree add fake"}', 1.0, 'redteam_self_label', ?)`, trajectoryID, time.Now())

	fmt.Println("[+] Mock labels inserted successfully. Ready for PRM training.")
}
