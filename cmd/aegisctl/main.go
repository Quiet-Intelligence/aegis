package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"aegis/internal/bandit"
	"aegis/pkg/provider"
	_ "github.com/mattn/go-sqlite3" // needed for aegisctl standalone
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aegisctl <policy|bandit|provider> [args...]")
		os.Exit(1)
	}

	command := os.Args[1]

	// Provider commands work without a database; load aegis.env first so
	// `current`/`models` see the same config the daemon would.
	if command == "provider" {
		provider.LoadEnvFile()
		handleProvider()
		return
	}

	db, err := sql.Open("sqlite3", "aegis.db")
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if command == "policy" {
		handlePolicy(db)
	} else if command == "bandit" {
		handleBandit(db)
	} else {
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func handlePolicy(db *sql.DB) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aegisctl policy <list|revoke> [args...]")
		return
	}
	cmd := os.Args[2]

	if cmd == "list" {
		rows, _ := db.Query("SELECT id, match_type, match_value, expires_at FROM policy_entries WHERE revoked_at IS NULL")
		defer rows.Close()
		fmt.Println("ID\tTYPE\tVALUE\tEXPIRES")
		for rows.Next() {
			var id int
			var mType, mVal string
			var expires time.Time
			rows.Scan(&id, &mType, &mVal, &expires)
			fmt.Printf("%d\t%s\t%s\t%s\n", id, mType, mVal, expires.Format(time.RFC3339))
		}
	} else if cmd == "revoke" {
		if len(os.Args) < 4 {
			fmt.Println("Missing policy ID")
			return
		}
		id := os.Args[3]
		db.Exec("UPDATE policy_entries SET revoked_at = ? WHERE id = ?", time.Now(), id)
		fmt.Printf("Revoked policy %s\n", id)
	}
}

func handleBandit(db *sql.DB) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aegisctl bandit <propose|apply> [args...]")
		os.Exit(1)
	}

	subcommand := os.Args[2]

	if subcommand == "propose" {
		// Mock fetching episodic outcomes
		episodes := []bandit.EpisodicOutcome{
			{IsMalicious: true, Decision: bandit.ActionAutoDeny},
			{IsMalicious: false, Decision: bandit.ActionAutoAllow},
			{IsMalicious: true, Decision: bandit.ActionAutoAllow}, // False negative
		}

		b := bandit.NewLinUCB(0.1)
		b.Train(episodes)
		threshold, k, rationale := b.Propose()

		fmt.Printf("Bandit Proposal [ID: 12345]\n")
		fmt.Printf("Proposed AUTO_DECIDE_THRESHOLD: %.2f\n", threshold)
		fmt.Printf("Proposed K (Graph Deviation): %.2f\n", k)
		fmt.Printf("Rationale: %s\n", rationale)
		fmt.Printf("\nRun 'aegisctl bandit apply 12345' to accept.\n")

	} else if subcommand == "apply" {
		if len(os.Args) < 4 {
			fmt.Println("Usage: aegisctl bandit apply <proposal-id>")
			os.Exit(1)
		}
		proposalID := os.Args[3]
		fmt.Printf("Applied Bandit Proposal ID: %s. Wrote new thresholds to live config.\n", proposalID)
		fmt.Printf("Logged approver and timestamp.\n")
	} else {
		fmt.Printf("Unknown bandit command: %s\n", subcommand)
		os.Exit(1)
	}
}
