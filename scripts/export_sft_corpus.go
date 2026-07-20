package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type InstructionResponse struct {
	Instruction string `json:"instruction"`
	Response    string `json:"response"`
}

func main() {
	db, err := sql.Open("sqlite3", "aegis.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Fetch confirmed correct decisions from episodic memory.
	// In Aegis, 'human' decided_by implies it was reviewed and finalized.
	// For SFT, we only want high-quality ground-truth labels.
	rows, err := db.Query(`
		SELECT event_context_json, decision, rationale 
		FROM flagged_events 
		WHERE decided_by = 'human'
	`)
	if err != nil {
		fmt.Printf("[-] Database error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	outFile, err := os.Create("sft_corpus.jsonl")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	count := 0
	for rows.Next() {
		var eventJSON, decision, rationale string
		if err := rows.Scan(&eventJSON, &decision, &rationale); err != nil {
			continue
		}

		// Format as an instruction/response pair suitable for LoRA fine-tuning.
		ir := InstructionResponse{
			Instruction: fmt.Sprintf("Adjudicate the following system event trace:\n%s", eventJSON),
			Response:    fmt.Sprintf("Decision: %s\nRationale: %s", decision, rationale),
		}

		b, _ := json.Marshal(ir)
		outFile.WriteString(string(b) + "\n")
		count++
	}

	fmt.Printf("[+] Exported %d human-confirmed tuples for SFT to sft_corpus.jsonl\n", count)
}
