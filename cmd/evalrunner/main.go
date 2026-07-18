package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aegis/evals/golden"
	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	"aegis/internal/memory/episodic"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/telemetry"
	_ "github.com/mattn/go-sqlite3"
)

type EvalMetrics struct {
	Total      int
	Precision  float64
	Recall     float64
	F1         float64
	FPR        float64
	FNR        float64
	AutoRecall AutoRecallMetrics
}

type AutoRecallMetrics struct {
	Total     int
	Precision float64
}

func main() {
	b, err := os.ReadFile("evals/golden/cases.json")
	if err != nil {
		panic(err)
	}

	var cases []golden.GoldenCase
	if err := json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}

	// Setup mock control plane
	db, _ := sql.Open("sqlite3", ":memory:")
	memory.InitSchema(db)
	repoID := int64(999)
	db.Exec("INSERT INTO repos (id, remote_url_hash, first_seen) VALUES (?, 'eval', ?)", repoID, time.Now())

	embedder := &embed.MockEmbedder{}
	store := episodic.NewStore(db, embedder)

	baseLLM := &adjudicator.OpenAIAdjudicator{
		Model: "gpt-4",
	}

	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      baseLLM,
		Store:    store,
		Embedder: embedder,
	}

	scorer := graph.NewScorer(db, repoID, "/workspace")

	tp, tn, fp, fn := 0, 0, 0, 0
	autoTP, autoFP := 0, 0
	autoTotal := 0

	for _, c := range cases {
		// Replay sequence through scorer
		eventChan := make(chan *telemetry.Event, 100)
		ctx, cancel := context.WithCancel(context.Background())

		go scorer.Consume(ctx, eventChan)

		for _, ev := range c.EventSequence {
			eventChan <- ev
		}

		time.Sleep(10 * time.Millisecond) // wait for processing
		
		var flagged graph.FlaggedEvent
		select {
		case flagged = <-scorer.Flagged():
		default:
			// No flag
		}
		
		decision := adjudicator.DecisionAllow
		isAuto := false

		if flagged.SessionID != "" {
			// Adjudicate
			d, rat, _ := adj.Adjudicate(context.Background(), repoID, flagged)
			decision = d
			if rat == "auto_recall" {
				isAuto = true
				autoTotal++
			}
		}
		
		cancel()

		// Truth evaluation
		predictedMalicious := decision == adjudicator.DecisionDeny
		actualMalicious := c.Label == golden.Malicious

		if predictedMalicious && actualMalicious {
			tp++
			if isAuto { autoTP++ }
		} else if !predictedMalicious && !actualMalicious {
			tn++
		} else if predictedMalicious && !actualMalicious {
			fp++
			if isAuto { autoFP++ }
		} else if !predictedMalicious && actualMalicious {
			fn++
		}
	}

	precision := float64(tp) / float64(tp+fp)
	if tp+fp == 0 { precision = 1.0 }
	recall := float64(tp) / float64(tp+fn)
	if tp+fn == 0 { recall = 1.0 }
	f1 := 2 * (precision * recall) / (precision + recall)
	if precision+recall == 0 { f1 = 0 }

	metrics := EvalMetrics{
		Total:     len(cases),
		Precision: precision,
		Recall:    recall,
		F1:        f1,
		FPR:       float64(fp) / float64(fp+tn),
		FNR:       float64(fn) / float64(tp+fn),
		AutoRecall: AutoRecallMetrics{
			Total: autoTotal,
			Precision: float64(autoTP) / float64(autoTP+autoFP),
		},
	}

	fmt.Printf("Eval Results (Golden):\nPrecision: %.2f\nRecall: %.2f\nF1: %.2f\n", precision, recall, f1)
	
	os.MkdirAll("evals/results", 0755)
	out, _ := json.MarshalIndent(metrics, "", "  ")
	os.WriteFile(filepath.Join("evals/results", fmt.Sprintf("eval_%d.json", time.Now().Unix())), out, 0644)
}
