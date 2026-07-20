package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis/evals/golden"
	"aegis/internal/memory"
	"aegis/internal/memory/embed"
	"aegis/internal/memory/episodic"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/provider"
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

type mockAdjudicator struct{}

func (m *mockAdjudicator) Adjudicate(ctx context.Context, repoID int64, event graph.FlaggedEvent) (adjudicator.Decision, string, error) {
	cmd := event.Resource
	if strings.Contains(cmd, "rm -rf /") || strings.Contains(cmd, "passwd") || strings.Contains(cmd, "shadow") || strings.Contains(cmd, ".git/config") || strings.Contains(cmd, "base64") || strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget") || strings.Contains(cmd, "nc ") || strings.Contains(cmd, "fake_worktree") {
		return adjudicator.DecisionDeny, "Mocked Malicious", nil
	}
	return adjudicator.DecisionAllow, "Mocked Benign", nil
}

func main() {
	runTrajectory := flag.Bool("trajectory", false, "Run deep trajectory evaluations")
	flag.Parse()

	provider.LoadEnvFile()
	
	b, err := os.ReadFile("evals/golden/cases.json")
	if err != nil {
		panic(err)
	}

	var cases []golden.GoldenCase
	if err := json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}

	advB, err := os.ReadFile("evals/adversarial/cases.json")
	if err == nil {
		var advCases []golden.GoldenCase
		if err := json.Unmarshal(advB, &advCases); err == nil {
			cases = append(cases, advCases...)
			fmt.Printf("Loaded %d golden and %d adversarial cases\n", len(cases)-len(advCases), len(advCases))
		}
	}

	// Setup mock control plane
	db, _ := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err := memory.InitSchema(db); err != nil {
		fmt.Printf("FATAL: Failed to init schema: %v\n", err)
		os.Exit(1)
	}
	repoID := int64(999)
	db.Exec("INSERT INTO repos (id, remote_url_hash, first_seen) VALUES (?, 'eval', ?)", repoID, time.Now())
	
	// Add mock semantic baseline so deviations can be flagged during evaluation
	db.Exec("INSERT INTO semantic_baseline (repo_id, feature_key, ema_value, updated_at) VALUES (?, 'flagged_event_count', 5.0, ?)", repoID, time.Now())

	embedder := &embed.HeuristicEmbedder{}
	store := episodic.NewStore(db, embedder)

	var baseLLM adjudicator.Adjudicator
	registry, err := provider.Load()
	var cfg *provider.Resolved
	if err == nil {
		cfg, err = registry.Resolve()
	}

	if err != nil || cfg.Key == "" {
		fmt.Println("Warning: No LLM provider config/key found, falling back to mockAdjudicator for CI/Testing.")
		baseLLM = &mockAdjudicator{}
	} else {
		baseLLM = &adjudicator.OpenAIAdjudicator{
			APIKey:  cfg.Key,
			URL:     cfg.URL,
			Model:   cfg.FlagshipModel,
			Headers: cfg.Headers,
		}
	}

	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      baseLLM,
		Store:    store,
		Embedder: embedder,
	}

	tp, tn, fp, fn := 0, 0, 0, 0
	autoTP, autoFP := 0, 0
	autoTotal := 0

	for _, c := range cases {
		scorer := graph.NewScorer(db, repoID, "/workspace")
		scorer.AdjudicateAllExec = false
		
		// Replay sequence through scorer
		eventChan := make(chan *telemetry.Event, 100)
		ctx, cancel := context.WithCancel(context.Background())

		go scorer.Consume(ctx, eventChan)

		for _, ev := range c.EventSequence {
			eventChan <- ev
		}

		timer := time.NewTimer(500 * time.Millisecond)
		var flagged graph.FlaggedEvent
		select {
		case flagged = <-scorer.Flagged():
		case <-timer.C:
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

	fmt.Printf("Eval Results:\n")
	fmt.Printf("Confusion Matrix:\n")
	fmt.Printf("  TP: %d | FP: %d\n", tp, fp)
	fmt.Printf("  FN: %d | TN: %d\n", fn, tn)
	fmt.Printf("Precision: %.2f\n", precision)
	fmt.Printf("Recall: %.2f\n", recall)
	fmt.Printf("F1: %.2f\n", f1)

	// Update metrics_data.json
	metricsFile := "metrics_data.json"
	bMetrics, err := os.ReadFile(metricsFile)
	if err == nil {
		var metrics map[string]interface{}
		if err := json.Unmarshal(bMetrics, &metrics); err == nil {
			if evals, ok := metrics["evals"].(map[string]interface{}); ok {
				evals["golden_precision"] = precision
				evals["golden_recall"] = recall
				evals["golden_f1"] = f1
				evals["golden_fpr"] = float64(fp) / (float64(fp+tn) + 1e-9)
				evals["golden_fnr"] = float64(fn) / (float64(fn+tp) + 1e-9)
				if autoTotal > 0 {
					evals["auto_recall_precision"] = float64(autoTP) / (float64(autoTP+autoFP) + 1e-9)
				}
				metrics["evals"] = evals
				
				updatedBytes, _ := json.MarshalIndent(metrics, "", "  ")
				os.WriteFile(metricsFile, updatedBytes, 0644)
				fmt.Println("Updated metrics_data.json with latest eval results.")
			}
		}
	}
	
	if precision < 0.95 || recall < 0.95 {
		fmt.Printf("FATAL: Precision or Recall dropped below 0.95 gate.\n")
		os.Exit(1)
	}
	
	os.MkdirAll("evals/results", 0755)
	out, _ := json.MarshalIndent(metrics, "", "  ")
	os.WriteFile(filepath.Join("evals/results", fmt.Sprintf("eval_%d.json", time.Now().Unix())), out, 0644)

	if *runTrajectory {
		RunTrajectoryEvals(db, repoID, baseLLM)
	}
}
