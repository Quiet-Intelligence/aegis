package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegis/internal/memory"
	"aegis/internal/memory/consolidate"
	"aegis/internal/memory/embed"
	"aegis/internal/memory/episodic"
	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/policy"
	"aegis/pkg/telemetry"
	"github.com/cilium/ebpf"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	fmt.Println("Starting Aegis Control Plane (aegisd)...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 0. Initialize SQLite DB
	db, err := sql.Open("sqlite3", "aegis.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if err := memory.InitSchema(db); err != nil {
		panic(err)
	}

	repoID := int64(1) // Mock

	// 1. Initialize Channels (Prompt 3 - separate queues, fail-open/closed)
	chConfig := telemetry.ChannelConfig{
		CriticalChan:    make(chan *telemetry.Event, 1000), // file_open, exec
		TelemetryChan:   make(chan *telemetry.Event, 1000), // net
		CriticalTimeout: 10 * time.Millisecond,
	}

	// 2. Load eBPF Programs & Start Readers
	targetCgroupId := uint64(12345) // Mock
	ebpfLayer, err := telemetry.InitLayer(ctx, targetCgroupId, chConfig)
	if err != nil {
		fmt.Printf("Warning: eBPF initialization incomplete: %v\n", err)
	}
	defer ebpfLayer.Close()

	// 3. Start Graph Scorer
	workspaceDir := "/workspace"
	scorer := graph.NewScorer(db, repoID, workspaceDir)
	
	// Start consuming both channels
	go scorer.Consume(ctx, chConfig.CriticalChan)
	go scorer.Consume(ctx, chConfig.TelemetryChan)

	// 4. Initialize Embedder and Store
	embedder := &embed.MockEmbedder{}
	store := episodic.NewStore(db, embedder)

	// 5. Initialize Adjudicator (Retrieval Augmented)
	baseLLM := &adjudicator.OpenAIAdjudicator{
		APIKey: os.Getenv("OPENAI_API_KEY"),
		URL:    "https://api.openai.com/v1/chat/completions",
		Model:  "gpt-4",
	}
	
	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      baseLLM,
		Store:    store,
		Embedder: embedder,
	}

	var firstColl *ebpf.Collection
	if len(ebpfLayer.Collections) > 0 {
		firstColl = ebpfLayer.Collections[0]
	}

	// 6. Initialize Policy Enforcer
	enforcer, err := policy.NewEnforcer("audit.jsonl", firstColl, db, repoID)
	if err != nil {
		fmt.Printf("Failed to create enforcer: %v\n", err)
		return
	}

	// 7. Adjudication Loop
	go func() {
		for flagged := range scorer.Flagged() {
			fmt.Printf("[FLAGGED] Session: %s, Rule: %s\n", flagged.SessionID, flagged.Rule)
			
			decision, rationale, err := adj.Adjudicate(ctx, repoID, flagged)
			if err != nil {
				fmt.Printf("Adjudication Error: %v\n", err)
				continue
			}

			fmt.Printf("  -> [DECISION] %s (Rationale: %s)\n", decision, rationale)
			enforcer.Enforce(flagged.SessionID, flagged.Event, decision, rationale)
		}
	}()

	// 8. Graceful Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Shutting down aegisd... Running consolidation job")
	consolidate.SessionEnd(context.Background(), db, repoID, "demo-session-id", 0.2)
}
