package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"aegis/pkg/adjudicator"
	"aegis/pkg/graph"
	"aegis/pkg/policy"
	"aegis/pkg/telemetry"
	"github.com/cilium/ebpf"
)

func main() {
	fmt.Println("Starting Aegis Control Plane (aegisd)...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Initialize Channels
	eventChan := make(chan telemetry.Event, 1000)

	// 2. Load eBPF Programs & Start Readers
	targetCgroupId := uint64(12345) // Mock
	ebpfLayer, err := telemetry.InitLayer(ctx, targetCgroupId, eventChan)
	if err != nil {
		fmt.Printf("Warning: eBPF initialization incomplete (expected on Windows): %v\n", err)
	}
	defer ebpfLayer.Close()

	// 3. Start Graph Scorer
	workspaceDir := "/workspace"
	scorer := graph.NewScorer(workspaceDir)
	go scorer.Consume(ctx, eventChan)

	// 4. Initialize Adjudicator & Policy Enforcer
	adj := &adjudicator.OpenAIAdjudicator{
		APIKey: os.Getenv("OPENAI_API_KEY"),
		URL:    "https://api.openai.com/v1/chat/completions",
		Model:  "gpt-4",
	}

	var firstColl *ebpf.Collection
	if len(ebpfLayer.Collections) > 0 {
		firstColl = ebpfLayer.Collections[0]
	}

	enforcer, err := policy.NewEnforcer("audit.jsonl", firstColl)
	if err != nil {
		fmt.Printf("Failed to create enforcer: %v\n", err)
		return
	}

	// 5. Adjudication Loop
	go func() {
		for flagged := range scorer.Flagged() {
			fmt.Printf("[FLAGGED] Session: %s, Rule: %s\n", flagged.SessionID, flagged.Rule)
			
			decision, rationale, err := adj.Adjudicate(ctx, flagged)
			if err != nil {
				fmt.Printf("Adjudication Error: %v\n", err)
				continue
			}

			fmt.Printf("  -> [DECISION] %s (Rationale: %s)\n", decision, rationale)
			enforcer.Enforce(flagged.SessionID, flagged.Event, decision, rationale)
		}
	}()

	// 6. Graceful Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Shutting down aegisd...")
}
