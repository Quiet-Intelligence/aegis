package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"strconv"
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

func envUint64(key string, fallback uint64) uint64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		fmt.Printf("WARNING: invalid %s=%q, using default %d\n", key, v, fallback)
		return fallback
	}
	return n
}

func main() {
	fmt.Println("Starting Aegis Control Plane (aegisd)...")

	// Load config from env file before anything reads AEGIS_* vars.
	// Required for root operation: sudo strips user env exports.
	loadEnvFile()

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
	// AEGIS_CGROUP_ID scopes monitoring to one container's cgroup v2 inode
	// (see scripts/cgroup_id.sh). 0 = wildcard: monitor the whole host.
	targetCgroupId := envUint64("AEGIS_CGROUP_ID", 0)
	auditOnly := os.Getenv("AEGIS_AUDIT_ONLY") == "1"

	if targetCgroupId == 0 {
		fmt.Println("WARNING: AEGIS_CGROUP_ID not set — monitoring ALL processes on this host.")
		if !auditOnly {
			// Safety interlock: a fail-closed adjudicator plus host-wide
			// visibility would start -EPERM-ing unrelated system processes.
			fmt.Println("Safety interlock: forcing AEGIS_AUDIT_ONLY=1 (no kernel blocking) while unscoped.")
			auditOnly = true
		}
	} else {
		fmt.Printf("Monitoring scoped to cgroup ID: %d\n", targetCgroupId)
	}
	if auditOnly {
		fmt.Println("Mode: AUDIT-ONLY (decisions logged, nothing blocked in kernel)")
	}

	ebpfLayer, err := telemetry.InitLayer(ctx, targetCgroupId, chConfig, os.Getenv("AEGIS_EBPF_DIR"))
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
	defer ebpfLayer.Close()

	// 3. Start Graph Scorer
	workspaceDir := "/workspace"
	scorer := graph.NewScorer(db, repoID, workspaceDir)
	if cd := os.Getenv("AEGIS_FLAG_COOLDOWN"); cd != "" {
		if n, err := strconv.Atoi(cd); err == nil && n >= 0 {
			scorer.FlagCooldown = time.Duration(n) * time.Second
		}
	}
	fmt.Printf("Flag cooldown: %s (AEGIS_FLAG_COOLDOWN to override, seconds)\n", scorer.FlagCooldown)
	if os.Getenv("AEGIS_FLAG_NET") == "1" {
		scorer.FlagNet = true
		fmt.Println("Net flagging: ON — outbound connections will be adjudicated")
	}

	// Start consuming both channels
	go scorer.Consume(ctx, chConfig.CriticalChan)
	go scorer.Consume(ctx, chConfig.TelemetryChan)

	// 4. Initialize Embedder and Store
	embedder := &embed.HeuristicEmbedder{}
	store := episodic.NewStore(db, embedder)

	// 5. Initialize Adjudicator (Retrieval Augmented)
	// Endpoint/key/model are env-driven; defaults target OpenRouter.
	llmURL := os.Getenv("AEGIS_LLM_URL")
	if llmURL == "" {
		llmURL = "https://openrouter.ai/api/v1/chat/completions"
	}
	llmKey := os.Getenv("AEGIS_LLM_KEY")
	if llmKey == "" {
		llmKey = os.Getenv("OPENAI_API_KEY") // legacy fallback
	}
	llmModel := os.Getenv("AEGIS_LLM_MODEL")
	if llmModel == "" {
		llmModel = os.Getenv("AEGIS_FLAGSHIP_MODEL")
	}
	if llmModel == "" {
		llmModel = "deepseek/deepseek-chat"
	}

	// Hard spend cap: max LLM adjudications per minute, across ALL sessions.
	// Memory auto-recall happens upstream of this and stays free.
	maxRPM := 20
	if v := os.Getenv("AEGIS_MAX_LLM_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxRPM = n
		}
	}

	fmt.Printf("Adjudicator endpoint: %s (model: %s)\n", llmURL, llmModel)
	fmt.Printf("LLM adjudication budget: %d calls/min (AEGIS_MAX_LLM_RPM to override, 0=unlimited)\n", maxRPM)
	if llmKey == "" {
		fmt.Println("WARNING: AEGIS_LLM_KEY is not set — every flagged event will fail closed (Deny), zero API calls made.")
	}

	baseLLM := &adjudicator.OpenAIAdjudicator{
		APIKey: llmKey,
		URL:    llmURL,
		Model:  llmModel,
	}
	rateLimitedLLM := &adjudicator.RateLimitedAdjudicator{Inner: baseLLM, Limit: maxRPM}

	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      rateLimitedLLM,
		Store:    store,
		Embedder: embedder,
	}

	var firstColl *ebpf.Collection
	if len(ebpfLayer.Collections) > 0 {
		firstColl = ebpfLayer.Collections[0]
	}

	// 6. Initialize Policy Enforcer
	enforcer, err := policy.NewEnforcer("audit.jsonl", firstColl, db, repoID, auditOnly)
	if err != nil {
		fmt.Printf("Failed to create enforcer: %v\n", err)
		return
	}

	// 7. Adjudication Loop
	go func() {
		for flagged := range scorer.Flagged() {
			evType := "?"
			if flagged.Event != nil {
				evType = flagged.Event.Type
			}
			fmt.Printf("[FLAGGED] %s %s\n           session=%s rule=%s\n", evType, flagged.Resource, flagged.SessionID, flagged.Rule)
			if os.Getenv("AEGIS_DEBUG") == "1" {
				fmt.Printf("[DEBUG] LLM prompt:\n%s\n", adjudicator.BuildPrompt(flagged))
			}

			decision, rationale, err := adj.Adjudicate(ctx, repoID, flagged)
			if err != nil {
				// Fail closed: never skip enforcement because the LLM is
				// unreachable, misconfigured, or returned garbage.
				fmt.Printf("Adjudication error (failing closed): %v\n", err)
				if decision == "" {
					decision = adjudicator.DecisionDeny
					rationale = "adjudication unavailable; default deny"
				}
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
