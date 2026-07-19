package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aegis/internal/memory"
	"aegis/internal/memory/consolidate"
	"aegis/internal/memory/embed"
	"aegis/internal/memory/episodic"
	"aegis/internal/proxy"
	"aegis/pkg/adjudicator"
	"aegis/pkg/control"
	"aegis/pkg/graph"
	"aegis/pkg/policy"
	"aegis/pkg/provider"
	"aegis/pkg/telemetry"
	"github.com/cilium/ebpf"
	_ "github.com/mattn/go-sqlite3"
)

// containerCgroupID resolves a running Docker container's cgroup v2 ID
// (the kernfs inode bpf_get_current_cgroup_id reports) without shelling
// out to scripts. Works across systemd and cgroupfs docker drivers.
func containerCgroupID(name string) (uint64, error) {
	out, err := exec.Command("docker", "inspect", "-f", "{{.Id}}", name).Output()
	if err != nil {
		return 0, fmt.Errorf("docker inspect %s: %w", name, err)
	}
	cid := strings.TrimSpace(string(out))

	candidates := []string{
		fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", cid),
		fmt.Sprintf("/sys/fs/cgroup/docker/%s", cid),
		fmt.Sprintf("/sys/fs/cgroup/system.slice/containerd-%s.scope", cid),
	}
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return st.Ino, nil
		}
	}
	return 0, fmt.Errorf("cgroup directory not found for container %s", name)
}

type targetPlan struct {
	initialID   uint64
	container   string
	watchDocker bool
	hostWide    bool
}

// resolveTargetPlan distinguishes an EXPLICIT cgroup 0 (host-wide) from an
// unset cgroup (wait silently for the Docker target). Previously both became
// 0, which made starting aegisd before run.sh capture the whole host.
func resolveTargetPlan() (targetPlan, error) {
	if raw, explicit := os.LookupEnv("AEGIS_CGROUP_ID"); explicit && strings.TrimSpace(raw) != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return targetPlan{}, fmt.Errorf("invalid AEGIS_CGROUP_ID=%q: %w", raw, err)
		}
		return targetPlan{initialID: id, hostWide: id == 0}, nil
	}

	name := os.Getenv("AEGIS_CONTAINER_NAME")
	if name == "" {
		name = "aegis-agent-runtime"
	}
	id, err := containerCgroupID(name)
	if err == nil {
		return targetPlan{initialID: id, container: name, watchDocker: true}, nil
	}
	return targetPlan{initialID: telemetry.DisabledCgroupID, container: name, watchDocker: true}, nil
}

func waitForContainer(ctx context.Context, name string, layer *telemetry.EbpfLayer) (uint64, error) {
	fmt.Printf("Target container %q is not running. eBPF capture is DISABLED; waiting...\n", name)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if id, err := containerCgroupID(name); err == nil {
			if err := layer.SetTargetCgroup(id); err != nil {
				return 0, err
			}
			fmt.Printf("Container %q appeared; monitoring cgroup ID: %d\n", name, id)
			return id, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

// watchContainer follows stop/recreate cycles. Capture is disabled as soon
// as the named container disappears, so stale cgroup IDs can never cause host
// telemetry leakage.
func watchContainer(ctx context.Context, name string, layer *telemetry.EbpfLayer, current uint64) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	active := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			id, err := containerCgroupID(name)
			if err != nil {
				if active {
					if err := layer.SetTargetCgroup(telemetry.DisabledCgroupID); err == nil {
						fmt.Printf("Container %q stopped; eBPF capture disabled, waiting for restart.\n", name)
					}
					active = false
				}
				continue
			}
			if !active || id != current {
				if err := layer.SetTargetCgroup(id); err == nil {
					fmt.Printf("Container %q active; retargeted eBPF to cgroup ID: %d\n", name, id)
					current = id
					active = true
				}
			}
		}
	}
}

func main() {
	fmt.Println("Starting Aegis Control Plane (aegisd)...")

	// Fill in missing config from aegis.env/.env before anything reads
	// AEGIS_* vars. Required under sudo, which strips user exports.
	provider.LoadEnvFile()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
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

	// 1. Initialize Channels (separate queues, fail-open/closed)
	chConfig := telemetry.ChannelConfig{
		CriticalChan:    make(chan *telemetry.Event, 1000), // file_open, exec
		TelemetryChan:   make(chan *telemetry.Event, 1000), // net
		CriticalTimeout: 10 * time.Millisecond,
	}

	// 2. Load eBPF Programs & Start Readers
	plan, err := resolveTargetPlan()
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		return
	}
	targetCgroupId := plan.initialID
	auditOnly := os.Getenv("AEGIS_AUDIT_ONLY") == "1"
	execGateEnabled := os.Getenv("AEGIS_EXEC_GATE") != "0"

	if plan.hostWide {
		fmt.Println("WARNING: AEGIS_CGROUP_ID=0 explicitly requests host-wide monitoring.")
		if !auditOnly {
			// Safety interlock: host-wide visibility plus a deny decision
			// would start -EPERM-ing unrelated system processes.
			fmt.Println("Safety interlock: forcing AEGIS_AUDIT_ONLY=1 (no kernel blocking) while unscoped.")
			auditOnly = true
		}
	} else if targetCgroupId != telemetry.DisabledCgroupID {
		fmt.Printf("Monitoring scoped to cgroup ID: %d\n", targetCgroupId)
	} else {
		fmt.Printf("Initial scope: disabled sentinel (no host events can match).\n")
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
	if err := ebpfLayer.SetExecGateEnabled(execGateEnabled); err != nil {
		if execGateEnabled {
			fmt.Printf("FATAL: cannot enable BPF exec backstop: %v\n", err)
			return
		}
		fmt.Printf("WARNING: could not disable BPF exec backstop: %v\n", err)
	}

	if plan.watchDocker {
		if targetCgroupId == telemetry.DisabledCgroupID {
			targetCgroupId, err = waitForContainer(ctx, plan.container, ebpfLayer)
			if err != nil {
				fmt.Printf("Stopped while waiting for target container: %v\n", err)
				return
			}
		} else {
			fmt.Printf("Auto-detected container %q cgroup ID: %d\n", plan.container, targetCgroupId)
		}
		go watchContainer(ctx, plan.container, ebpfLayer, targetCgroupId)
	}

	// 3. Start Graph Scorer
	workspaceDir := "/workspace"
	scorer := graph.NewScorer(db, repoID, workspaceDir)
	if cd := os.Getenv("AEGIS_FLAG_COOLDOWN"); cd != "" {
		if n, err := strconv.Atoi(cd); err == nil && n >= 0 {
			scorer.FlagCooldown = time.Duration(n) * time.Second
		}
	}
	if os.Getenv("AEGIS_FLAG_NET") == "1" {
		scorer.FlagNet = true
		fmt.Println("Net flagging: ON — outbound connections will be adjudicated")
	}
	if execGateEnabled {
		// The seccomp gate adjudicates exec synchronously. eBPF still
		// records exec telemetry, but must not create a second async
		// decision for the same command.
		scorer.AdjudicateAllExec = false
		fmt.Println("Command enforcement: synchronous seccomp gate (pre-exec hold)")
	} else if os.Getenv("AEGIS_ADJUDICATE_ALL_EXEC") == "0" {
		scorer.AdjudicateAllExec = false
		fmt.Println("Command adjudication: high-risk binaries only (AEGIS_ADJUDICATE_ALL_EXEC=0)")
	} else {
		fmt.Println("Command adjudication: ALL execs (full argv sent to the configured provider)")
	}
	fmt.Printf("Flag cooldown: %s (AEGIS_FLAG_COOLDOWN to override, seconds)\n", scorer.FlagCooldown)

	// Start consuming both channels
	go scorer.Consume(ctx, chConfig.CriticalChan)
	go scorer.Consume(ctx, chConfig.TelemetryChan)

	// 4. Initialize Embedder and Store
	embedder := &embed.HeuristicEmbedder{}
	store := episodic.NewStore(db, embedder)

	// 5. Resolve LLM provider and models (providers.json + env)
	registry, err := provider.Load()
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
	cfg, err := registry.Resolve()
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("LLM provider: %s (%s)\n", cfg.ProviderName, cfg.URL)
	fmt.Printf("Models: cheap=%s flagship=%s\n", cfg.CheapModel, cfg.FlagshipModel)
	if cfg.Auth == "none" {
		fmt.Println("API key: not required for this provider")
	} else if cfg.Key == "" {
		fmt.Printf("WARNING: no API key found (checked: %s) — adjudications will fail closed (Deny).\n",
			strings.Join(cfg.KeyEnvsTried, ", "))
	} else {
		fmt.Printf("API key: %s (from %s)\n", cfg.MaskedKey(), cfg.KeySource)
	}

	// Hard spend cap: max LLM adjudications per minute, across ALL
	// sessions. Memory auto-recall happens upstream of this and is free.
	maxRPM := 20
	if v := os.Getenv("AEGIS_MAX_LLM_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxRPM = n
		}
	}
	fmt.Printf("LLM adjudication budget: %d calls/min (AEGIS_MAX_LLM_RPM to override, 0=unlimited)\n", maxRPM)

	cheapLLM := &adjudicator.OpenAIAdjudicator{
		APIKey:  cfg.Key,
		URL:     cfg.URL,
		Model:   cfg.CheapModel,
		Headers: cfg.Headers,
	}

	flagshipLLM := &adjudicator.OpenAIAdjudicator{
		APIKey:  cfg.Key,
		URL:     cfg.URL,
		Model:   cfg.FlagshipModel,
		Headers: cfg.Headers,
	}

	cascade := &proxy.RLMCascade{
		CheapLLM:    cheapLLM,
		FlagshipLLM: flagshipLLM,
	}

	rateLimited := &adjudicator.RateLimitedAdjudicator{Inner: cascade, Limit: maxRPM}

	// Wrap with AMLL (Episodic Memory)
	adj := &episodic.RetrievalAugmentedAdjudicator{
		LLM:      rateLimited,
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
	if execGateEnabled {
		approvedMap := ebpfLayer.Map("approved_exec_map")
		if approvedMap == nil {
			fmt.Println("FATAL: approved_exec_map is missing; refusing to expose an unbacked exec gate")
			return
		}
		enforcer.SetApprovedExecMap(approvedMap)
	}

	// 6.5 Initialize Control Socket
	sockPath := "/run/aegis/control.sock"
	if os.Geteuid() != 0 {
		sockPath = "/tmp/aegis.sock"
	}
	// Try creating dir for /run/aegis
	if sockPath == "/run/aegis/control.sock" {
		os.MkdirAll("/run/aegis", 0755)
	}
	ctrlSock := control.NewControlSocket(sockPath, enforcer)
	if err := ctrlSock.Start(); err != nil {
		fmt.Printf("WARNING: failed to start control socket on %s: %v\n", sockPath, err)
	} else {
		defer ctrlSock.Stop()
		fmt.Printf("Control socket: listening on %s\n", sockPath)
	}

	if execGateEnabled {
		socketPath := os.Getenv("AEGIS_EXEC_GATE_SOCKET")
		if socketPath == "" {
			socketPath = ".aegis-run/exec-gate.sock"
		}
		gate, err := control.StartExecGate(ctx, socketPath, adj, enforcer, repoID)
		if err != nil {
			fmt.Printf("FATAL: could not start synchronous exec gate at %s: %v\n", socketPath, err)
			os.Exit(1)
		}
		defer gate.Close()
		fmt.Printf("Exec gate: listening on %s (commands remain blocked until explicit Allow)\n", socketPath)
	}

	// 7. Adjudication Loop
	go func() {
		for flagged := range scorer.Flagged() {
			evType := "?"
			if flagged.Event != nil {
				evType = flagged.Event.Type
			}
			if flagged.Actor != "" && flagged.Actor != flagged.Resource {
				fmt.Printf("[FLAGGED] %s %s\n           by=%s\n           session=%s rule=%s\n", evType, flagged.Resource, flagged.Actor, flagged.SessionID, flagged.Rule)
			} else {
				fmt.Printf("[FLAGGED] %s %s\n           session=%s rule=%s\n", evType, flagged.Resource, flagged.SessionID, flagged.Rule)
			}
			if os.Getenv("AEGIS_DEBUG") == "1" {
				fmt.Printf("[DEBUG] LLM prompt:\n%s\n", adjudicator.BuildPrompt(flagged))
			}

			decision, rationale, err := adj.Adjudicate(ctx, repoID, flagged)
			if err != nil {
				// Provider/format errors are not security verdicts. Mark
				// them AskUser so an outage cannot permanently block a
				// legitimate binary in the kernel deny map.
				fmt.Printf("Adjudication unavailable (no automatic block): %v\n", err)
				if decision == "" {
					decision = adjudicator.DecisionAskUser
					rationale = "adjudication unavailable; human review required"
				}
			}

			fmt.Printf("  -> [DECISION] %s (Rationale: %s)\n", decision, rationale)
			enforcer.Enforce(flagged, decision, rationale)
		}
	}()

	// 8. Graceful Shutdown
	<-ctx.Done()

	fmt.Println("Shutting down aegisd... Running consolidation job")
	consolidate.SessionEnd(context.Background(), db, repoID, "demo-session-id", 0.2)
}
