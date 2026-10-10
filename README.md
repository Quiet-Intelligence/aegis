<div align="center">

# Aegis
**Behavioural governance, episodic memory and adaptive policy control for autonomous agents**

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/C-eBPF%20LSM-A8B9CC?style=for-the-badge&logo=c)](https://ebpf.io/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite)](https://sqlite.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker)](https://docker.com/)

*A zero-trust enforcement boundary for AI coding agents, built as a one-week OpenAI Buildweek proof of concept.*

</div>

---

> [!IMPORTANT]
> **Aegis is a kernel-level security tool built on eBPF LSM hooks. It runs only on Linux** (kernel 5.8 or newer with `CONFIG_BPF_LSM=y` and `lsm=bpf` on the kernel command line). It will not run natively on macOS or Windows. On Windows use WSL2 to build the project and run the test suite; loading the kernel programs needs a kernel that exposes BPF-LSM. Evaluate the enforcement path on a Linux machine or virtual machine ([Section 8](#8-setup-installation-and-running)).

Aegis is a security control plane that sits inside a hardened container boundary and governs an autonomous coding agent. Static isolation (containers, seccomp, AppArmor) judges each action on its own, and an agent that has been prompt-injected can still chain individually permitted actions into something harmful. Aegis therefore watches the *sequence* of kernel events an agent produces, scores it against hard zero-trust rules and a learned per-repository baseline, consults an LLM only when it has no precedent, remembers every decision, and converts denials into rules enforced in the kernel. This repository is a research prototype: the data plane, control plane, memory, policy compiler and evaluation harness are implemented and tested, and the limits of what has been validated are stated in [Section 11](#11-current-project-status) and [Section 13](#13-limitations-and-future-work).

![Aegis architecture](docs/architecture.png)

## Table of Contents
- [1. Introduction and Motivation](#1-introduction-and-motivation)
- [2. Project Overview (For General Audiences)](#2-project-overview-for-general-audiences)
- [3. Technically Rigorous Deep Dive](#3-technically-rigorous-deep-dive)
- [4. System Architecture](#4-system-architecture)
- [5. Repository Structure](#5-repository-structure)
- [6. Technology Stack](#6-technology-stack)
- [7. Infrastructure, DevOps and CI/CD](#7-infrastructure-devops-and-cicd)
- [8. Setup, Installation and Running](#8-setup-installation-and-running)
- [9. Case Studies](#9-case-studies)
- [10. Results, Benchmarks and Evaluation](#10-results-benchmarks-and-evaluation)
- [11. Current Project Status](#11-current-project-status)
- [12. System Evaluation](#12-system-evaluation)
- [13. Limitations and Future Work](#13-limitations-and-future-work)
- [14. Debugging and Troubleshooting](#14-debugging-and-troubleshooting)
- [15. Support and Maintenance](#15-support-and-maintenance)
- [16. Contribution Guidelines](#16-contribution-guidelines)
- [17. License](#17-license)
- [18. Contributors and Citation](#18-contributors-and-citation)

---

## 1. Introduction and Motivation
Autonomous coding agents read untrusted content (repositories, issues, web pages) and then act on it with real permissions. That combination makes *prompt injection* a security problem rather than a quality problem: text the agent reads can steer what the agent does. Containers and sandboxes are necessary, but they are static allow/deny boundaries, and the interesting failures happen *inside* what they allow.

The project was motivated by **CVE-2026-55607**, a sandbox escape in Anthropic's Claude Code (fixed in version 2.1.163). Public write-ups describe the chain: the agent did not validate worktree names, so an attacker's repository could use prompt injection to make it run `git worktree add .git`, turning the repository root into a valid git directory whose attacker-controlled configuration then governed later git operations; combined with a symlink under `.claude/worktrees` pointing at the home directory and a `core.fsmonitor` setting, this allowed the shell start-up file `~/.zshenv` to be overwritten, which the shell reads *before* the macOS Seatbelt sandbox is applied, so the payload ran outside the sandbox. Every individual step was an operation the agent was allowed to perform.

The lesson Aegis takes from this is not a signature for that exploit but a design principle: **threats of this kind are emergent and composable**. They are visible only in the *sequence* of actions and in how that sequence deviates from what is normal for the repository. Aegis observes the sequence at the kernel boundary, recognises deviation, remembers precedent so that it is not paying for an LLM call on every event, and turns what it learns into enforceable policy.

## 2. Project Overview (For General Audiences)
Imagine you hire a capable but trusting assistant to work in your house. You can lock the front door (traditional sandboxing), but a note slipped under the door could still talk the assistant into unlocking the back window. What you actually want is a supervisor who watches what the assistant does.

* **It watches the smallest actions (telemetry).** Using a Linux kernel feature called eBPF, Aegis sees which files the agent opens, which programs it launches and which network connections it makes, without modifying the agent.
* **It looks at sequences, not single actions (behaviour graph).** Opening a file is fine; opening a hundred unrelated files outside the project, then launching a downloader, is not.
* **It has a memory (retrieval-augmented adjudication).** If a situation matches one it has already judged, it reuses that judgement instantly and for free. Only genuinely new situations are sent to a language model for a decision.
* **It converts decisions into rules (enforcement).** A denial becomes a rule that the kernel enforces on every later attempt, with no further model call.
* **It is measured honestly (evaluation).** The project ships a test harness that replays multi-step attacks and legitimate workflows, so that making it stricter cannot silently make it unusable.

## 3. Technically Rigorous Deep Dive
Aegis is organised as four cooperating pillars (kernel data plane, stateful control plane, episodic memory, and policy and learning) plus a synchronous execution gate.

### 3.1 The kernel data plane (Layer 1)
Three `bpf_lsm` programs (`ebpf/file_open.bpf.c`, `socket_connect.bpf.c`, `exec_hash.bpf.c`) attach to the `file_open`, `socket_connect` and `bprm_check_security` hooks. They filter by the agent's cgroup, so only the agent's process tree is observed, and emit fixed-size event structs through a `BPF_MAP_TYPE_RINGBUF`. Enforcement is deliberately **progressive**: the programs only observe until userspace populates the `denied_hashes` and `denied_paths` maps, after which matching opens and executions are refused in the kernel (`-EPERM`). This lets the system run in an observation-only mode and tighten once it has evidence.

### 3.2 The stateful control plane (Layer 2, `aegisd`)
* **Telemetry (`pkg/telemetry`).** Ring-buffer records are read with `cilium/ebpf` and reinterpreted in place, without copying; event wrappers are recycled with `sync.Pool` so that the decode and pooling paths are allocation-free (measured in [Section 10](#10-results-benchmarks-and-evaluation)). Back-pressure is applied per event class: bounded, **fail-closed** channels with timeouts for the critical `file_open` and `exec` events (a slow consumer cannot silently drop security-relevant events), and **fail-open** for generic telemetry (to protect throughput).
* **Scorer (`pkg/graph`).** Each event is appended to a per-session temporal graph and scored in two modes. *Hard invariants* are checked regardless of any baseline: access outside `/workspace`, modification of `.git/config` or worktree metadata, execution of high-risk binaries (`rm`, `wget`, `curl`, `nc`), and optionally any outbound network. *Baseline deviation* compares event timing and shape with an exponential-moving-average baseline for the repository (kept in SQLite and updated asynchronously by `internal/memory/consolidate`). A per-rule cooldown prevents one noisy process from flooding the adjudicator.
* **Retrieval-augmented adjudicator (`pkg/adjudicator`, `internal/memory/episodic`).** An anomalous event is first looked up in episodic memory. For an `exec`, recall requires an **exact** match on path, argv, matched rule and the binary's SHA-256, so that a merely similar command, or a modified binary at the same path, can never inherit a previous *allow*. For other events the event is embedded and any past decision with cosine similarity above 0.95 is recalled, best first. Only on a miss is the LLM consulted, through a cascade (`internal/proxy`) that tries a cheaper model first and escalates to a flagship model for hard cases; a fixed-window rate limiter (`pkg/adjudicator/ratelimit.go`) caps spend and fails closed without touching the network once the budget is exhausted. Every decision is stored as a case with its embedding (float32 BLOBs in SQLite).
* **Enforcer (`pkg/policy`).** Writes an audit log, converts denials into stored policies and synchronises them into the BPF maps.

### 3.3 The synchronous execution gate
A seccomp user-notification supervisor (`pkg/control`, `perimeter/aegis-gate.c`) can **hold an `exec` until the adjudicator has decided**, which closes the window in which a new binary could run before a policy exists for it. This is the one place where the system blocks on a decision rather than learning from one.

### 3.4 Formal policy layer (Cedar subset)
Declarative boundaries are written as AWS Cedar `forbid` rules (for example `forbid(principal, action, resource) when { resource.binary_hash == "..." }`). A small compiler (`internal/policy/cedar`) translates the supported forms, binary-hash equality and path-prefix `like` patterns, into the payloads of the `denied_hashes` and `denied_paths` maps, so that enforcement is an O(1) map lookup in the kernel with no external policy call on the hot path. The compiler is deliberately a narrow, regex-based translator, **not** a full Cedar engine; the checked-in policies are validated against `schema.json` in CI with the Cedar CLI.

### 3.5 Offline learning and evaluation
* **LinUCB contextual bandit (`internal/bandit`).** Proposes decision thresholds (for example the auto-decide threshold) under an asymmetric reward in which a false negative costs -5 and a false positive -1, reflecting zero-trust priorities. It is **offline**: it is trained on recorded outcomes and its proposals are applied by a human via `aegisctl`. It is a one-step reinforcement-learning method (a contextual bandit), not a full sequential RL agent.
* **Static and stateful evaluation.** EV1 is a small golden set used as a CI regression gate. EV2 replays multi-step adversaries (three strategies that adapt after each denial) and ten legitimate developer workflows as simulated kernel telemetry through the **real** scorer, memory and adjudicator code paths, measuring how many steps an attacker survives and how often legitimate work is wrongly refused. The reasoning behind that design, and the ways a learned reward could be gamed, are in `docs/reward_hacking_audit.md`.
* **Process Reward Model (PRM) scaffold.** `scripts/train_prm.py` runs end to end but has far too little labelled data to be predictive and is not used for any decision.

### 3.6 Threat model and trust boundaries
* **Protected:** actions of an agent process tree inside the Layer 0 container, as observed at the LSM hooks.
* **Assumed trusted:** the Linux kernel and the BPF subsystem, the `aegisd` process and its SQLite store, and the host operator. A compromised kernel or a root user outside the container is out of scope.
* **Not claimed:** protection against kernel exploits, against an agent that can disable the daemon from outside the container, or complete coverage of all syscalls (only the three hooked operations are observed).
* **Adjudication risk:** the LLM consumes event descriptions that may themselves contain attacker-controlled strings; events are serialised through deterministic `MarshalJSON` implementations and the exec-recall path is exact-match precisely so that a model-visible text cannot widen an earlier allow.

## 4. System Architecture
![System Architecture](docs/architecture.png)

**Decision path for one anomalous event.** The agent inside Layer 0 issues a syscall; the LSM hook (Layer 1) emits an event and, if a matching deny rule already exists in the BPF maps, blocks it immediately. Otherwise the event travels through the ring buffer to `aegisd`, is appended to the session graph and scored. Events that trip a hard invariant or deviate from the baseline go to the adjudicator: episodic memory is queried first (exact match for `exec`, cosine > 0.95 otherwise); a miss goes to the LLM cascade. The decision is stored with its embedding. A denial is converted into a policy and synchronised into the BPF maps, so the same behaviour is blocked in the kernel next time. Offline, the bandit proposes threshold changes from recorded outcomes, and the EV1/EV2 harness checks that changes do not degrade security or task completion.

## 5. Repository Structure
```text
aegis/
├── perimeter/            # Layer 0: container definition, seccomp profile, run script, aegis-gate (exec gate supervisor, C)
├── ebpf/                 # Layer 1: LSM programs (file_open, socket_connect, exec_hash), shared map
│   │                     #          definitions, vmlinux_fallback.h for kernels without BTF
├── cmd/
│   ├── aegisd/           # Layer 2 daemon (control plane)
│   ├── aegisctl/         # operator CLI: provider, policy (list/revoke), bandit (propose/apply), review
│   ├── aegis-tui/        # Bubble Tea terminal UI tailing the audit log
│   ├── evalrunner/       # EV1 golden and EV2 trajectory runners; writes metrics_data.json
│   └── loadgen/          # synthetic event generator (throughput testing)
├── pkg/
│   ├── telemetry/        # ring-buffer readers, pooled events, back-pressure
│   ├── graph/            # temporal session graph and scorer
│   ├── adjudicator/      # adjudicator interface, rate limiter
│   ├── policy/           # enforcer: audit log, policy store, BPF map synchronisation
│   ├── control/          # seccomp user-notification exec gate and control socket
│   └── provider/         # model-provider registry (providers.json)
├── internal/
│   ├── memory/           # SQLite schema, episodic recall, embedders, baseline consolidation
│   ├── bandit/           # LinUCB contextual bandit and audit report
│   ├── proxy/            # LLM cascade (cheap first, flagship on escalation)
│   └── policy/cedar/     # Cedar-subset compiler, schema, baseline rules
├── evals/                # golden cases, adversarial cases, trajectory environment, generator, held-out set
├── scripts/              # collect_bench.py, update_metrics.py, train_prm.py, install_deps.sh, soak_test.sh, SFT export
├── docs/                 # architecture diagram (PNG + Excalidraw source), reward-hacking audit, chart images
├── assets/demo.mp4       # recorded demonstration
└── .github/workflows/    # ci.yml, evals-ci.yml, trajectory-evals.yml, cedar-ci.yml, check-heldout.yml, contamination-check.yml
```

## 6. Technology Stack
* **Data plane:** C and eBPF (`bpf_lsm`, libbpf, BTF), compiled with `clang -target bpf`; `vmlinux_fallback.h` for kernels without BTF.
* **Control plane:** Go (1.25 in `go.mod`); `cilium/ebpf` for ring-buffer ingestion; `go-sqlite3`.
* **Memory:** SQLite with float32 embedding BLOBs and brute-force cosine similarity in native Go.
* **Policy:** AWS Cedar (schema validation with the Cedar CLI) with a custom subset compiler to BPF map entries.
* **Exec gate:** libseccomp user notification (C) with a Go control socket.
* **Interface:** Bubble Tea terminal UI.
* **Models:** any OpenAI-compatible chat-completions endpoint (hosted or local, for example Ollama); a deterministic keyword mock for reproducible CI.
* **Tooling and evaluation:** GitHub Actions, Docker, Python (scikit-learn for the PRM scaffold, matplotlib for charts).

## 7. Infrastructure, DevOps and CI/CD
The pipeline separates fast regression gates from deeper evaluations.

1. **Build, vet and test (`ci.yml`).** `go build ./...` (so that references to undefined symbols anywhere, including the evaluation runner, fail the build), `go vet ./...`, and `go test ./... -race -count=1`.
2. **Evaluations on every change (`ci.yml`, `evals-ci.yml`).** The EV1 golden set must keep precision and recall at or above 0.95 or the build fails; EV2 trajectories run with the mock adjudicator. This guards against a tuning change quietly making the scorer weaker or the system unusable.
3. **eBPF compilation (`ci.yml`).** The three LSM programs are compiled with clang (using the bundled `vmlinux_fallback.h` when the runner exposes no BTF) and the build checks that the objects exist and contain LSM sections. Hosted runners have no BPF-LSM kernel, so loading and enforcement are validated on a Linux host, not in CI.
4. **Trajectory evaluation and held-out corpus (`trajectory-evals.yml`, `check-heldout.yml`, `contamination-check.yml`).** Deeper, adaptive evaluations (EV2) run through the real scorer and memory. A held-out trajectory set (`evals/trajectory/heldout/`) is protected structurally: the workflows fail a pull request that modifies both the scorer (`pkg/graph/`) and the held-out corpus, so the scorer cannot be tuned against the cases it is later judged on in the same change.
5. **Formal policy validation (`cedar-ci.yml`).** The Cedar CLI validates the checked-in policies against `schema.json`, so contradictory or schema-violating policies cannot be merged.
6. **Metrics pipeline (`make metrics`).** `scripts/collect_bench.py` runs the Go benchmarks (median of five runs) and `scripts/update_metrics.py` regenerates the charts and the tables in [Section 10](#10-results-benchmarks-and-evaluation) from `metrics_data.json`. Nothing in that section is typed by hand.

## 8. Setup, Installation and Running

### Requirements
* **Linux** with kernel 5.8 or newer, `CONFIG_BPF_LSM=y`, and `lsm=bpf` (for example `lsm=bpf,apparmor`) on the kernel command line to *load* the LSM programs. Without it you can still build everything and run the full test suite.
* **Windows:** use WSL2. Stock WSL kernels do not enable BPF-LSM, so on WSL2 the objects compile and tests run, and live enforcement needs a custom kernel.
* **macOS:** use a Linux virtual machine; Darwin kernels have no eBPF.
* Go 1.25, `clang` and `llvm` (eBPF compilation), `make`, Python 3 with matplotlib (charts), optionally Docker and `libseccomp`.
* eBPF objects are compiled against the kernel headers of the machine running them; `make -C ebpf` falls back to the bundled `vmlinux_fallback.h` when `/sys/kernel/btf/vmlinux` is unavailable (typical on WSL2), so compilation does not need network access or `linux-headers`.

### One-command path
```bash
git clone https://github.com/Quiet-Intelligence/aegis.git && cd aegis
make everything        # dependencies, eBPF objects, Go binaries, tests, evals, benchmarks, metrics, then the TUI
```

### Individual targets
`make ebpf` (clang), `make build`, `make test`, `make vet`, `make eval` (EV1), `make eval-trajectory` (EV2), `make bench` (Go benchmarks), `make metrics` (charts and the README tables), `make tui`, and `./run_demo.sh` (compile, start `aegisd`, open the TUI; then run commands inside the container from a second terminal to watch them judged).

### 8.1 Configuring the adjudicator
The adjudicator is model-agnostic (OpenAI-compatible chat completions) and uses a two-tier cascade. **Never commit keys**; set them in the environment or in a git-ignored `aegis.env` (see `aegis.env.example`). Without a key, the evaluations use a deterministic keyword mock so that CI is reproducible.

```bash
export AEGIS_LLM_URL="https://api.openai.com/v1/chat/completions"
export AEGIS_CHEAP_MODEL="gpt-4o-mini"      # first-pass model
export AEGIS_FLAGSHIP_MODEL="gpt-4o"        # escalation model
export AEGIS_LLM_KEY="..."
```
Other providers work by changing the URL and model names, for example an aggregator such as OpenRouter, Groq, or a **local model** through Ollama (`AEGIS_LLM_URL=http://localhost:11434/v1/chat/completions`, no key needed), which keeps file paths from ever leaving the host. `aegisctl provider` manages the provider registry.

## 9. Case Studies

### 9.1 The motivating class: CVE-2026-55607
The `git worktree` sandbox escape described in [Section 1](#1-introduction-and-motivation) is the design motivation. The relevant property is that none of its steps is individually forbidden. Aegis's session graph and baseline deviation check are designed to flag the *combination* (modifying worktree and `.git` metadata, writes outside `/workspace`, execution of a binary not seen before) rather than any single call. The repository's trajectory evaluator simulates this style of multi-step, adaptive attack against the real scorer, memory and adjudicator ([Section 10](#10-results-benchmarks-and-evaluation)).

### 9.2 BunnyHijack
In a red-team evaluation Aegis was run against [BunnyHijack](https://github.com/X3r0Day/BunnyHijack-PoC), a proof of concept for a trust-boundary flaw in the `bun` package manager (the maintainer disputes its classification as a vulnerability). Aegis flagged the anomalous post-exploitation system calls, such as unexpected network sockets and file writes, and blocked the payload at the syscall layer, together with other unauthorised commands issued in the same session. No signature for this exploit exists in the repository; detection comes from the behavioural graph and the exec gate. This was exercised live on Linux hosts, including WSL2, by the team and recorded below; it is not reproducible in CI.

**Demonstration (full run):**

<video src="assets/demo.mp4" controls="controls" width="100%">
  Your browser does not support the video tag. The file is at <code>assets/demo.mp4</code>.
</video>

## 10. Results, Benchmarks and Evaluation
The tables and charts between the markers below are **generated** by `make eval eval-trajectory bench metrics` from real runs and are overwritten on every run; they are not typed by hand. Read them with the following in mind: the benchmarks measure userspace cost only (the eBPF hooks are exercised on a Linux host); EV1 is a six-case regression gate, not a security benchmark; and EV2 uses simulated telemetry and, in CI, a mock adjudicator, so it checks the scoring, memory and policy logic and does not measure a live model's judgement.

<!-- METRICS_START -->

### Throughput, latency and allocations (Go benchmarks)

Measured by `scripts/collect_bench.py` (median of 5 runs) on **Intel(R) Core(TM) i7-14650HX**. These are *userspace* costs: they exclude the eBPF ring buffer and kernel hooks, which are exercised on a Linux host (see "Evidence" above).

| Operation | Time per op | Allocations per op |
|---|---:|---:|
| Score one benign `file_open` (rules, session graph, SQLite baseline read) | 3.75 µs (~267k events/s/core) | 20 |
| Score one benign `exec` | 4.38 µs | 25 |
| Score + flag one out-of-workspace `file_open` | 4.50 µs | 20 |
| Decode a ring-buffer record (in-place reinterpretation) | 0.16 ns | 0 |
| Event pool get/put | 8.9 ns | 0 |
| Compile a two-rule Cedar policy to BPF map entries | 7.1 µs | 91 |

The decode and pooling paths are allocation-free; the scoring path is not (it builds session IDs, resource strings and graph nodes per event).

![Scorer cost](docs/images/scorer_cost.png)

### Episodic memory recall (brute-force cosine over stored embeddings)

| Stored cases | Query latency |
|---:|---:|
| 10 | 0.02 ms |
| 100 | 0.18 ms |
| 1,000 | 1.83 ms |
| 5,000 | 11.07 ms |
| 20,000 | 47.55 ms |

Cost is linear in stored cases (~2.4 µs per case). An ANN index becomes necessary once a repository holds tens of thousands of cases.

![ANN latency](docs/images/ann_latency.png)

### Static golden dataset (EV1)

A fast CI regression gate over 6 hand-written cases (malicious and benign sequences); it is a smoke test, not a security benchmark.

| Metric | Value |
|--------|-------|
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | 1.000 |
| False Positive Rate | 0.000 |
| False Negative Rate | 0.000 |

### Stateful trajectory evaluation (EV2)

A multi-step adversary (three strategies: fast worktree, slow drip, benign blend, adapting after each denial) and ten legitimate developer workflows are replayed as simulated kernel telemetry through the **real** scorer, episodic memory and adjudicator code paths (`evalrunner -trajectory`). The adjudicator is a deterministic keyword mock in CI; set `AEGIS_LLM_KEY` to run the same trajectories against a live model.

| Metric | Value |
|--------|-------|
| Adversarial runs (N) | 20 |
| Mean steps survived before denial | 9.20 (variance 5.86) |
| Legitimate workflows | 10 |
| Over-refusals | 1 (10%) |
| Task success rate | 90% |

![Trajectory metrics](docs/images/trajectory_metrics.png)

### Process Reward Model (PRM) scaffold

The PRM pipeline (`scripts/train_prm.py`) is wired end to end and emits a model artifact, but it has too little labelled data to be predictive and is **not** used for any decision. See `docs/reward_hacking_audit.md`.

| Metric | Value |
|--------|-------|
| Labelled trajectory steps mined | 2 |
| PRM R² | -0.0029 |

<!-- METRICS_END -->

## 11. Current Project Status

### Implemented and verified
* **Kernel data plane:** three LSM programs with cgroup filtering, ring-buffer telemetry and progressive enforcement via BPF maps; compilation checked in CI, behaviour validated live on Linux (native and WSL2) outside CI.
* **Control plane:** pooled in-place telemetry decoding with fail-closed/fail-open back-pressure; temporal graph scorer with hard invariants and a baseline-deviation score; rule cooldowns.
* **Adjudication:** exact-match exec recall, cosine recall for other events, LLM cascade, and a rate limiter; every decision persisted with its embedding.
* **Policy:** Cedar-subset compiler to BPF map payloads; policy synchronisation; CI schema validation.
* **Execution gate:** seccomp user-notification supervisor that holds an `exec` for a decision.
* **Operator tooling:** Bubble Tea TUI tailing the audit log with rationales and similarity scores; `aegisctl` for the provider registry, policy list/revoke, bandit proposals and review.
* **Evaluation:** EV1 gate, EV2 stateful trajectories with an adaptive adversary and legitimate-workflow checks, held-out set with contamination guards, and a generated metrics pipeline; 57 Go test functions run under the race detector.
* **Performance work with measurements:** a switch from JSON to float32 BLOB embeddings cut episodic recall at 5,000 cases from 278 ms to 11 ms.

### Not implemented or not validated
* The Process Reward Model is a scaffold with too little data to be predictive and is not used for any decision.
* The bandit is offline only.
* No live, large-scale red-team benchmark exists; EV1 and EV2 are regression gates over small, partly simulated sets.
* Enforcement in the kernel is not covered by CI.

## 12. System Evaluation
An honest reading of what the evidence supports:

* **Does it generalise beyond one CVE?** The design is signature-free by intent: the scorer reasons about workspace boundaries, high-risk binaries and baseline deviation rather than about named exploits. The evidence for generalisation is the EV2 trajectory results (an adaptive adversary survives a mean of about 9 steps before denial in simulation) and the BunnyHijack live run. Neither is a substitute for an independent red-team study.
* **Cost and latency of the hot path.** Scoring costs a few microseconds per event and decoding is allocation-free ([Section 10](#10-results-benchmarks-and-evaluation)); these are userspace figures and exclude kernel hooks and ring-buffer transfer. Memory recall makes repeated situations free of LLM calls and cuts their decision latency from a network round trip to milliseconds.
* **Memory scaling.** Recall is brute force and linear in the number of stored cases; it is comfortable to a few thousand cases and needs an index beyond that.
* **Learning and reward hacking.** Optimising thresholds against a static evaluation set is exposed to reward hacking. The mitigation implemented is structural: thresholds change only through a human-applied proposal, and any change is re-evaluated against stateful, held-out trajectories ([`docs/reward_hacking_audit.md`](docs/reward_hacking_audit.md)). This reduces the risk; it is not a proof of its absence.
* **Over-refusal.** In EV2 one of ten legitimate workflows is refused (10%), which is a real cost; reducing it without raising the survival of attackers is the main open tuning problem.

## 13. Limitations and Future Work
1. **Linux only.** CI has no BPF-LSM kernel, so enforcement is validated on hosts, not automatically. Shipping one binary across kernels needs eBPF **CO-RE** (compile once, run everywhere) with embedded BTF; objects are currently compiled per machine.
2. **Episodic recall is brute force** (about 2.4 µs per stored case). An ANN index (`sqlite-vec` or HNSW) is needed beyond tens of thousands of cases.
3. **Cedar support is a narrow subset** (binary-hash and path-prefix `forbid` rules). The baseline-deviation rules in `baseline_rules.cedar` are declarative documentation and are not enforced by the compiler; a full Cedar evaluator would be a replacement for it.
4. **Session graphs are unbounded** within a session; long-running sessions need a window or ring.
5. **Evaluation scale.** The golden set is small and EV2 is simulated telemetry; a larger, independently built adversarial corpus and live-model evaluation are needed before any claim of security efficacy.
6. **Learning.** The bandit is offline-only; online adaptation needs safety bounds first. The PRM needs real labelled trajectories.
7. **Portability.** Native telemetry adapters (eBPF for Windows, macOS Endpoint Security) behind the existing `Telemetry` interface, or a WebAssembly/WASI capability sandbox (a "Layer 0.5") for platforms without BPF-LSM.
8. **Local adjudicators.** Fine-tuned small models (scripts for supervised-fine-tuning data export and LoRA training are included) would remove the dependence on an external API.

## 14. Debugging and Troubleshooting
* **`operation not permitted` when loading eBPF.** Run `aegisd` with root capabilities, and confirm that BPF-LSM is active: `lsm=bpf` must appear on the kernel command line (check `/sys/kernel/security/lsm`). Stock WSL2 kernels do not include it.
* **Missing headers or BTF on WSL2.** If `/sys/kernel/btf/vmlinux` does not exist, `make -C ebpf` uses the bundled `vmlinux_fallback.h`. A warning about `linux-headers` during dependency installation is expected and harmless.
* **High garbage-collection pauses.** Check that the `sync.Pool` event recycling in `pkg/telemetry/events.go` has not been bypassed by local changes; run `make bench` and compare allocations per operation.
* **Evaluations differ between machines.** Without `AEGIS_LLM_KEY` the evaluations use the deterministic mock adjudicator; results with a live model will differ.
* **A secrets check before committing.** Keep `aegis.env` out of version control (it is git-ignored); use `aegis.env.example` as the template.

## 15. Support and Maintenance
Aegis is an academic and hackathon research repository. Please use the GitHub issue tracker for bugs and feature requests. Security issues, especially bypasses of the behavioural heuristics or the exec gate, should be reported privately to the maintainers rather than in a public issue.

## 16. Contribution Guidelines
The repository follows GitFlow: branch from `develop` as `feature/<name>` and use Conventional Commits (for example `feat(graph): ...`). Changes must pass the CI gates: build, vet and race tests; the EV1 gate (precision and recall at or above 0.95); EV2 trajectories; eBPF compilation; and Cedar validation. A decrease in golden-set recall will not be merged without an explicit maintainer override and a written justification. New behaviour needs a test, and any benchmark claim should come from `make bench` and `make metrics`, not hand-edited numbers.

## 17. License
Distributed under the **PolyForm Noncommercial License**. Commercial use, deployment in revenue-generating environments, or integration into proprietary security products requires written authorisation from the authors.

## 18. Contributors and Citation
Designed and implemented by **Pundarikaksh N. Tripathi** (kernel data plane, control plane, memory, policy, evaluation and tooling) over a one-week OpenAI Buildweek sprint. **Sameer Sharma** contributed presentation and documentation; **Arnav Singh** contributed testing and validation of the live security behaviour.

If you use the architecture or the evaluation methodology in academic work, please cite:

```bibtex
@software{Aegis_2026,
  author = {Tripathi, Pundarikaksh N. and Singh, Arnav and Sharma, Sameer},
  title  = {Aegis: Behavioral Governance and Adaptive Policy Control for Autonomous Agents},
  year   = {2026},
  url    = {https://github.com/Quiet-Intelligence/aegis},
  note   = {OpenAI Buildweek proof of concept}
}
```
