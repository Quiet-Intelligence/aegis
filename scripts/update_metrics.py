"""Regenerate the README results section and charts from metrics_data.json.

metrics_data.json is written by tools in this repository only:
  * `evalrunner`            -> "evals" (EV1 golden set) and "trajectory_evals" (EV2 stateful trajectories)
  * `collect_bench.py`      -> "benchmarks" (Go benchmarks: scorer, ANN recall, Cedar compile, telemetry hot paths)
  * `train_prm.py`          -> "prm"
Run `make metrics` after `make eval eval-trajectory bench`.
"""
import json
import os
import re

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

IMG = "docs/images"


def style(ax):
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(True, alpha=0.25)


def main():
    os.makedirs(IMG, exist_ok=True)
    with open("metrics_data.json", encoding="utf-8") as f:
        data = json.load(f)
    bench = data["benchmarks"]["results"]
    cpu = data["benchmarks"].get("cpu", "unknown CPU")

    # --- ANN recall latency vs stored vectors ---------------------------------------------------------
    ann = sorted(((int(k.rsplit("_", 1)[1]), v["ns_per_op"] / 1e6) for k, v in bench.items() if k.startswith("BenchmarkQuery/Vectors_")))
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot([a for a, _ in ann], [b for _, b in ann], "o-", color="#2c3e50")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Stored case embeddings per repository (384-d float32)")
    ax.set_ylabel("Recall query latency (ms, median)")
    ax.set_title("Brute-force episodic recall: linear in stored cases")
    style(ax)
    fig.tight_layout()
    fig.savefig(f"{IMG}/ann_latency.png", dpi=200)
    plt.close(fig)

    # --- scorer cost -----------------------------------------------------------------------------------
    sc = {k.split("/", 1)[1]: v for k, v in bench.items() if k.startswith("BenchmarkScorerProcessEvent/")}
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    names = list(sc)
    ax.barh(names, [sc[n]["ns_per_op"] / 1000 for n in names], color=["#4c6ef5", "#4c6ef5", "#e8590c"][: len(names)])
    ax.set_xlabel("Userspace cost per event (microseconds, median)")
    ax.set_title("Scoring one kernel event (rules + session graph + SQLite baseline read)")
    style(ax)
    fig.tight_layout()
    fig.savefig(f"{IMG}/scorer_cost.png", dpi=200)
    plt.close(fig)

    # --- EV1 -------------------------------------------------------------------------------------------
    ev = data["evals"]
    fig, ax = plt.subplots(figsize=(7, 4))
    vals = [ev["golden_precision"], ev["golden_recall"], ev["golden_f1"]]
    bars = ax.bar(["Precision", "Recall", "F1"], vals, color=["#3498db", "#2ecc71", "#9b59b6"])
    ax.set_ylim(0, 1.1)
    ax.set_title("EV1: static golden + adversarial cases (CI regression smoke test)")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center")
    style(ax)
    fig.tight_layout()
    fig.savefig(f"{IMG}/eval_metrics.png", dpi=200)
    plt.close(fig)

    # --- EV2 -------------------------------------------------------------------------------------------
    tr = data["trajectory_evals"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4.2))
    a1.hist(tr["survival_distribution"], bins=range(0, 52), color="#8e44ad", rwidth=0.9)
    a1.set_xlabel("Steps survived before denial")
    a1.set_ylabel("Runs")
    a1.set_title(f"Adversarial survival (N={tr['adversarial_runs']})")
    style(a1)
    success = tr["task_success_rate"]
    a2.pie([success, 1 - success], labels=["Task success", "Over-refusal"], autopct="%1.0f%%", colors=["#2ecc71", "#95a5a6"], startangle=90)
    a2.set_title(f"Legitimate workflows (N={tr['legitimate_workflows']})")
    fig.suptitle("EV2: stateful trajectory evaluation", y=1.02)
    fig.tight_layout()
    fig.savefig(f"{IMG}/trajectory_metrics.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

    def b(name, key="ns_per_op"):
        return bench[name][key]

    md = f"""
### Throughput, latency and allocations (Go benchmarks)

Measured by `scripts/collect_bench.py` (median of {data['benchmarks'].get('count', '?')} runs) on **{cpu}**. These are *userspace* costs: they exclude the eBPF ring buffer and kernel hooks, which are exercised on a Linux host (see "Evidence" above).

| Operation | Time per op | Allocations per op |
|---|---:|---:|
| Score one benign `file_open` (rules, session graph, SQLite baseline read) | {b('BenchmarkScorerProcessEvent/file_open_in_workspace') / 1000:.2f} µs (~{1e9 / b('BenchmarkScorerProcessEvent/file_open_in_workspace') / 1000:.0f}k events/s/core) | {b('BenchmarkScorerProcessEvent/file_open_in_workspace', 'allocs_per_op'):.0f} |
| Score one benign `exec` | {b('BenchmarkScorerProcessEvent/exec_benign') / 1000:.2f} µs | {b('BenchmarkScorerProcessEvent/exec_benign', 'allocs_per_op'):.0f} |
| Score + flag one out-of-workspace `file_open` | {b('BenchmarkScorerProcessEvent/file_open_flagged_outside_workspace') / 1000:.2f} µs | {b('BenchmarkScorerProcessEvent/file_open_flagged_outside_workspace', 'allocs_per_op'):.0f} |
| Decode a ring-buffer record (in-place reinterpretation) | {b('BenchmarkDecodeFileOpen'):.2f} ns | {b('BenchmarkDecodeFileOpen', 'allocs_per_op'):.0f} |
| Event pool get/put | {b('BenchmarkEventPoolGetPut'):.1f} ns | {b('BenchmarkEventPoolGetPut', 'allocs_per_op'):.0f} |
| Compile a two-rule Cedar policy to BPF map entries | {b('BenchmarkCompileToBPF') / 1000:.1f} µs | {b('BenchmarkCompileToBPF', 'allocs_per_op'):.0f} |

The decode and pooling paths are allocation-free; the scoring path is not (it builds session IDs, resource strings and graph nodes per event).

![Scorer cost](docs/images/scorer_cost.png)

### Episodic memory recall (brute-force cosine over stored embeddings)

| Stored cases | Query latency |
|---:|---:|
""" + "\n".join(f"| {n:,} | {ms:.2f} ms |" for n, ms in ann) + f"""

Cost is linear in stored cases (~{ann[-1][1] * 1000 / ann[-1][0]:.1f} µs per case). An ANN index becomes necessary once a repository holds tens of thousands of cases.

![ANN latency](docs/images/ann_latency.png)

### Static golden dataset (EV1)

A fast CI regression gate over {ev.get('cases', 'a small number of')} hand-written cases (malicious and benign sequences); it is a smoke test, not a security benchmark.

| Metric | Value |
|--------|-------|
| Precision | {ev['golden_precision']:.3f} |
| Recall | {ev['golden_recall']:.3f} |
| F1 Score | {ev['golden_f1']:.3f} |
| False Positive Rate | {ev['golden_fpr']:.3f} |
| False Negative Rate | {ev['golden_fnr']:.3f} |

### Stateful trajectory evaluation (EV2)

A multi-step adversary (three strategies: fast worktree, slow drip, benign blend, adapting after each denial) and ten legitimate developer workflows are replayed as simulated kernel telemetry through the **real** scorer, episodic memory and adjudicator code paths (`evalrunner -trajectory`). The adjudicator is a deterministic keyword mock in CI; set `AEGIS_LLM_KEY` to run the same trajectories against a live model.

| Metric | Value |
|--------|-------|
| Adversarial runs (N) | {tr['adversarial_runs']} |
| Mean steps survived before denial | {tr['mean_steps_survived']:.2f} (variance {tr['variance_steps']:.2f}) |
| Legitimate workflows | {tr['legitimate_workflows']} |
| Over-refusals | {tr['over_refusals']} ({100 * tr['over_refusals'] / tr['legitimate_workflows']:.0f}%) |
| Task success rate | {100 * tr['task_success_rate']:.0f}% |

![Trajectory metrics](docs/images/trajectory_metrics.png)

### Process Reward Model (PRM) scaffold

The PRM pipeline (`scripts/train_prm.py`) is wired end to end and emits a model artifact, but it has too little labelled data to be predictive and is **not** used for any decision. See `docs/reward_hacking_audit.md`.

| Metric | Value |
|--------|-------|
| Labelled trajectory steps mined | {data['prm']['labeled_steps_used']} |
| PRM R² | {data['prm']['r2_score']:.4f} |
"""
    with open("README.md", encoding="utf-8") as f:
        readme = f.read()
    start, end = "<!-- METRICS_START -->", "<!-- METRICS_END -->"
    new = start + "\n" + md + "\n" + end
    readme = re.sub(re.escape(start) + r".*?" + re.escape(end), lambda _: new, readme, flags=re.S)
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)


if __name__ == "__main__":
    main()
