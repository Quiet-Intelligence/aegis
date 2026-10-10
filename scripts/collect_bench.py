"""Run the Go benchmarks and record the medians in metrics_data.json under "benchmarks".

    python3 scripts/collect_bench.py [--count 5]

Everything the README reports about throughput, latency and allocations comes from here (and from `evalrunner` for
the evaluation metrics); nothing is typed in by hand.
"""
import argparse
import json
import re
import statistics
import subprocess
import sys

PACKAGES = ["./pkg/graph", "./pkg/telemetry", "./internal/memory/episodic", "./internal/policy/cedar"]
LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([\d.]+) ns/op(?:\s+([\d.]+) B/op)?(?:\s+(\d+) allocs/op)?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--metrics", default="metrics_data.json")
    a = ap.parse_args()

    out = subprocess.run(
        ["go", "test", "-run", "^$", "-bench", ".", "-benchmem", f"-count={a.count}", *PACKAGES],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        sys.exit(out.stdout + out.stderr)

    runs, cpu = {}, ""
    for line in out.stdout.splitlines():
        if line.startswith("cpu:"):
            cpu = line.split(":", 1)[1].strip()
        m = LINE.match(line)
        if m:
            name, _, ns, bop, aop = m.groups()
            runs.setdefault(name, []).append((float(ns), float(bop or 0), int(aop or 0)))

    bench = {}
    for name, vals in runs.items():
        bench[name] = {
            "ns_per_op": statistics.median(v[0] for v in vals),
            "bytes_per_op": statistics.median(v[1] for v in vals),
            "allocs_per_op": statistics.median(v[2] for v in vals),
        }
    with open(a.metrics) as f:
        metrics = json.load(f)
    for stale in ("throughput", "ann_benchmarks", "provider_benchmarks", "cedar_benchmarks"):
        metrics.pop(stale, None)          # these used to be typed in by hand and are no longer published
    metrics["benchmarks"] = {"cpu": cpu, "count": a.count, "results": bench}
    with open(a.metrics, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"recorded {len(bench)} benchmarks ({cpu}) in {a.metrics}")


if __name__ == "__main__":
    main()
