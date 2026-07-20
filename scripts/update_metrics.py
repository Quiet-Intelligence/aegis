import json
import re
import os
import matplotlib.pyplot as plt

def main():
    # Ensure images directory exists
    os.makedirs('docs/images', exist_ok=True)

    with open('metrics_data.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Plot 1: ANN Query Latency vs Stored Vectors
    vectors = [x['vectors'] for x in data['ann_benchmarks']]
    latencies = [x['latency_ms'] for x in data['ann_benchmarks']]

    plt.figure(figsize=(8, 5))
    plt.plot(vectors, latencies, marker='o', linestyle='-', color='#2c3e50', linewidth=2)
    plt.axhline(y=50, color='#e74c3c', linestyle='--', label='50ms threshold')
    plt.title('Brute-Force Cosine Similarity Query Latency', fontsize=14)
    plt.xlabel('Stored Vectors per Repository', fontsize=12)
    plt.ylabel('p95 Latency (ms)', fontsize=12)
    plt.xscale('log')
    plt.grid(True, which='both', linestyle='--', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    plt.savefig('docs/images/ann_latency.png', dpi=300)
    plt.close()

    # Plot 2: Golden Eval Metrics
    metrics = ['Precision', 'Recall', 'F1 Score', 'Auto-Recall Prec']
    values = [
        data['evals']['golden_precision'],
        data['evals']['golden_recall'],
        data['evals']['golden_f1'],
        data['evals']['auto_recall_precision']
    ]

    plt.figure(figsize=(8, 5))
    bars = plt.bar(metrics, values, color=['#3498db', '#2ecc71', '#9b59b6', '#f1c40f'])
    plt.title('Golden Dataset Evaluation Metrics', fontsize=14)
    plt.ylabel('Score (0.0 to 1.0)', fontsize=12)
    plt.ylim(0.9, 1.01)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.002, f'{yval:.3f}', ha='center', va='bottom', fontsize=11)
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('docs/images/eval_metrics.png', dpi=300)
    plt.close()

    # Plot 3: Trajectory Eval Metrics (EV2)
    traj_metrics = ['Adversarial\nSurvival', 'Legitimate\nSuccess']
    # Normalizing survival (lower is better, but we plot steps survived out of 50)
    # Actually, let's plot "Deterrence Rate" (1 - mean/50) and "Success Rate"
    deterrence = 1.0 - (data['trajectory_evals']['mean_steps_survived'] / 50.0)
    success_rate = data['trajectory_evals']['task_success_rate']
    
    plt.figure(figsize=(6, 5))
    bars2 = plt.bar(traj_metrics, [deterrence, success_rate], color=['#e74c3c', '#2ecc71'])
    plt.title('Trajectory Evaluation (EV2)', fontsize=14)
    plt.ylabel('Rate (0.0 to 1.0)', fontsize=12)
    plt.ylim(0.0, 1.1)
    for bar in bars2:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.02, f'{yval:.3f}', ha='center', va='bottom', fontsize=11)
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('docs/images/trajectory_metrics.png', dpi=300)
    plt.close()

    # Construct Markdown Tables
    md_content = f"""
### System Throughput & Latency

| Metric | Value |
|--------|-------|
| Sustained Event Rate | {data['throughput']['events_per_sec']:.1f} evt/sec |
| Event Drops (Backpressure) | {data['throughput']['drops']} |
| p50 Pipeline Latency | {data['throughput']['p50_ms']:.3f} ms |
| p95 Pipeline Latency | {data['throughput']['p95_ms']:.3f} ms |
| p99 Pipeline Latency | {data['throughput']['p99_ms']:.3f} ms |

### Static Golden Dataset Accuracies (EV1)

| Metric | Value |
|--------|-------|
| Precision | {data['evals']['golden_precision']:.3f} |
| Recall | {data['evals']['golden_recall']:.3f} |
| F1 Score | {data['evals']['golden_f1']:.3f} |
| False Positive Rate (FPR) | {data['evals']['golden_fpr']:.3f} |
| False Negative Rate (FNR) | {data['evals']['golden_fnr']:.3f} |
| Auto-Recall Precision | {data['evals']['auto_recall_precision']:.3f} |

### Stateful Trajectory Evaluation (EV2)

| Metric | Value |
|--------|-------|
| Adversarial Runs (N) | {data['trajectory_evals']['adversarial_runs']} |
| Mean Steps Survived | {data['trajectory_evals']['mean_steps_survived']:.2f} (Variance: {data['trajectory_evals']['variance_steps']:.2f}) |
| Legitimate Workflows Tested | {data['trajectory_evals']['legitimate_workflows']} |
| Over-Refusal Rate | {(data['trajectory_evals']['over_refusals'] / data['trajectory_evals']['legitimate_workflows']) * 100:.1f}% |
| Task Success Rate | {data['trajectory_evals']['task_success_rate'] * 100:.1f}% |

### Offline PRM Training Metrics

| Metric | Value |
|--------|-------|
| Labeled Steps Used | {data['prm']['labeled_steps_used']} |
| MLPR R² Score | {data['prm']['r2_score']:.4f} |

### Performance Visualizations
<br>
<div align="center">
  <img src="docs/images/ann_latency.png" alt="ANN Latency Graph" width="60%">
</div>
<br>
<div align="center">
  <img src="docs/images/eval_metrics.png" alt="Eval Metrics Graph" width="60%">
</div>
<br>
<div align="center">
  <img src="docs/images/trajectory_metrics.png" alt="Trajectory Metrics Graph" width="60%">
</div>
"""

    with open('README.md', 'r', encoding='utf-8') as f:
        readme = f.read()

    pattern = re.compile(r'<!-- METRICS_START -->.*?<!-- METRICS_END -->', re.DOTALL)
    new_readme = pattern.sub(f'<!-- METRICS_START -->\n{md_content}\n<!-- METRICS_END -->', readme)

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_readme)

if __name__ == '__main__':
    main()
