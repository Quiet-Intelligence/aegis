# Trajectory Evals Held-Out Set (EV2-7)

This directory is the strict **contamination-controlled held-out set** for trajectory evaluations. 

## Structural Boundary
To ensure the adversarial generator (`generator.go`) and the temporal graph scorer are never unintentionally tuned against each other, the adversarial scenarios stored in this directory are mathematically isolated.

1. **No simultaneous PRs:** CI enforces that Pull Requests cannot modify both `pkg/graph/scorer.go` and the `evals/trajectory/heldout` test corpus in the same commit.
2. **True generalization:** The PRM and LinUCB bandit algorithms are ONLY benchmarked against these held-out trajectories *after* their hyperparameters are locked.

Any modifications to this folder require explicit approval from the Evals maintainer to prevent data leakage.
