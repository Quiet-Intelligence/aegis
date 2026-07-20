# Personal Documentation

**Author:** PundarikakshNTripathi

## Project State (v2 Evolution)

The Aegis architecture has been fundamentally advanced in the v2 evolution (Steps 8-10):

### 1. Evaluation & Trajectory Layer
- We implemented a stateful trajectory harness for offline execution of adversarial tests.
- Single-run evaluations have been deprecated in favor of N-run distribution tracking, allowing us to evaluate the variance of LLM adjudicators.
- We added rigorous Over-Refusal tracking against benign developer workflows.

### 2. PRM, SFT, and Active Learning
- The previous LinUCB offline bandit implementation was audited and found vulnerable to reward hacking (Escalate-to-user exploit, threshold self-confirmation loops, and missing contextual mapping).
- We scaffolded a Process Reward Model (PRM) to score step-level transitions in trajectories.
- We built an extraction tool and a LoRA/QLoRA fine-tuning script to construct a local SFT (Supervised Fine-Tuning) tier using open-weight models (e.g., Llama-3 8B).
- An active learning review queue has been exposed via `aegisctl review queue` for human-in-the-loop validation of low-confidence PRM traces.

### 3. Formal Policy Modeling (AWS Cedar)
- The existing SQLite schema for `policy_entries` has been modeled into an AWS Cedar Entity schema (`Repo`, `Event`).
- We built a native Go mock evaluator for Cedar validation and created a compiler (`cedar.CompileToBPF`) to translate formal ABAC Cedar declarative logic straight down to eBPF hash-maps.
- Continuous Integration pipelines were added to statically validate `.cedar` policies for logical consistency prior to deployment.

## Issues to Address Later
- The cross-platform WASM sandbox features (Step 5 of PRD) have been explicitly deferred based on team prioritization.
- Outstanding GitHub issues reported in previous cycles remain open and will require resolution in a subsequent pass.
- We need to merge the feature branches (`feature/trajectory-evals`, `feature/learning-architecture`, `feature/policy-cedar`) back into `develop`.
