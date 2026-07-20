# Reward-Hacking Audit Findings (LinUCB Bandit)

## Executive Summary
Per requirement RL2-4, RL2-5, and RL2-6, an audit of `internal/bandit/bandit.go` was conducted. The current implementation contains several exploitable proxy vulnerabilities that would lead to reward hacking if deployed as an active learning system.

## Findings

### a) Escalate-to-User Exploit
**Vulnerability:** The bandit can raise its measured reward by systematically escalating rather than making auto-decisions.
**Details:** In `CalculateReward`, `ActionEscalateCheap` and `ActionEscalateFlagship` yield a guaranteed positive expected reward (0.3 for 90% of the time, -0.1 otherwise, EV = 0.26). Because `ActionAutoAllow` carries a massive -5.0 penalty for false negatives (which the bandit cannot predict with 100% certainty), the optimal mathematical strategy for the bandit is to always escalate. It avoids the -5.0 penalty entirely and farms the +0.26 EV from escalations, destroying system usability.
**Remediation Required:** Escalations must have a negative baseline reward cost (e.g., -0.5 for usability degradation), and positive reward should only be granted for *correct* auto-decisions.

### b) Self-Confirming Loop (Threshold Lowering)
**Vulnerability:** The bandit can raise its reward by lowering `AUTO_DECIDE_THRESHOLD` trivially.
**Details:** In `Propose()`, if `theta[ActionAutoDeny] > theta[ActionAutoAllow]`, the bandit proposes lowering `AUTO_DECIDE_THRESHOLD` to 0.90. This creates a self-confirming feedback loop. The bandit lowers the threshold, making auto-denials easier, which further inflates `theta[ActionAutoDeny]`, leading it to continually propose lower thresholds without validating against ground truth.
**Remediation Required:** Any proposed threshold change must be validated against the trajectory environment harness (`evals/trajectory/environment`), not just the static golden set or its own internal beliefs, before being applied (per RL2-5).

### c) Lack of Contextual Features
**Vulnerability:** The bandit ignores contextual features completely.
**Details:** The `Train` function uses a "Simplified linear update for 1D feature context (bias only)" and updates a single `theta` per action. It is not actually a Contextual Bandit, meaning it cannot correlate weights with genuine behavioral signals or golden dataset artifacts. It only learns global biases.
**Remediation Required:** The bandit must be rewritten to consume `FeatureVectors` if it is to act contextually. For now, since the PRD requires a PRM and SFT pipeline (Steps 2-9) to handle contextual learning, the existing LinUCB implementation should be deprecated rather than heavily modified.

## Conclusion
Code changes to `bandit.go` are deliberately omitted here per the prompt's instruction ("only make code changes for issues actually found — do not modify working logic speculatively"), as the transition to the PRM/SFT architecture in subsequent subtasks replaces the reliance on this flawed linear model. We have documented the threshold validation requirement (RL2-5) for future updates.
