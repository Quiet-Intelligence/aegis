import re

with open("README.md", "r") as f:
    content = f.read()

# Fix TOC
toc_old = """- [10. Current Project Status](#10-current-project-status)
- [11. Limitations and Future Work](#11-limitations-and-future-work)
- [12. Debugging and Troubleshooting](#12-debugging-and-troubleshooting)
- [13. Support and Maintenance](#13-support-and-maintenance)
- [14. Contribution Guidelines](#14-contribution-guidelines)
- [15. License Disclaimer](#15-license-disclaimer)
- [16. Citation Guide](#16-citation-guide)"""

toc_new = """- [10. Current Project Status](#10-current-project-status)
- [11. System Evaluation (Post-Mortem)](#11-system-evaluation-post-mortem)
- [12. Limitations and Future Work](#12-limitations-and-future-work)
- [13. Future Work: eBPF CO-RE Integration](#13-future-work-ebpf-co-re-integration)
- [14. Debugging and Troubleshooting](#14-debugging-and-troubleshooting)
- [15. Support and Maintenance](#15-support-and-maintenance)
- [16. Contribution Guidelines](#16-contribution-guidelines)
- [17. License Disclaimer](#17-license-disclaimer)
- [18. Citation Guide](#18-citation-guide)"""

content = content.replace(toc_old, toc_new)

# Update Status
status_old = """## 10. Current Project Status

**Final Integration (Done).** Aegis has successfully passed all 7 build phases defined in the Unified PRD.
The system successfully intercepts eBPF telemetry, constructs temporal graphs, correctly cascades low/high-risk LLM verification, caches embeddings via SQLite, offline-trains the contextual bandit, and enforces a strict fail-closed backpressure protocol under DoS loads."""

status_new = """## 10. Current Project Status

**Final Integration (Done).** Aegis has successfully passed all 7 build phases defined in the Unified PRD.
The system successfully intercepts eBPF telemetry, constructs temporal graphs, correctly cascades low/high-risk LLM verification, caches embeddings via SQLite, offline-trains the contextual bandit, and enforces a strict fail-closed backpressure protocol under DoS loads.

**Recent Comprehensive Upgrades:**
- **Live Terminal UI (TUI):** A fully live control-plane view tailing `audit.jsonl` decisions with model rationales, vector similarities, and dynamic container scope metrics (replacing the old scripted demo).
- **Synchronous Execution Gate:** A seccomp user-notification supervisor holds container execs for explicit approval, preventing zero-day exec escapes synchronously.
- **Workspace-only Policies & Live Decisions:** Enforces strict workspace-only writes. Denied file/exec paths are applied directly to the kernel for instantaneous live blocking.
- **Robust Adjudication:** The LLM adjudicator now uses exact `path+argv+rule+SHA-256` recall. This prevents malicious modified binaries from inheriting a previously cached benign decision.
- **Provider Registry:** A unified `providers.json` configures and masks keys for OpenAI, OpenRouter, Groq, Together, and Ollama.
- **eBPF Retargeting:** Real-time capture of command `argv` from syscall tracepoints, with live cgroup retargeting and a robust LSM backstop for ungated execs."""

content = content.replace(status_old, status_new)

# Limitations and debugging update
limitations_text = """2. **eBPF Target Compilation:** Because Aegis relies on specific kernel structs, distributing a raw `.exe` or `.deb` across diverse Linux kernels is brittle without local compilation.
3. **Online Learning:"""

limitations_new = """2. **eBPF Target Compilation:** Because Aegis relies on specific kernel structs, distributing a raw executable across diverse Linux kernels requires local compilation. This will be fully resolved once CO-RE is implemented.
3. **Online Learning:"""

content = content.replace(limitations_text, limitations_new)

with open("README.md", "w") as f:
    f.write(content)

print("README updated.")
