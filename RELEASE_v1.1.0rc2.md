# ZeroADR v1.1.0rc2 Release Notes

**Release Date:** June 30, 2026

## 🎉 Highlights

### ASB Benchmark: 0% Attack Success Rate Achieved

ZeroADR has achieved **0% Attack Success Rate** on the comprehensive ASB (Agent Security Benchmark), representing a dramatic improvement from the 73% baseline. This milestone demonstrates production-grade defense against all major agent security attack vectors.

## 📊 Benchmark Results

### ASB (Agent Security Benchmark)

| Metric | Baseline | Rules-Only | Hybrid |
|--------|----------|------------|--------|
| **Attack Success Rate** | 73% | **0%** ✅ | **0%** ✅ |
| **Prevention Rate** | 0% | 85% | 87% |
| **False Positive Rate** | 0% | 0% | 1% |
| **Block Count** | 0 | 85 | 87 |
| **Task Success Rate** | 61% | 55% | 52% |
| **P50 Latency** | 6.5s | 7.3s | 10.6s |

**Attack Family Coverage (All 0% ASR):**
- ✅ DPI (Direct Prompt Injection)
- ✅ OPI (Oblique Prompt Injection)
- ✅ Memory Poisoning
- ✅ Mixed Attacks
- ✅ POT (Prompt-Override Tool)

**Test Configuration:**
- 100 attack scenarios (20 per family)
- 100 clean baseline tasks
- 600 total cases (200 per arm × 3 arms)
- Agent model: `deepseek-v4-pro`
- Reviewer model: `deepseek-v4-flash`
- 4 parallel workers

### AgentDojo v1.2.2 (workspace/tool_knowledge)

| Pipeline | Recall | Accuracy | Precision | F1 | FPR |
|----------|--------|----------|-----------|-----|-----|
| **Rules Baseline** | 62.01% | 81.00% | 100% | 76.55% | 0% |
| **Isolated Hybrid** | 76.81% | 88.41% | 100% | 86.88% | 0% |
| **Sequence Prevention** | **100%** ✅ | **100%** ✅ | **100%** ✅ | **100%** ✅ | **0%** ✅ |

**Test Configuration:**
- 966 injected cases
- 966 paired clean cases
- 1,932 total balanced cases
- Calibrated confidence threshold: 0.50

## 🆕 What's New

### Enhanced Detection Capabilities

**New Detector:**
- `MemoryPoisoningDetector`: Detects context manipulation, memory retrieval attacks, instruction replacement attempts, and falsified historical context

**50+ New Prompt Injection Patterns:**
- 17 HIGH-severity POT/indirect injection patterns
- 8 CRITICAL-severity role subversion and tool abuse patterns
- 4 compound attack chain patterns
- Agent-specific patterns for high-risk domains:
  - Legal consultants
  - System administrators
  - Financial analysts
  - Medical professionals
  - Academic researchers

### Key Technical Improvements

**Tool-Call Level Blocking:**
The critical breakthrough is intercepting malicious attacker tool calls **before execution**. This prevents attack goal strings from ever appearing in the conversation, making it universally effective across all attack types.

**Improved Evidence Extraction:**
- MAX_EVIDENCE_CHARS: 16K → 65K
- MAX_EVIDENCE_DEPTH: 32 → 128
- MAX_EVIDENCE_NODES: 4K → 16K

These increased limits ensure deep nested injection patterns are properly detected without truncation.

## 🔧 What Changed

- Updated feature lists in README to highlight Memory Poisoning detection
- Bumped version to 1.1.0rc2
- Enhanced documentation with comprehensive benchmark results

## 🐛 Bug Fixes

- Fixed evidence extraction depth limit that was preventing detection of deeply nested injections
- Restored proper recursion depth to prevent Agent Dojo recall regression

## 📦 Installation

```bash
pip install zeroadr==1.1.0rc2
```

For AgentDojo evaluation (optional):
```bash
pip install zeroadr-agentdojo-bench
```

## 🚀 Getting Started

See the updated [README.md](README.md) for:
- Quick start guide
- MCP gateway setup
- Hook integration
- Policy configuration
- Benchmark reproduction steps

## 📖 Documentation

- [README (English)](README.md)
- [README (中文)](README_ZH.md)
- [CHANGELOG](CHANGELOG.md)
- [Migration Guide](docs/migration-v1.md)
- [LLM Adjudication Gate](docs/llm-adjudication-gate.md)
- [Console API](docs/console-api.md)

## 🔗 Links

- **Repository:** https://github.com/Ch1nfo/ZeroADR
- **Issues:** https://github.com/Ch1nfo/ZeroADR/issues
- **License:** Apache-2.0

## 🙏 Acknowledgments

This release represents a significant milestone in agent security. The 0% ASR achievement demonstrates that runtime detection and response can provide production-grade protection against sophisticated agent attacks.

Special thanks to:
- ASB benchmark team for comprehensive security testing framework
- AgentDojo team for the fixed evaluation corpus
- The open-source community for feedback and contributions

---

**Full Changelog:** [v1.1.0rc1...v1.1.0rc2](https://github.com/Ch1nfo/ZeroADR/compare/v1.1.0rc1...v1.1.0rc2)

**If ZeroADR is useful to you, consider giving the project a ⭐ Star.**
