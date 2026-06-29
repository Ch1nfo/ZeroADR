# ZeroADR Agent Security Bench Companion

Independent evaluation package for running the official ICLR 2025 Agent Security Bench corpus
against ZeroADR. The upstream ASB source is cloned privately and pinned to commit
`1f561dccf92d55302368fa67679b4ba9d9c8fdc4`; it is not bundled in this distribution.

```bash
conda run -n agent zeroadr-asb prepare
conda run -n agent zeroadr-asb manifest --attack-cases 100 --paired-clean
conda run -n agent zeroadr-asb benchmark --arms baseline,rules,hybrid --resume
```

Memory Poisoning results are conditioned on successful poisoned-memory retrieval. All generated
artifacts are private under `.zeroadr/evaluations/asb/`.
