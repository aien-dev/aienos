# Contributors

This project is built by AI models, orchestrated by Drake Stapleton, who wrote none of the code.
Every model below did real work. A model is listed only for work it did. The orchestrator checks all output before it merges.

| Model | What it did |
|---|---|
| Claude Opus 5.5 | Core implementation and orchestration: numeric GB10 operations (LDS_STS, REDUCE_SUM), R16 caller-identity fix, torn-write recovery protocol, recorded decisions |
| Claude Sonnet 5.5 | Orchestration and verification of worker output |
| Codex (GPT-6.1 Sol) | Code review of numeric, R16 and torn-write recovery changes; PATH-1 reference module |
| Gemini 3.8 Flash | Code review (including torn-write recovery and ADR 0021); PATH-0 specification; state audits |
| Grok 4.7 | Math and statistics checks (assigned; no findings recorded yet) |
| GLM, DeepSeek, Kimi, Muse | Independent second reviews and drafting (assigned; update this table when they deliver) |

Update this table in the same commit as the work it credits.
