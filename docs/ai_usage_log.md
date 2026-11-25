# AI usage log

Keep an honest record of how AI was used and where it was wrong. Interviewers value this more than a perfect story.

| # | Task | Tool / prompt summary | AI output | What I verified | What was wrong or changed |
|---|------|-----------------------|-----------|-----------------|---------------------------|
| 1 | Draft SPL for password spraying | | | Ran it against S2 data | |
| 2 | Explain Sysmon Event ID 22 fields | | | Checked against Sysmon docs | |
| 3 | Triage summary of Detection 04 | `ai_triage.py` | | Compared with raw 4104 events | |

## Guardrails I applied
- Lab data only; sanitised before sending to the LLM and a local model (Ollama) so nothing leaves the machine (see `redact()` in `ai/ai_triage.py`).
- AI output is a draft. The analyst verifies it against raw logs and makes the final call.
- No API keys in the repo (`.env` is git-ignored).
- Measured quality: AI-drafted queries that needed fixes: __ of __.
