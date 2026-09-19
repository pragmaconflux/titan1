# Local AI Analyst (Milestone 8)

The Local AI Analyst explains what Titan's deterministic engine already
found. It never performs decoding, detection, attribution, or enrichment,
and it never invents evidence.

```bash
titan analyst --report report.json --ask "Why is this High Risk?"
```

## Grounding architecture

1. Titan loads one or more completed structured reports (files or
   directories).
2. An immutable **evidence ledger** assigns stable references to nodes,
   intelligence signals, detections, IOCs, ATT&CK techniques, risk facts,
   and Phase 5 correlation results. IDs are deterministic across runs
   (e.g. `node:1`, `detection:TITAN-003`, `ioc:domains:<digest>`); when
   several reports are loaded, naturally-colliding IDs gain a report
   ordinal (`node:0:1` vs `node:1:1`), while content-hashed IOC IDs stay
   shared so the same indicator carries the same citation everywhere.
3. A deterministic **question planner** maps the question to an intent and
   selects a bounded, relevance-ranked evidence subset — the model never
   chooses its own evidence.
4. The optional local model receives only that subset (trimmed by whole
   items so the context is always valid JSON).
5. **Every factual claim must cite ledger references, and the cited
   evidence must support it.** An answer is rejected when a citation does
   not resolve, when a factual line carries no citation (prose as much as
   bullets), or when a line asserts a concrete indicator — address, domain,
   URL, hash, rule id, ATT&CK technique — that does not appear in the
   evidence that line cites. Checking only that a citation resolves would
   accept "exfiltrates credentials to 10.0.0.5 [node:0]" whenever `node:0`
   exists, whatever it actually contains.
6. Backend errors and rejected answers fall back to the deterministic
   answer — model failure never removes analyst output. The structured
   response records `fallback_used` and `validation_errors`
   (`local-ai-analyst-response-v1.0`,
   `schemas/local-ai-analyst-response-v1.0.schema.json`).

## Supported questions

The deterministic planner routes (at least) the milestone examples:

- "Why is this High Risk?"
- "Show every decoded PowerShell stage."
- "Explain the decoding chain."
- "Which IOC caused this detection?"
- "Which MITRE techniques apply?"
- "Summarize this investigation."
- "Compare this sample to previous cases." (uses Phase 5 relationships,
  attribution hints, and shared IOCs across loaded reports)
- "Suggest evidence-backed next steps."

Anything else falls through to a general evidence summary.

## Backends

The **deterministic backend is the default and needs no model**: answers
are built directly from the ledger with citations. This is also the
guaranteed fallback.

The first model backend is an OpenAI-compatible local HTTP endpoint
(llama.cpp's server and similar local runtimes):

```bash
titan analyst --report report.json \
  --backend local-openai \
  --endpoint http://127.0.0.1:8080/v1/chat/completions \
  --model local-model \
  --ask "Summarize this investigation."
```

Run without `--ask` for an interactive session; add `--json` for the
structured response.

## Safety model

- **Optional and off by default** — nothing AI-related runs unless
  `titan analyst` is launched with `--backend local-openai`.
- **Loopback-only by default** — non-loopback endpoints are refused unless
  `--allow-remote-endpoint` is passed explicitly, which prints a warning
  that ledger evidence will leave the host. There is no autonomous network
  access of any kind.
- **Bounded** — evidence count, context characters, output tokens, request
  timeout, and response size are all capped; temperature is 0 for
  reproducibility.
- **Facts stay separate from inference** — factual lines carry citations;
  the model is instructed to prefix speculation with `Inference:`. Labeled
  inference may go uncited, but it may not introduce an indicator that
  appears nowhere in the ledger, so the label is not a route around
  grounding.
- **No evidence means no factual answer** — an empty selection yields
  "Titan did not record evidence that answers this question."

### Untrusted report content

Ledger values include decoded payload previews, which are
attacker-controlled and may contain prompt-injection text aimed at the
model. The containment is structural, not behavioral: the model has no
tools and no network, its output is plain text, and that text is only
accepted if every factual bullet cites real ledger entries. A manipulated
answer at worst fails validation and is replaced by the deterministic
answer — this path is covered by a regression test.

## Response contract

```json
{
  "schema_version": "local-ai-analyst-response-v1.0",
  "question": "Why is this High Risk?",
  "answer": "- Risk risk level: HIGH [risk:...]",
  "intent": "explain_risk",
  "backend": "deterministic",
  "model": "none",
  "evidence_ids": ["risk:...", "detection:TITAN-003"],
  "fallback_used": true,
  "validation_errors": []
}
```
