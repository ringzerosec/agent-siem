# brain: local decision-model service

A small HTTP service that lets the Agent SIEM Node app ask a local, calibrated decision model typed
questions (yes/no, pick-one, 0-1 score) instead of sending data to OpenAI. Nothing leaves the machine
at runtime: `run.sh` sets `HF_HUB_OFFLINE=1` and unsets any HF token.

Two backends:

| backend | model | process | venv |
|---|---|---|---|
| `laya` | Laya `typed-decisions` checkpoint (`/Users/jarvis/laya_base/typed-decisions`, ModernBERT-large, 421M) | front door, `127.0.0.1:7811` | `/Users/jarvis/laya-venv` |
| `vega` | Vega 0.8B (`vegaml` 0.9.0: frozen Qwen3.5-0.8B reader + 14M-param engine, Apache-2.0) | worker, `127.0.0.1:7812` | `brain/.venv-vega` (Python 3.12) |

The two models live in separate venvs, so they run as two processes. `serve.py` on 7811 hosts
Laya and forwards `"backend":"vega"` requests to 7812. Both processes run the same `serve.py`, and
`BRAIN_BACKEND` picks the role. **The default backend is `vega`** when the worker is up (it answered
the smoke tests far better; see below). Set `BRAIN_DEFAULT=laya` to change it. If Vega is down,
the service falls back to Laya.

## Run

```bash
/Users/jarvis/rgs/graph-watch/brain/run.sh          # both backends; Ctrl-C stops both
BRAIN_NO_VEGA=1 /Users/jarvis/rgs/graph-watch/brain/run.sh   # Laya only
python3 /Users/jarvis/rgs/graph-watch/brain/smoke.py         # in another shell
```

Startup takes about 5 s for Laya and about 15 s for Vega once the weights are cached.

## API

`GET /health` returns `{"ok": true, "backends": ["laya","vega"], "default": "vega"}`

`POST /decide` (the body must be 64 KB or smaller)

```json
{"state": <any JSON or string>,
 "questions": {
   "is_llm":   {"type": "noul",   "instructions": "Is this request a call to an LLM API?"},
   "priority": {"type": "choice", "instructions": "How urgent?", "criteria": ["ignore","review this week","investigate today","respond now"]},
   "severity": {"type": "score",  "instructions": "How severe?", "criteria": ["low","medium","high"]}},
 "backend": "laya" | "vega"}          // optional
```

The response:

```json
{"backend": "vega", "ms": 539.0, "answers": {
  "is_llm":   {"type": "noul",   "p": 0.9999, "abstain": false},
  "priority": {"type": "choice", "choice": "investigate today", "probabilities": {...}, "confidence": 0.45, "abstain": true},
  "severity": {"type": "score",  "score": 0.56, "abstain": true}}}
```

* `choice` criteria may be a list of names or a `{name: description}` map.
* `score` is the expected level rescaled to the range 0 to 1.
* For Vega, `abstain` is the engine's own flag (from conformal prediction sets).
* Laya has no abstain flag, so the service sets one:
  * `choice` abstains when `confidence < 0.35`. This is Laya's normalized confidence, not the top probability.
  * `noul` abstains when `0.35 < p < 0.65`.
  * `score` abstains when `confidence < 0.35`.
* The errors are JSON `{"error": "..."}`:
  * 400: malformed JSON or body
  * 404: unknown path
  * 413: body larger than 64 KB
  * 422: bad question or bad backend name
  * 503: Vega was requested but is not running
  * 500: model failure

## Measured on this Mac (Apple M5, 32 GB, CPU)

| | Laya typed-decisions | Vega 0.8B |
|---|---|---|
| warm latency, 3 questions batched (median of 5) | **265 ms** | **539 ms** |
| warm latency, 1 question | 70-120 ms | 210-300 ms |
| first request after start | ~440 ms | ~940 ms |
| memory (phys_footprint of the process) | ~2.0 GB | ~3.4 GB |
| weights on disk | 0.84 GB (already present) | ~1.8 GB Qwen3.5-0.8B + 57 MB engine (HF cache) |

Both models run on **CPU**, which is faster than MPS here. On MPS, Laya took 590 ms for 3 questions
against 206 ms on CPU, and Vega was even slower on MPS.

### Vega needed one fix

Out of the box, Vega took **4 to 15 s per request** on both CPU and MPS. That fails the 2 s budget.

Profiling found the cause: about 80% of the time went into one `torch.conv1d` call. This is the
grouped (depthwise) conv in transformers' reference `causal_conv1d_fn` for Qwen3.5. It is the
fallback used when the CUDA-only `causal_conv1d` kernel is missing.

`serve.py` replaces that function at startup with a shift-and-add version:

* It is numerically equivalent (max difference about 2e-6).
* It brings a request down to the 210-540 ms above.

The patch is in `_patch_qwen_conv1d()` and does not modify any installed package.

Other notes on Vega:

* The system `python3` is 3.9, and `vegaml` needs Python 3.10 or newer. The venv therefore uses
  `/Users/jarvis/.local/bin/python3.12`.
* Laya's README suggests the `laya` Python package with `laya.Agent(path)`. The service loads the
  local checkpoint directory that way, offline.

## Smoke test results (smoke.py)

| case | expected | Laya | Vega |
|---|---|---|---|
| a1 LLM-gateway request (`/v1/chat/completions`, SSE, `messages`) | yes | p=0.637, abstains | **p=1.000** |
| a2 GitHub issues API | no | p=0.628, abstains | **p=0.003** |
| b1 two exfil attempts (ssh key to webhook.site, aws creds to requestbin.net) | yes | p=0.258 (wrong) | p=0.015 (wrong) |
| b2 exfil compared with `sudo apt install` | no | p=0.283 | **p=0.002** |
| c1 credential exfil finding, priority | investigate/respond | "investigate today", conf 0.08, abstains | **"investigate today"** (0.45 / respond 0.33), abstains |
| c2 `apt install ripgrep`, priority | ignore/review | "review this week", conf 0.03, abstains | **"review this week"** (0.475), abstains |

**What the results show:**

* **Vega is usable for shadow-AI classification and triage.** It is confident and correct on a1, a2
  and b2. On priority it picks a sensible level and honestly abstains between neighbouring levels.
* **Laya (typed-decisions) is not discriminating on these prompts.** It gives about 0.63 for both
  a1 and a2, and about 0.27 for both b1 and b2. The abstain gate catches the first pair, but the
  second pair is a confident wrong "no".
* The base Laya checkpoint (`/Users/jarvis/laya_base`) is worse. It gave p=1.0 that the GitHub call
  is an LLM call. This is the label-following problem its README describes. That is why
  typed-decisions is the Laya default.
* **Same-actor linking (b1) fails on both backends with the generic question.** Vega gets it right
  when the question names the behaviour: "Do both findings show credential theft followed by an
  upload attempt to an external request-capture service?" gave 0.977 on the positive pair and
  0.080 on the negative pair.
* For linking, ask about the concrete shared technique, not "same attacker playbook".
  Alternatively, fit a Vega TTT head (`v.fit`, at least 6 labelled examples) on our own findings.
  The same applies to anything abstract.
