"""Local decision-model service for Agent SIEM.

One script, two roles (picked by BRAIN_BACKEND):
  laya  front door on 127.0.0.1:7811. Hosts Laya in-process and proxies backend="vega"
        requests to the Vega worker (the two models live in separate venvs).
  vega  worker on 127.0.0.1:7812. Hosts Vega in-process.

Endpoints (same on both):
  GET  /health -> {"ok": true, "backends": [...], "default": "..."}
  POST /decide {"state": any, "questions": {...}, "backend": "laya"|"vega"?}
       -> {"backend": "...", "answers": {...normalized...}, "ms": float}

Answers are normalized to one shape across backends:
  noul   {"type": "noul",   "p": float, "abstain": bool}
  choice {"type": "choice", "choice": str, "probabilities": {...}, "confidence": float, "abstain": bool}
  score  {"type": "score",  "score": float in 0..1, "abstain": bool}
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("BRAIN_BACKEND", "laya")
HOST = os.environ.get("BRAIN_HOST", "127.0.0.1")
PORT = int(os.environ.get("BRAIN_PORT", "7811" if ROLE == "laya" else "7812"))
VEGA_URL = os.environ.get("BRAIN_VEGA_URL", "http://127.0.0.1:7812")  # used by the laya role only
LAYA_DIR = os.environ.get("LAYA_DIR", "/Users/jarvis/laya_base/typed-decisions")
DEVICE = os.environ.get("BRAIN_DEVICE", "cpu")  # CPU beats MPS for both models at this size
MAX_BODY = 64 * 1024
TYPES = ("choice", "score", "noul")


class BadRequest(Exception):
    """Client error; carries an HTTP status (400 malformed, 413 too big, 422 bad question, 503 no backend)."""

    def __init__(self, msg, status=422):
        super().__init__(msg)
        self.status = status


def validate(questions):
    """Check the Jev-style question map before it reaches a model."""
    if not isinstance(questions, dict) or not questions:
        raise BadRequest("questions must be a non-empty object")
    for qid, q in questions.items():
        if not isinstance(q, dict) or q.get("type") not in TYPES:
            raise BadRequest("question %r: type must be one of %s" % (qid, ", ".join(TYPES)))
        if not isinstance(q.get("instructions"), str) or not q["instructions"].strip():
            raise BadRequest("question %r: instructions must be a non-empty string" % qid)
        crit = q.get("criteria")
        if q["type"] == "choice" and not (isinstance(crit, (list, dict)) and len(crit) >= 2):
            raise BadRequest("question %r: choice needs criteria with at least 2 options" % qid)
        if q["type"] == "score" and not (isinstance(crit, list) and len(crit) >= 2):
            raise BadRequest("question %r: score needs criteria as a list of >= 2 level descriptions" % qid)


def as_dict(crit):
    """Choice criteria may be a list of option names or {name: description}."""
    return {str(c): str(c) for c in crit} if isinstance(crit, list) else {str(k): str(v) for k, v in crit.items()}


# ---------------------------------------------------------------- Laya
class LayaBackend:
    name = "laya"

    def __init__(self):
        os.environ.setdefault("USE_TF", "0")  # avoids a TF/abseil deadlock noted in Laya's README
        import laya
        self.agent = laya.Agent(LAYA_DIR, device=DEVICE)

    def decide(self, state, questions):
        res = self.agent.system_one(state, questions)["answers"]
        out = {}
        for qid, q in questions.items():
            a = res[qid]
            if q["type"] == "noul":
                p = float(a["noul"])
                out[qid] = {"type": "noul", "p": round(p, 4), "abstain": 0.35 < p < 0.65}
            elif q["type"] == "choice":
                conf = float(a["confidence"])
                out[qid] = {"type": "choice", "choice": a["choice"], "probabilities": a["probabilities"],
                            "confidence": round(conf, 4), "abstain": conf < 0.35}
            else:  # score: Laya returns the expected level 0..k-1; rescale to 0..1
                k = len(q["criteria"])
                out[qid] = {"type": "score", "score": round(float(a["score"]) / (k - 1), 4),
                            "abstain": float(a.get("confidence", 1.0)) < 0.35}
        return out


# ---------------------------------------------------------------- Vega
def _patch_qwen_conv1d():
    """Qwen3.5's reference causal_conv1d_fn runs a grouped torch.conv1d that is pathologically slow
    on Apple Silicon CPU and MPS (~80% of request time, 10+ s per request). This shift-and-add
    version is numerically the same (max diff ~2e-6) and ~30x faster end to end."""
    import torch.nn.functional as F
    import transformers.models.qwen3_5.modeling_qwen3_5 as m
    from transformers.activations import ACT2FN

    def causal_conv1d_fn(hidden_states, weight, bias=None, activation=None, **_):
        x = hidden_states.to(weight.dtype)
        k, n = weight.shape[-1], x.shape[-1]
        xp = F.pad(x, (k - 1, 0))
        out = sum(xp[:, :, i:i + n] * weight[:, i, None] for i in range(k))
        if bias is not None:
            out = out + bias[:, None]
        if activation is not None:
            out = ACT2FN[activation](out)
        return out.to(hidden_states.dtype)

    m.causal_conv1d_fn = causal_conv1d_fn


class VegaBackend:
    name = "vega"

    def __init__(self):
        _patch_qwen_conv1d()
        import vegaml
        # token=False: never send an HF token; the 0.8B checkpoint is public and cached locally.
        self.v = vegaml.load(device=DEVICE, token=False)

    def decide(self, state, questions):
        vq = {}  # translate Jev-style questions into Vega's (noul -> boolean, list criteria -> dict)
        for qid, q in questions.items():
            if q["type"] == "noul":
                vq[qid] = {"type": "boolean", "instructions": q["instructions"],
                           "criteria": as_dict(q.get("criteria") or {"true": "yes", "false": "no"})}
            elif q["type"] == "choice":
                vq[qid] = {"type": "choice", "instructions": q["instructions"], "criteria": as_dict(q["criteria"])}
            else:
                vq[qid] = {"type": "score", "instructions": q["instructions"], "criteria": list(q["criteria"])}
        res = self.v.decide(state, vq)["answers"]
        out = {}
        for qid, q in questions.items():
            a, abstain = res[qid], bool(res[qid]["abstain"])
            if q["type"] == "noul":
                out[qid] = {"type": "noul", "p": round(float(a["boolean"]), 4), "abstain": abstain}
            elif q["type"] == "choice":
                out[qid] = {"type": "choice", "choice": a["choice"],
                            "probabilities": {k: round(float(p), 4) for k, p in a["probs"].items()},
                            "confidence": round(float(a["confidence"]), 4), "abstain": abstain}
            else:
                k = len(q["criteria"])
                exp = sum(int(lvl) * float(p) for lvl, p in a["probs"].items())
                out[qid] = {"type": "score", "score": round(exp / (k - 1), 4), "abstain": abstain}
        return out


# ---------------------------------------------------------------- service
LOCAL = (LayaBackend if ROLE == "laya" else VegaBackend)()  # load once at startup
LOCK = threading.Lock()  # torch inference is serialized; /health stays responsive


def vega_proxy(path, body=None, timeout=30):
    req = urllib.request.Request(VEGA_URL + path, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())


def vega_up():
    if ROLE != "laya":
        return False
    try:
        return vega_proxy("/health", timeout=1)[1].get("ok", False)
    except Exception:
        return False


def backends():
    return [LOCAL.name] + (["vega"] if vega_up() else [])


def default_backend(avail):
    want = os.environ.get("BRAIN_DEFAULT", "vega")  # Vega answered the smoke tests correctly; Laya did not
    return want if want in avail else avail[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "brain/1"

    def _send(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # one terse line per request on stderr
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    def do_GET(self):
        if self.path != "/health":
            return self._send(404, {"error": "not found"})
        avail = backends()
        self._send(200, {"ok": True, "backends": avail, "default": default_backend(avail)})

    def do_POST(self):
        if self.path != "/decide":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise BadRequest("body exceeds %d bytes" % MAX_BODY, 413)
            raw = self.rfile.read(n)
            try:
                req = json.loads(raw or b"null")
            except ValueError:
                raise BadRequest("body is not valid JSON", 400)
            if not isinstance(req, dict) or "state" not in req:
                raise BadRequest("body must be an object with state and questions", 400)
            validate(req.get("questions"))
            want = req.get("backend") or (default_backend(backends()) if ROLE == "laya" else LOCAL.name)
            if want not in ("laya", "vega"):
                raise BadRequest("backend must be laya or vega")
            t0 = time.perf_counter()
            if want == LOCAL.name:
                with LOCK:
                    answers = LOCAL.decide(req["state"], req["questions"])
            elif ROLE == "laya":  # forward to the Vega worker
                try:
                    status, out = vega_proxy("/decide", raw)
                except urllib.error.HTTPError as e:
                    return self._send(e.code, json.loads(e.read() or b"{}"))
                except Exception:
                    raise BadRequest("vega backend is not running", 503)
                answers = out["answers"]
            else:
                raise BadRequest("this worker only serves %s" % LOCAL.name, 503)
            self._send(200, {"backend": want, "answers": answers,
                             "ms": round(1000 * (time.perf_counter() - t0), 1)})
        except BadRequest as e:
            self._send(e.status, {"error": str(e)})
        except Exception as e:  # model or runtime failure
            self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


if __name__ == "__main__":
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("brain: %s ready on http://%s:%d" % (ROLE, HOST, PORT), flush=True)
    srv.serve_forever()
