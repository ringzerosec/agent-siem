"""Smoke test: realistic security questions against the running brain service, on every backend.

Usage: python3 brain/smoke.py [http://127.0.0.1:7811]   (standard library only)
"""
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7811"

LLM_Q = {"is_llm": {"type": "noul", "instructions": "Is this request a call to a large language model API?"}}
SAME_Q = {"same_actor": {"type": "noul", "instructions": "Do these two incidents look like the same attacker playbook?"}}
PRIO_Q = {"priority": {"type": "choice", "instructions": "How should the security team prioritise this finding?",
                       "criteria": ["ignore", "review this week", "investigate today", "respond now"]}}

EXFIL_A = ("laptop-17: agent read ~/.ssh/id_ed25519, wrote it into docs/diagram.md, "
           "then curl tried to upload to webhook.site (refused)")
CASES = [
    ("a1 shadow-AI, LLM gateway (expect yes)",
     {"host": "llm-gw.internal.corp", "path": "/v1/chat/completions", "content_type": "application/json",
      "accept": "text/event-stream", "body_keys": ["model", "messages", "max_tokens", "stream", "temperature"]}, LLM_Q),
    ("a2 shadow-AI, GitHub issues (expect no)",
     {"host": "api.github.com", "path": "/repos/x/y/issues", "body_keys": ["title", "body", "labels"]}, LLM_Q),
    ("b1 same actor, two exfil attempts (expect yes)",
     {"finding_A": EXFIL_A,
      "finding_B": "laptop-42: agent read ~/.aws/credentials, then curl tried to upload to requestbin.net (refused)"}, SAME_Q),
    ("b2 same actor, exfil vs apt install (expect no)",
     {"finding_A": EXFIL_A, "finding_B": "laptop-42: agent ran sudo apt install ripgrep"}, SAME_Q),
    ("c1 priority, credential exfil (expect investigate/respond)",
     {"finding": EXFIL_A, "severity_hint": "credential access + egress to paste/webhook service",
      "outcome": "upload blocked by egress policy"}, PRIO_Q),
    ("c2 priority, package install (expect ignore/review)",
     {"finding": "laptop-42: agent ran sudo apt install ripgrep", "outcome": "allowed"}, PRIO_Q),
]


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


health = call("GET", "/health")
print("health:", json.dumps(health))
for backend in health["backends"]:
    print("\n=== backend: %s ===" % backend)
    for label, state, q in CASES:
        out = call("POST", "/decide", {"state": state, "questions": q, "backend": backend})
        (qid, a), = out["answers"].items()
        if a["type"] == "noul":
            ans = "p(yes)=%.3f" % a["p"]
        else:
            ans = "%s (conf %.2f) %s" % (a["choice"], a["confidence"], a["probabilities"])
        print("%-58s %s%s  [%.0f ms]" % (label, ans, "  ABSTAIN" if a["abstain"] else "", out["ms"]))
    # warm latency, three questions batched in one request
    batch = dict(LLM_Q, **SAME_Q, **PRIO_Q)
    ms = [call("POST", "/decide", {"state": CASES[4][1], "questions": batch, "backend": backend})["ms"]
          for _ in range(5)]
    print("warm latency, 3 questions batched: median %.0f ms (runs: %s)" % (sorted(ms)[2], ms))
