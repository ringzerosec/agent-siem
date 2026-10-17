// brain.js — the local decision model (Vega, or Laya) as a second intelligence
// over the graph. Calibrated typed answers, run on this machine (brain/serve.py);
// nothing is sent to an outside AI provider. Optional: if the service is not
// running, every call returns null and the console works as before.
//
//   BRAIN_URL=http://127.0.0.1:7811   (default)   BRAIN=off to disable

const URL = process.env.BRAIN_URL || 'http://127.0.0.1:7811';
const OFF = process.env.BRAIN === 'off';
let down = 0;   // back off for a minute after a failure

export async function decide(state, questions, { timeout = 4000, backend } = {}) {
  if (OFF || Date.now() < down) return null;
  try {
    const r = await fetch(`${URL}/decide`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ state, questions, ...(backend ? { backend } : {}) }), signal: AbortSignal.timeout(timeout) });
    if (!r.ok) throw new Error(`brain ${r.status}`);
    return await r.json();
  } catch { down = Date.now() + 60_000; return null; }
}
export async function brainHealth() {
  try { const r = await fetch(`${URL}/health`, { signal: AbortSignal.timeout(1500) }); return r.ok ? await r.json() : null; } catch { return null; }
}

export const TECHNIQUES = [
  'credential theft then upload to an external paste or request-capture site',
  'credential or data sent to an unapproved AI service',
  'poisoned skill, plugin or instruction file steering the agent',
  'tool call to an untrusted MCP server',
  'vulnerable or untrusted package installed',
  'privilege escalation',
  'persistence or tampering with the security agent',
  'benign or unclear activity',
];
export const PRIORITIES = ['ignore', 'review this week', 'investigate today', 'respond now'];

// One finding -> technique + priority, in one forward pass.
export async function classifyFinding(f) {
  const state = { finding: f.title, details: f.summary, severity: f.severity, blocked_by_enforcement: f.blocked === true, threat_category: f.threat };
  const res = await decide(state, {
    technique: { type: 'choice', instructions: 'Which attack technique does this security finding show?', criteria: TECHNIQUES },
    priority: { type: 'choice', instructions: 'How urgently should a security engineer act on this finding?', criteria: PRIORITIES },
  });
  if (!res) return null;
  const t = res.answers?.technique, p = res.answers?.priority;
  return { technique: t?.choice, technique_p: t?.confidence, technique_abstain: !!t?.abstain, priority: p?.choice, priority_p: p?.confidence, priority_abstain: !!p?.abstain, backend: res.backend, ms: res.ms };
}

// Two findings on different endpoints -> same concrete playbook? (Asked about
// the technique, not "the same attacker": the models answer the concrete
// question far better.)
export async function samePlaybook(a, b, technique) {
  const res = await decide({ finding_a: `${a.title}: ${a.summary}`, finding_b: `${b.title}: ${b.summary}` }, {
    same: { type: 'noul', instructions: `Do both findings show ${technique}?` },
  });
  const ans = res?.answers?.same;
  return ans ? { p: ans.p, abstain: !!ans.abstain, backend: res.backend } : null;
}

// Borderline shadow-AI fingerprint -> is this an LLM API call?
export async function isLlmCall(req) {
  const res = await decide({ host: req.host, path: req.path, accept: req.accept, content_type: req.content_type, body_keys: req.body_keys, req_headers: req.req_headers, resp_content_type: req.resp_content_type, resp_keys: req.resp_keys },
    { is_llm: { type: 'noul', instructions: 'Is this request a call to a large language model API?' } }, { timeout: 1500 });
  const a = res?.answers?.is_llm;
  return a ? { p: a.p, abstain: !!a.abstain, backend: res.backend } : null;
}
