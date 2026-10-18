// adapter-rzs.js — pull real activity from installed Ring Zero Security daemons
// and feed it to the graph. One daemon = one device on the wall.
//
//   RZS=ENG-MBP-0142=http://localhost:7700,build-vm=http://10.0.0.5:7700 node src/adapter-rzs.js
//   RZS_TOKEN=...   bearer token if the daemon API requires one
//   RZS_TOKEN_ENG_MBP_0142=...   per-device token (device id with - → _)
//   RZS_TEAM_ENG_MBP_0142="Platform Engineering"   team shown on the tile (default: daemon user)
//   RZS_POLL_MS=2000
//   RZS_SINCE_HOURS=24  skip sessions that ended before this window
//
// What it reads from each daemon (all read-only GETs):
//   /api/v1/sessions                 agent sessions (id, agent_type, actor, state)
//   /api/v1/sessions/:id/events      the kernel + proxy events of that session
//   /api/v1/sessions/:id/commentary  the daemon's plain-English narrative
//   /api/v1/discovery/inventory      MCP servers declared in agent configs
//   /api/v1/events?limit=1000        fallback when sessions carry no events
//
// Daemon event kinds (snake_case) → graph kinds:
//   file_open → read            file_write/file_create/file_rename → write
//   file_delete → delete        process_exec → exec     process_fork → spawn
//   network_connect → connect   network_send → send     dns_query → dns
//   mcp_tool_call → tool        llm_request/llm_response/llm_tool_call → prompt
//   proxy_block/proxy_detection/dlp_pii → connect (allowed=false, reason)
//   tamper_* → tamper           contained_exec_blocked → exec (refused)
//   contained_file_blocked → read (refused)     offensive_prompt → prompt (flagged)

// Shared access token for the SIEM API (src/auth.js): SIEM_TOKEN, or the one
// the server generated in data/siem-token.
import { readFileSync } from 'node:fs';
const SIEM_TOKEN = process.env.SIEM_TOKEN || (() => { try { return readFileSync(new URL('../data/siem-token', import.meta.url), 'utf8').trim(); } catch { return ''; } })();
const AUTH = SIEM_TOKEN ? { authorization: `Bearer ${SIEM_TOKEN}` } : {};
const API = process.env.API || 'http://localhost:8080';
const POLL = Number(process.env.RZS_POLL_MS || 2000);
const TOKEN = process.env.RZS_TOKEN || '';
const SINCE_H = Number(process.env.RZS_SINCE_HOURS || 24);

const targets = (process.env.RZS || 'local=http://localhost:7700').split(',').map((s) => {
  const [device, url] = s.includes('=') ? s.split('=') : [s.replace(/https?:\/\//, '').split(':')[0], s];
  return { device: device.trim(), url: url.trim().replace(/\/$/, '') };
});

// Token per device: RZS_TOKEN_<device with - as _> wins over RZS_TOKEN.
function headersFor(device) {
  const t = process.env[`RZS_TOKEN_${device.replace(/[^A-Za-z0-9]/g, '_')}`] || TOKEN;
  return t ? { authorization: `Bearer ${t}` } : {};
}
// Full-scope token for enforcement (block/contain). Separate from the
// read-only token used for polling: without it, actions are left queued.
const ADMIN_TOKEN = process.env.RZS_ADMIN_TOKEN || '';
function adminHeadersFor(device) {
  const t = process.env[`RZS_ADMIN_TOKEN_${device.replace(/[^A-Za-z0-9]/g, '_')}`] || ADMIN_TOKEN;
  return t ? { authorization: `Bearer ${t}`, 'content-type': 'application/json' } : null;
}

// Actuator: apply the console's approved block/contain actions on this daemon.
// block_host -> block each resolved IP (the daemon enforces on IPs, refuses
// hostnames); contain_session -> contain that session. Each result is posted
// back so the console shows applied/failed. Idempotent: the console only hands
// back actions still in 'queued'.
async function runActions(t) {
  const admin = adminHeadersFor(t.device);
  const r = await fetch(`${API}/api/actions/pending?device=${encodeURIComponent(t.device)}`, { headers: AUTH, signal: AbortSignal.timeout(6000) });
  if (!r.ok) return;
  const actions = await r.json();
  for (const a of actions) {
    if (!admin) { await post(`/api/actions/${a.id}/result`, { ok: false, device: t.device, detail: 'no admin token for this device (set RZS_ADMIN_TOKEN_' + t.device.replace(/[^A-Za-z0-9]/g, '_') + ')' }); continue; }
    const verdicts = [];
    if (a.type === 'block_host') {
      const ips = (a.ips || []).filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
      if (!ips.length) { await post(`/api/actions/${a.id}/result`, { ok: false, device: t.device, detail: `no resolved IPs for ${a.target}; the daemon enforces on IPs` }); continue; }
      for (const ip of ips) verdicts.push({ type: 'block', target: ip, rationale: `${a.reason || 'blocked'} (${a.target})` });
    } else if (a.type === 'quarantine_skill') {
      // Block the agent from reading the skill (its SKILL.md): it can no longer load it.
      verdicts.push({ type: 'block', target: a.target, rationale: a.reason || 'skill quarantined' });
    } else if (a.type === 'contain_session') {
      verdicts.push({ type: 'contain_session', session_id: a.target, rationale: a.reason || 'contained' });
    } else continue;
    try {
      const vr = await fetch(`${t.url}/api/v1/verdicts`, { method: 'POST', headers: admin, body: JSON.stringify({ source: 'agent-siem', reference: `action-${a.id}`, verdicts }), signal: AbortSignal.timeout(10000) });
      const body = await vr.json().catch(() => ({}));
      const installed = body.installed || [];
      const ok = vr.ok && installed.length > 0;
      await post(`/api/actions/${a.id}/result`, { ok, device: t.device, installed, detail: ok ? `installed ${installed.length} rule(s)` : (body.refused?.join('; ') || `daemon ${vr.status}`) });
      process.stdout.write(`${t.device}:${a.type}${ok ? '+' : '!'} `);
    } catch (e) {
      await post(`/api/actions/${a.id}/result`, { ok: false, device: t.device, detail: e.message });
    }
  }
}
let headers = {};
async function get(url) {
  const r = await fetch(url, { headers, signal: AbortSignal.timeout(6000) });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...AUTH }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

const KIND = {
  file_open: 'read', file_write: 'write', file_create: 'write', file_rename: 'write', file_delete: 'delete',
  process_exec: 'exec', process_fork: 'spawn', network_connect: 'connect', network_send: 'send', dns_query: 'dns',
  mcp_tool_call: 'tool', llm_request: 'prompt', llm_response: 'prompt', llm_tool_call: 'prompt', offensive_prompt: 'prompt',
  proxy_block: 'connect', proxy_detection: 'connect', dlp_pii: 'connect',
  tamper_ptrace: 'tamper', tamper_signal: 'tamper', tamper_mount: 'tamper', tamper_umount: 'tamper',
  contained_exec_blocked: 'exec', contained_file_blocked: 'read',
  http_request: 'http',   // request metadata from the proxy (docs/shadow-ai-daemon-spec.md)
};

function agentName(session, ev) {
  const t = session?.agent_type;
  if (typeof t === 'string') return t.toLowerCase();
  if (t && typeof t === 'object') return Object.keys(t)[0]?.toLowerCase() || 'agent';
  return (ev?.process || 'agent').toLowerCase();
}

function mapEvent(ev, device, owner, session) {
  const kind = KIND[ev.kind];
  if (!kind) return null;
  const ts = Date.parse(ev.timestamp) || Date.now();
  const out = {
    id: ev.id, ts, device, owner, session: session?.id || `${device}:${agentName(session, ev)}`,
    agent: agentName(session, ev), kind, pid: ev.pid, ppid: ev.ppid, process: ev.process, parent_process: ev.parent_process,
    target: ev.target || '', allowed: ev.allowed !== false, reason: ev.reason || undefined, category: ev.category || undefined,
    session_state: session?.state, session_privileged: session?.privileged === true, session_reason: session?.privileged_reason || undefined,
  };
  if (kind === 'prompt') {
    const c = ev.llm_context || {};
    out.text = c.response_text || ev.extra?.prompt || ev.extra?.text || ev.target || '';
    out.provider = c.provider; out.model = c.model; out.tool_call = c.tool_call;
    out.flagged = ev.kind === 'offensive_prompt';
  }
  if (kind === 'http') { const x = ev.extra || ev; Object.assign(out, { host: x.host, path: x.path, method: x.method, port: x.port, req_headers: x.req_headers, body_keys: x.body_keys, model: x.model, accept: x.accept, resp_content_type: x.resp_content_type, resp_keys: x.resp_keys }); }
  if (kind === 'tamper') out.target = ev.kind.replace('tamper_', '') + (ev.target ? ' ' + ev.target : '');
  if (kind === 'exec' && ev.extra?.argv) out.target = Array.isArray(ev.extra.argv) ? ev.extra.argv.join(' ') : String(ev.extra.argv);
  return out;
}

// Skill surfaces: the daemon's skill scanner (POST /api/v1/skill-scan/auto,
// read-only) every SKILL_SCAN_MIN minutes. Each root (skills, plugins, rules,
// MCP configs, instruction files) becomes a Skill node with its findings.
const SKILL_EVERY = Number(process.env.SKILL_SCAN_MIN || 10) * 60 * 1000;
const lastSkillScan = new Map();
function injectionSeverity(f) {
  const sig = (f.signals || []).join(' ').toLowerCase();
  if (/override|exfil|credential|curl|ignore previous|hidden instruction/.test(sig)) return 'high';
  const c = Number(f.confidence) || 0;
  return c >= 0.7 ? 'high' : c >= 0.5 ? 'medium' : 'low';
}
async function scanSkills(t) {
  if (Date.now() - (lastSkillScan.get(t.device) || 0) < SKILL_EVERY) return;
  lastSkillScan.set(t.device, Date.now());
  const r = await fetch(`${t.url}/api/v1/skill-scan/auto`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: '{}', signal: AbortSignal.timeout(60000) });
  if (!r.ok || !(r.headers.get('content-type') || '').includes('json')) return;   // older daemons: no skill scanner
  const scan = await r.json();
  const items = (scan.results || []).map((x) => {
    const findings = [
      ...(x.injection_reports || []).flatMap((rep) => (rep.findings || []).map((f) => ({ severity: injectionSeverity(f), category: 'Prompt injection', message: (f.signals || []).join('; '), file: rep.path, source: f.source }))),
      ...(x.pattern_findings || []).map((f) => ({ severity: String(f.severity || 'medium').toLowerCase(), category: f.category || f.pattern_name, message: f.message || f.pattern_name, file: f.file, source: 'pattern' })),
      ...(x.supply_findings || []).flatMap((rep) => (rep.findings || []).map((f) => ({ severity: String(f.severity || rep.risk || 'medium').toLowerCase(), category: 'Supply chain', message: f.message || f.kind || '', file: rep.path || f.file, source: 'supply-chain' }))),
    ];
    const order = { critical: 3, high: 2, medium: 1, low: 0 };
    const worst = findings.reduce((w, f) => ((order[f.severity] ?? 0) > (order[w] ?? -1) ? f.severity : w), 'clean');
    return { device: t.device, agent: x.agent, kind: x.kind, path: x.path, owner: x.owner, files_scanned: x.files_scanned, risk: worst, findings };
  });
  if (items.length) { await post('/api/skills', items); process.stdout.write(`${t.device}:skills ${items.length} `); }
}

// Deep scan commands from the console (GET /api/commands): run the daemon's
// scanners and report back (POST /api/scan-results). All daemon calls here are
// read-only (GET, or the read-only skill-scan POST).
async function runCommands(t) {
  const r = await fetch(`${API}/api/commands?devices=${encodeURIComponent(t.device)}`, { headers: AUTH, signal: AbortSignal.timeout(6000) });
  if (!r.ok) return;
  for (const c of await r.json()) {
    if (c.type !== 'deep_scan') continue;
    const safe = async (path) => { try { return await get(`${t.url}${path}`); } catch { return null; } };
    lastSkillScan.delete(t.device); await scanSkills(t).catch(() => {});   // fresh skill scan
    const results = {
      source: 'daemon', status: await safe('/api/v1/status'), health: await safe('/api/v1/health/components'),
      nhi: await safe('/api/v1/nhi'), supply_chain: await safe('/api/v1/supply-chain/summary'), compliance: await safe('/api/v1/compliance/summary'),
    };
    if (!results.status && !results.health) results.unreachable = true;   // daemon not answering: say so, don't fake a posture
    await post('/api/scan-results', { command: c.id, device: t.device, results });
    process.stdout.write(`${t.device}:deep-scan `);
  }
}

const seen = new Map();  // device → Set of event ids already sent
const sentNotes = new Map(); // session → last commentary seq
const lastInv = new Map();   // device → last inventory sent (only resend on change)

async function pollDevice(t) {
  headers = headersFor(t.device);
  const ids = seen.get(t.device) || new Set();
  seen.set(t.device, ids);
  // Tile headline: RZS_TEAM_<device> if set (e.g. "Build Infrastructure"), else the daemon's user/host.
  let owner = process.env[`RZS_TEAM_${t.device.replace(/[^A-Za-z0-9]/g, '_')}`] || '';
  if (!owner) { try { const h = await get(`${t.url}/api/v1/health`); owner = h.user || h.hostname || ''; } catch { /* optional */ } }

  // MCP servers from the inventory scan → (:McpServer) nodes
  try {
    const inv = await get(`${t.url}/api/v1/discovery/inventory`);
    const servers = (inv.mcp_servers || []).map((m) => ({ device: t.device, name: m.name, agent: m.agent, transport: m.transport, url: m.url, command: m.command, scope: m.scope, held: m.held ?? m.status === 'held' }));
    const sig = JSON.stringify(servers);
    if (servers.length && lastInv.get(t.device) !== sig) { await post('/api/mcp-servers', servers); lastInv.set(t.device, sig); }
  } catch (e) { if (!/404/.test(e.message)) console.error(`${t.device}: inventory: ${e.message}`); }

  try { await scanSkills(t); } catch (e) { console.error(`${t.device}: skill scan: ${e.message}`); }
  try { await runCommands(t); } catch (e) { console.error(`${t.device}: commands: ${e.message}`); }
  try { await runActions(t); } catch (e) { console.error(`${t.device}: actions: ${e.message}`); }

  let sessions = [];
  try { sessions = await get(`${t.url}/api/v1/sessions`); if (!Array.isArray(sessions)) sessions = sessions.sessions || []; } catch (e) { console.error(`${t.device}: sessions: ${e.message}`); }

  const batch = [];
  if (sessions.length) {
    const cutoff = Date.now() - SINCE_H * 3600 * 1000;
    for (const s of sessions) {
      const last = Date.parse(s.last_event_at || s.end_time || s.start_time || 0) || 0;
      if (last && last < cutoff && s.state !== 'ACTIVE') continue;   // old history stays in the daemon
      let evs = [];
      try { evs = await get(`${t.url}/api/v1/sessions/${encodeURIComponent(s.id)}/events`); if (!Array.isArray(evs)) evs = evs.events || []; } catch { continue; }
      for (const ev of evs) {
        if (ids.has(ev.id)) continue;
        const m = mapEvent(ev, t.device, owner, s);
        if (m) { batch.push(m); ids.add(ev.id); }
      }
      // Narrative lines → notes on the session feed
      try {
        const c = await get(`${t.url}/api/v1/sessions/${encodeURIComponent(s.id)}/commentary`);
        const lines = Array.isArray(c) ? c : c.lines || [];
        const last = sentNotes.get(s.id) || 0;
        const fresh = lines.filter((l) => (l.seq || 0) > last);
        if (fresh.length) {
          await post('/api/notes', fresh.map((l) => ({ device: t.device, session: s.id, seq: l.seq, ts: Date.parse(l.at) || Date.now(), level: l.level, kind: l.kind, text: l.text, agent: l.agent })));
          sentNotes.set(s.id, Math.max(...fresh.map((l) => l.seq || 0)));
        }
      } catch { /* commentary is optional */ }
    }
  } else {
    // No session store: take the daemon's recent event stream as one session per agent.
    try {
      const evs = await get(`${t.url}/api/v1/events?limit=1000`);
      for (const ev of (Array.isArray(evs) ? evs : evs.events || [])) {
        if (ids.has(ev.id)) continue;
        const m = mapEvent(ev, t.device, owner, null);
        if (m) { batch.push(m); ids.add(ev.id); }
      }
    } catch (e) { console.error(`${t.device}: events: ${e.message}`); }
  }
  if (batch.length) {
    batch.sort((a, b) => a.ts - b.ts);
    for (let i = 0; i < batch.length; i += 500) await post('/api/events', batch.slice(i, i + 500));   // a backlog can be months
    process.stdout.write(`${t.device}:+${batch.length} `);
  }
}

console.log(`rzs adapter → ${API}; devices: ${targets.map((t) => `${t.device} (${t.url})`).join(', ')}`);
setInterval(async () => { for (const t of targets) { try { await pollDevice(t); } catch (e) { console.error(`${t.device}: ${e.message}`); } } }, POLL);
