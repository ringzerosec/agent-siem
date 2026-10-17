// adapter-rzs.js — pull real activity from installed Ring Zero Security daemons
// and feed it to the graph. One daemon = one device on the wall.
//
//   RZS=priya-laptop=http://localhost:7700,build-vm=http://10.0.0.5:7700 node src/adapter-rzs.js
//   RZS_TOKEN=...   bearer token if the daemon API requires one
//   RZS_TOKEN_priya_laptop=...   per-device token (device id with - → _)
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
let headers = {};
async function get(url) {
  const r = await fetch(url, { headers, signal: AbortSignal.timeout(6000) });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
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
  if (kind === 'tamper') out.target = ev.kind.replace('tamper_', '') + (ev.target ? ' ' + ev.target : '');
  if (kind === 'exec' && ev.extra?.argv) out.target = Array.isArray(ev.extra.argv) ? ev.extra.argv.join(' ') : String(ev.extra.argv);
  return out;
}

const seen = new Map();  // device → Set of event ids already sent
const sentNotes = new Map(); // session → last commentary seq

async function pollDevice(t) {
  headers = headersFor(t.device);
  const ids = seen.get(t.device) || new Set();
  seen.set(t.device, ids);
  let owner = '';
  try { const h = await get(`${t.url}/api/v1/health`); owner = h.user || h.hostname || ''; } catch { /* optional */ }

  // MCP servers from the inventory scan → (:McpServer) nodes
  try {
    const inv = await get(`${t.url}/api/v1/discovery/inventory`);
    const servers = (inv.mcp_servers || []).map((m) => ({ device: t.device, name: m.name, agent: m.agent, transport: m.transport, url: m.url, command: m.command, scope: m.scope, held: m.held ?? m.status === 'held' }));
    if (servers.length) await post('/api/mcp-servers', servers);
  } catch (e) { if (!/404/.test(e.message)) console.error(`${t.device}: inventory: ${e.message}`); }

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
