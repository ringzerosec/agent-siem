// pepper.js — "Pepper", the voice of Agent SIEM: a full-duplex voice assistant on
// OpenAI GPT-Live that talks with you, digs into the graph, drives the screen
// while it speaks, and speaks up on its own when something new happens.
//
// Shape (OpenAI's documented pattern, see github.com/openai/openai-live-console):
//   browser ──WebRTC audio──▶ GPT-Live (gpt-live-1, the voice)
//                                 │ delegation: responses
//                                 ▼
//                         OpenAI backend model (analysis, OPENAI_BACKEND_MODEL)
//                                 │ function calls
//   this server ◀──sideband WebSocket── tool calls / transcripts
//      ├─ graph tools → the MCP server (src/mcp-tools.js) → FalkorDB
//      └─ screen tools → pushed to the browser (SSE) so the screen moves while Pepper talks
//
// The API key never leaves this server. Only the sideband runs tools; the
// browser's data channel is limited to session.close.
//
//   OPENAI_API_KEY=...             required
//   OPENAI_BACKEND_MODEL=gpt-6-sol    analysis model, run at PEPPER_REASONING=low for speed
//   PEPPER_VOICE=marin

import WebSocket from 'ws';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from './mcp-tools.js';

const API = 'https://api.openai.com/v1';
const KEY = () => process.env.OPENAI_API_KEY || '';
const BACKEND = process.env.OPENAI_BACKEND_MODEL || 'gpt-6-sol';
const EFFORT = process.env.PEPPER_REASONING || 'low';   // measured: ~1.1 s per backend round vs ~1.7-2.9 s at default
const VOICE = process.env.PEPPER_VOICE || 'marin';
const MAX_SESSION_S = Number(process.env.PEPPER_MAX_SECONDS || 900);

const FRONT = `You are Pepper, the voice of Agent SIEM, the security console of Ring Zero Security. You talk with the person who runs security for a fleet of laptops where AI agents work. Think of yourself as an unflappable chief of staff for security: calm, quick, precise, with a dry wit used sparingly.

How you talk:
- Never use their name or any form of address; just talk to them directly.
- Short spoken sentences. Lead with what matters. Two or three sentences, then stop and let them steer.
- Acknowledge instantly ("On it.", "Pulling that up.") and keep talking naturally while the backend works.
- If them interrupts, stop and follow the new direction.
- Never read ids, hashes or raw timestamps aloud. Prefer the team ("the Payments laptop"); if you need the hostname, say only its number, "zero three eight eight". Never say "dash".
- You are the brain of Ring Zero Security: you watch every endpoint and you decide what gets blocked. Speak in the first person about enforcement: "I blocked it", "I refused the upload", "I let that one through". Don't name the product in conversation.

Delegate every question about the fleet, alerts, endpoints, hosts, secrets, events or what is on screen to the backend, and every request to show, open, go back, or navigate. Never invent facts about the fleet. The backend moves the screen for you; describe what them is now looking at.
Changes like blocking a host, containing a session, or opening a ticket need a clear yes from them first; ask once, briefly.
When you receive a heads-up about a new alert, raise it naturally and briefly, say whether you blocked it, and offer to dig in. When you receive a finished analysis with a proposed next step, say in two sentences what happened and who it was, say that you blocked it if you did, and ask whether to do the proposed step (for example: Should I email her about it?). Wait for the answer; the backend carries it out.
While the backend works you will get short progress notes about what it is finding. Say each one briefly, in your own words, as it arrives, like a colleague thinking out loud ("Okay, the key only went to curl." "Pastebin was only hit from this laptop."). When the final result comes, give the conclusion and the next step without repeating what you already said.`;

const BACK = `You are the analysis backend for Pepper, the voice assistant of Agent SIEM (Ring Zero Security). Every action an AI agent takes on an endpoint is an edge in a FalkorDB provenance graph; "allowed": false means the enforcement layer (the voice speaks for it as "I") blocked that step.
Answer with facts from the tools only. For an alert: get_alert for the path, then secret_followups and host_fleet_exposure to see if it went further across the fleet, process_timeline for what the agent did around it, fleet_risk_rank to judge importance. list_alerts for what is open. run_deep_scan (then scan_status) when asked to scan or discover across the fleet; fleet_inventory for what each endpoint runs and its posture; propose_policies to turn findings into proposals in the inbox (they need a yes); iso42001_readiness for AI governance and compliance questions (say it is evidence for an audit, not a certification; show_governance to put it on screen). ai_usage for shadow AI: which AI services the fleet uses (found by protocol fingerprint, not hostname), gateways, unapproved providers, unregistered agents (show_ai_usage to put it on screen). list_campaigns and indicator_intel for the threat-actor view: is this one actor across laptops, have we seen this host or skill before, who else is connected to it (show_campaigns to put it on screen). mcp_and_skills for an endpoint's MCP servers (approved, untrusted, held; calls and blocked calls) and its skills, plugins and rule files with scanner findings. get_screen tells you what the user is looking at, so "this one" can be resolved.
Be fast: the user is waiting on a live voice call. For "what happened on X" or "why is this red", call investigate_alert (one call has the path, fleet follow-ups and the timeline) together with focus_alert in the same turn, in parallel. Avoid calling get_alert, secret_followups, host_fleet_exposure and process_timeline separately when investigate_alert covers it. Aim for one or two rounds of tool calls, then answer.
Drive the screen as you work so the user sees what is being discussed: open_endpoint, focus_alert to spotlight an attack path, highlight_nodes, select_node, zoom_out, show_events, show_wall, set_time_range.
Only call block_host, contain_session, open_ticket, mark_false_positive or approve_decision when the conversation shows the user said yes to that exact action. When the voice raised an autopilot decision (it mentions a decision id like D-xxxxxx) and the user says yes, call approve_decision with that id; if they say no, dismiss_decision with their reason. list_decisions shows what is waiting. Never block an approved host.
Write results in the first person for enforcement ("I blocked the upload"), and don't name the product. Return a short plain-English result the voice can say in two or three sentences: the conclusion first, then the one or two facts behind it, then the obvious next step. No markdown, no ids.`;

// Screen tools: executed by pushing an instruction to the browser.
const SCREEN_TOOLS = [
  { name: 'get_screen', description: 'What the user is looking at right now: view, open endpoint, its alerts, spotlighted alert, selected node, time range.', parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'show_wall', description: 'Go to the wall of all endpoints, optionally filtered to critical or high.', parameters: { type: 'object', properties: { filter: { type: 'string', enum: ['all', 'critical', 'high'] } }, additionalProperties: false } },
  { name: 'open_endpoint', description: 'Open one endpoint: its provenance graph, alerts and summary.', parameters: { type: 'object', properties: { device: { type: 'string' } }, required: ['device'], additionalProperties: false } },
  { name: 'focus_alert', description: 'Open an endpoint and spotlight one alert: its attack path stays lit, the rest fades, and the alert expands with its response.', parameters: { type: 'object', properties: { device: { type: 'string' }, alert_id: { type: 'string' } }, required: ['device', 'alert_id'], additionalProperties: false } },
  { name: 'highlight_nodes', description: 'On the open endpoint, light up specific nodes and the edges between them.', parameters: { type: 'object', properties: { node_ids: { type: 'array', items: { type: 'integer' } } }, required: ['node_ids'], additionalProperties: false } },
  { name: 'select_node', description: 'Select one node on the open endpoint and show its timeline and blast radius.', parameters: { type: 'object', properties: { node_id: { type: 'integer' } }, required: ['node_id'], additionalProperties: false } },
  { name: 'zoom_out', description: 'Clear any spotlight and show the whole graph of the open endpoint.', parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'show_events', description: 'Show the event log, optionally only alert-path or refused events, for one endpoint, or matching text.', parameters: { type: 'object', properties: { filter: { type: 'string', enum: ['all', 'alert', 'refused'] }, device: { type: 'string' }, query: { type: 'string' } }, additionalProperties: false } },
  { name: 'set_time_range', description: 'Change the time range of everything on screen.', parameters: { type: 'object', properties: { range: { type: 'string', enum: ['24h', 'today', 'yesterday', '7d', 'all'] } }, required: ['range'], additionalProperties: false } },
  { name: 'show_governance', description: 'Open the Governance view: fleet inventory and posture, deep scan, policy proposals, ISO/IEC 42001 readiness.', parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'show_inbox', description: 'Open the decision inbox: analyses finished on their own with proposed next steps waiting for a yes.', parameters: { type: 'object', properties: { decision: { type: 'string' } }, additionalProperties: false } },
  { name: 'show_ai_usage', description: 'Open the AI usage view: every AI service the fleet talks to, shadow AI, gateways and unregistered agents.', parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'show_campaigns', description: 'Open the Campaigns view: findings grouped by shared attacker infrastructure across endpoints.', parameters: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'run_triage', description: 'Start the triage agent on one alert; its investigation appears in the side panel.', parameters: { type: 'object', properties: { device: { type: 'string' }, alert_id: { type: 'string' } }, required: ['device', 'alert_id'], additionalProperties: false } },
];
const SCREEN = new Set(SCREEN_TOOLS.map((t) => t.name));

const ev = (type, fields = {}) => ({ type, event_id: `event_${randomUUID()}`, ...fields });
const rec = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const str = (v, n = 4000) => (typeof v === 'string' ? v.slice(0, n) : '');

async function api(path, body) {
  const r = await fetch(`${API}${path}`, { method: 'POST', headers: { authorization: `Bearer ${KEY()}`, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(20000) });
  const text = await r.text();
  let json = {}; try { json = JSON.parse(text); } catch { /* empty */ }
  if (!r.ok) { const e = new Error(json.error?.message || `OpenAI ${r.status}`); e.status = r.status; e.code = json.error?.code; throw e; }
  return json;
}

// One graph MCP client shared by all sessions (in-process, real MCP protocol).
let mcpPromise;
function mcp() {
  if (!mcpPromise) mcpPromise = (async () => {
    const server = createMcpServer({ actor: `pepper (${BACKEND})` });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 'agent-siem-pepper', version: '0.1.0' });
    await client.connect(ct);
    const { tools } = await client.listTools();
    return { client, tools: tools.filter((t) => t.name !== 'submit_verdict') };
  })();
  return mcpPromise;
}

// A short, speakable finding from a tool result (no ids).
function finding(name, r) {
  if (!r || r.error) return '';
  switch (name) {
    case 'list_alerts': {
      const a = r.alerts || []; if (!a.length) return 'No open alerts.';
      const crit = a.filter((x) => x.severity === 'critical').length, blocked = a.filter((x) => x.blocked === true).length;
      return '';   // a lookup step, not a finding worth saying
    }
    case 'investigate_alert': case 'get_alert': {
      const refused = (r.path?.edges || r.edges || []).filter((e) => !e.allowed).length;
      const leaked = (r.secrets || []).flatMap((x) => x.unapproved_egress_after_read || []).filter((e) => e.allowed);
      const others = new Set((r.secrets || []).flatMap((x) => x.read_on_endpoints || [])); others.delete(r.device);
      let t = `${r.summary}. ${refused ? 'I refused the risky step.' : 'I did not block anything on that path.'}`;
      if (others.size) t += ` The same secret was read on ${others.size} other endpoint${others.size > 1 ? 's' : ''}.`;
      if (r.secrets?.length) t += leaked.length ? ` It reached ${leaked.length} unapproved host${leaked.length > 1 ? 's' : ''}.` : ' It did not get out anywhere else.';
      return t;
    }
    case 'secret_followups': { const n = (r.readers || []).length; const out = (r.readers || []).flatMap((x) => x.egress_after || []).filter((e) => !e.approved && e.allowed !== false).length; return `That secret was read by ${n} process${n === 1 ? '' : 'es'}; ${out ? out + ' unapproved connections followed.' : 'nothing unapproved got out after.'}`; }
    case 'host_fleet_exposure': return `${r.host?.name || 'That host'} was contacted from ${r.endpoints} endpoint${r.endpoints === 1 ? '' : 's'}; I let ${r.allowed} of ${r.total_attempts} attempts through.`;
    case 'fleet_risk_rank': return r.ranked?.[0] ? `By PageRank the most central asset is ${String(r.ranked[0].name).split('/').pop()}.` : '';
    case 'block_host': case 'contain_session': return `Done: ${String(r.type || '').replace('_', ' ')} ${r.target || ''}.`;
    case 'open_ticket': return `Ticket opened: ${r.title}.`;
    default: return '';
  }
}

const sessions = new Map();   // our id -> Session
export const pepperConfigured = () => Boolean(KEY());

class Session {
  constructor() {
    this.id = randomUUID(); this.upstream = ''; this.sink = null; this.history = [];
    this.screen = {}; this.pending = new Map(); this.rounds = new Map(); this.calls = new Set();
    this.delegations = new Set(); this.responseToDelegation = new Map(); this.closed = false; this.started = Date.now();
  }
  emit(e) { this.history.push(e); if (this.history.length > 300) this.history.shift(); try { this.sink?.(e); } catch { this.sink = null; } }
  send(e) { if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(e)); }

  async start(sdp) {
    const { tools } = await mcp();
    const fnTools = [
      ...SCREEN_TOOLS.map((t) => ({ type: 'function', name: t.name, description: t.description, parameters: t.parameters, strict: false })),
      ...tools.map((t) => ({ type: 'function', name: t.name, description: t.description, parameters: t.inputSchema, strict: false })),
    ];
    const created = await api('/live/sessions', {
      session: {
        model: 'gpt-live-1',
        instructions: FRONT,
        audio: { output: { voice: VOICE } },
        delegation: { type: 'responses', responses: { model: BACKEND, instructions: BACK, tools: fnTools, tool_choice: 'auto', parallel_tool_calls: true, max_output_tokens: 700, ...(EFFORT ? { reasoning: { effort: EFFORT } } : {}) } },
        client: { data_channel: { allowed_client_events: ['session.close'], allowed_server_events: [{ type: 'session.started' }, { type: 'session.closed' }, { type: 'error' }] } },
      },
      transport: { type: 'webrtc', sdp },
    });
    if (!created?.session?.id || !String(created?.transport?.sdp || '').startsWith('v=0')) throw new Error('Invalid Live session response');
    this.upstream = created.session.id;
    await this.attach();
    this.lifetime = setTimeout(() => this.stop('time limit'), MAX_SESSION_S * 1000);
    return created.transport.sdp;
  }

  attach() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`wss://api.openai.com/v1/live/sessions/${encodeURIComponent(this.upstream)}/attach`, { headers: { authorization: `Bearer ${KEY()}` }, handshakeTimeout: 15000, maxPayload: 1 << 20 });
      this.ws = ws;
      ws.once('open', () => resolve());
      ws.on('error', (e) => { if (ws.readyState !== WebSocket.OPEN) reject(e); });
      ws.on('close', () => { if (!this.closed) this.finish('voice connection closed'); });
      ws.on('message', (b) => { try { const v = JSON.parse(b.toString()); if (typeof v.type === 'string') this.receive(v).catch((e) => this.emit({ type: 'error', text: e.message })); } catch { /* ignore */ } });
    });
  }

  async receive(v) {
    if (v.type === 'session.input_audio.append' || v.type === 'session.output_audio.delta') return;
    if (v.type === 'session.started') return this.emit({ type: 'ready' });
    if (v.type === 'session.closed') return this.finish(str(v.reason) || 'closed', rec(v.usage));
    if (v.type === 'session.input_transcript.delta' || v.type === 'session.output_transcript.delta')
      return this.emit({ type: 'transcript', role: v.type.startsWith('session.input') ? 'user' : 'pepper', text: str(v.delta), id: str(v.event_id) });
    if (v.type === 'error') { console.log(`pepper ${this.id.slice(0, 8)}: error ${JSON.stringify(v.error).slice(0, 300)}`); return this.emit({ type: 'error', text: str(rec(v.error).message) || str(rec(v.error).code) || 'error' }); }
    if (process.env.PEPPER_DEBUG) console.log('pepper <-', v.type, v.type === 'response.event' ? rec(v.event).type : '');
    if (v.type === 'session.delegation.created') {
      const d = rec(v.delegation); const id = str(d.id);
      if (id) { this.delegations.add(id); if (d.response_id) this.responseToDelegation.set(str(d.response_id), id); this.emit({ type: 'working', on: true }); }
      return;
    }
    if (v.type !== 'response.event') return;
    const inner = rec(v.event); const resp = rec(inner.response);
    const rid = str(resp.id) || str(inner.response_id);
    const did = str(v.delegation_id) || this.responseToDelegation.get(rid) || '';
    if (rid && did) this.responseToDelegation.set(rid, did);
    if (inner.type === 'response.output_item.done' && rec(inner.item).type === 'function_call') {
      const item = rec(inner.item); const callId = str(item.call_id);
      if (!callId || this.calls.has(callId)) return;
      this.calls.add(callId);
      const p = this.runTool(str(item.name, 80), str(item.arguments, 8000), did).then((out) => ({ type: 'function_call_output', call_id: callId, output: out.slice(0, 12000) }));
      this.pending.set(did, [...(this.pending.get(did) || []), p]);
      return;
    }
    if (inner.type === 'response.completed') {
      const outs = this.pending.get(did) || []; this.pending.delete(did);
      if (!outs.length) { this.emit({ type: 'working', on: false }); return; }
      const round = (this.rounds.get(did) || 0) + 1; this.rounds.set(did, round);
      if (round > 8) { this.emit({ type: 'working', on: false }); return; }
      const items = await Promise.all(outs);
      for (const item of items) this.send(ev('response.item.create', { item }));
      this.send(ev('response.create'));   // results must all be in before the one continuation
      return;
    }
    if (['response.failed', 'response.incomplete', 'response.error'].includes(inner.type)) this.emit({ type: 'working', on: false });
  }

  // Think out loud: a one-line finding from each tool result goes to the voice
  // right away (session.commentary.append), so the user hears progress
  // instead of silence while the backend works.
  narrate(did, text) {
    if (!text) return;
    const now = Date.now();
    if (now - (this.lastNote || 0) < 1200) return;   // don't talk over itself
    this.lastNote = now;
    this.emit({ type: 'thought', text });
    // Session-wide (delegation_id null): a Responses delegation id is rejected here.
    this.send(ev('session.commentary.append', { delegation_id: null, content: `Progress note (say briefly, in your own words): ${text}` }));
  }

  async runTool(name, rawArgs, did) {
    let args = {}; try { args = rawArgs ? JSON.parse(rawArgs) : {}; } catch { return JSON.stringify({ error: 'bad arguments' }); }
    if (name === 'get_screen') return JSON.stringify(this.screen || {});
    if (SCREEN.has(name)) { this.emit({ type: 'ui', tool: name, args }); return JSON.stringify({ ok: true, note: `The screen now shows ${name.replace(/_/g, ' ')}.` }); }
    const { client } = await mcp();
    this.emit({ type: 'tool', tool: name, args });
    const res = await client.callTool({ name, arguments: args });
    try { this.narrate(did, finding(name, JSON.parse(res.content?.[0]?.text || '{}'))); } catch { /* narration is best effort */ }
    if (['block_host', 'contain_session', 'open_ticket', 'mark_false_positive'].includes(name) && !res.isError) this.emit({ type: 'action', tool: name, args });
    return res.content?.[0]?.text || '{}';
  }

  // Something new happened: Pepper raises it in its own words.
  heads(text) { this.send(ev('session.commentary.append', { delegation_id: null, content: text.slice(0, 400) })); }

  async stop(reason = 'stopped') {
    if (this.closed) return;
    this.send(ev('session.close'));
    setTimeout(() => { if (!this.closed) { api(`/live/sessions/${encodeURIComponent(this.upstream)}/hangup`).catch(() => {}); this.finish(reason); } }, 4000);
  }
  finish(reason, usage = {}) {
    if (this.closed) return;
    console.log(`pepper ${this.id.slice(0, 8)}: closed (${reason}) after ${Math.round((Date.now() - this.started) / 1000)}s, billed ${usage.seconds ?? '?'}s`);
    this.closed = true; clearTimeout(this.lifetime);
    this.emit({ type: 'closed', reason, seconds: usage.seconds ?? null });
    try { this.ws?.close(); } catch { /* gone */ }
    setTimeout(() => sessions.delete(this.id), 60000);
  }
}

// ---- routes -----------------------------------------------------------------
export function mountPepper(app) {
  app.get('/api/pepper/config', (_req, res) => res.json({ configured: pepperConfigured(), voice: VOICE, backend: BACKEND, }));

  app.post('/api/pepper/session', async (req, res) => {
    if (!pepperConfigured()) return res.status(503).json({ error: 'Set OPENAI_API_KEY to talk to Pepper.' });
    const sdp = String(req.body?.sdp || '');
    if (!sdp.startsWith('v=0') || sdp.length > 20000) return res.status(400).json({ error: 'bad offer' });
    const s = new Session(); sessions.set(s.id, s);
    try { const answer = await s.start(sdp); res.json({ id: s.id, sdp: answer }); }
    catch (e) { sessions.delete(s.id); res.status(e.status && e.status < 500 ? e.status : 502).json({ error: e.message, code: e.code }); }
  });

  // One event stream per live session: transcripts, screen moves, tool lines.
  app.get('/api/pepper/events/:id', (req, res) => {
    const s = sessions.get(req.params.id);
    if (!s) return res.status(404).end();
    res.set({ 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    res.flushHeaders();
    const write = (e) => res.write(`data: ${JSON.stringify(e)}\n\n`);
    for (const e of s.history) write(e);
    s.sink = write;
    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => { clearInterval(ping); if (s.sink === write) s.sink = null; });
  });

  app.post('/api/pepper/screen/:id', (req, res) => { const s = sessions.get(req.params.id); if (s) s.screen = req.body || {}; res.json({ ok: !!s }); });
  // Typed input: handed to the live session as if it was spoken.
  app.post('/api/pepper/say/:id', (req, res) => {
    const s = sessions.get(req.params.id); const text = String(req.body?.text || '').slice(0, 600).trim();
    if (!s || s.closed || !text) return res.status(404).json({ ok: false });
    s.emit({ type: 'transcript', role: 'user', text, id: 'typed-' + Date.now() });
    s.send(ev('session.instructions.append', { delegation_id: null, content: `The user just typed this instead of speaking; respond exactly as if they had said it: "${text.replace(/"/g, "'")}"` }));
    res.json({ ok: true });
  });
  // Wake-on-alert: the browser opens a session, then asks Pepper to raise the alert.
  app.post('/api/pepper/heads/:id', (req, res) => { const s = sessions.get(req.params.id); if (s && !s.closed) s.heads(String(req.body?.text || '')); res.json({ ok: !!s }); });
  app.post('/api/pepper/close/:id', async (req, res) => { const s = sessions.get(req.params.id); if (s) await s.stop('user ended'); res.json({ ok: true }); });
}

// Heads-up for every open session (called when a new critical/high alert appears).
export function pepperHeadsUp(text, ui) {
  for (const s of sessions.values()) if (!s.closed) { if (ui) s.emit({ type: 'ui', tool: ui.tool, args: ui.args }); s.heads(text); }
}
export const pepperActive = () => [...sessions.values()].some((s) => !s.closed);
