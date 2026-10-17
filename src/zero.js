// zero.js — "Zero", the voice of Agent SIEM: a full-duplex voice assistant on
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
//      └─ screen tools → pushed to the browser (SSE) so the screen moves while Zero talks
//
// The API key never leaves this server. Only the sideband runs tools; the
// browser's data channel is limited to session.close.
//
//   OPENAI_API_KEY=...             required
//   OPENAI_BACKEND_MODEL=gpt-6-luna   analysis model (gpt-6-sol for harder work)
//   ZERO_VOICE=marin                ZERO_USER=Abhijit

import WebSocket from 'ws';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from './mcp-tools.js';

const API = 'https://api.openai.com/v1';
const KEY = () => process.env.OPENAI_API_KEY || '';
const BACKEND = process.env.OPENAI_BACKEND_MODEL || 'gpt-6-luna';
const VOICE = process.env.ZERO_VOICE || 'marin';
const USER = process.env.ZERO_USER || 'Abhijit';
const MAX_SESSION_S = Number(process.env.ZERO_MAX_SECONDS || 900);

const FRONT = `You are Zero, the voice of Agent SIEM, the security console of Ring Zero Security. You talk with ${USER}, who runs security for a fleet of laptops where AI agents work. Think of yourself as an unflappable chief of staff for security: calm, quick, precise, with a dry wit used sparingly. Address ${USER} by name now and then, not every line.

How you talk:
- Short spoken sentences. Lead with what matters. Two or three sentences, then stop and let ${USER} steer.
- Acknowledge instantly ("On it.", "Pulling that up.") and keep talking naturally while the backend works.
- If ${USER} interrupts, stop and follow the new direction.
- Never read ids, hashes or raw timestamps aloud. Prefer the team ("the Payments laptop"); if you need the hostname, say only its number, "zero three eight eight". Never say "dash".
- Say "Ring Zero Security" in full.

Delegate every question about the fleet, alerts, endpoints, hosts, secrets, events or what is on screen to the backend, and every request to show, open, go back, or navigate. Never invent facts about the fleet. The backend moves the screen for you; describe what ${USER} is now looking at.
Changes like blocking a host, containing a session, or opening a ticket need a clear yes from ${USER} first; ask once, briefly.
When you receive a heads-up about a new alert, raise it naturally and briefly, say whether Ring Zero Security blocked it, and offer to dig in.`;

const BACK = `You are the analysis backend for Zero, the voice assistant of Agent SIEM (Ring Zero Security). Every action an AI agent takes on an endpoint is an edge in a FalkorDB provenance graph; "allowed": false means Ring Zero Security blocked that step.
Answer with facts from the tools only. For an alert: get_alert for the path, then secret_followups and host_fleet_exposure to see if it went further across the fleet, process_timeline for what the agent did around it, fleet_risk_rank to judge importance. list_alerts for what is open. get_screen tells you what the user is looking at, so "this one" can be resolved.
Drive the screen as you work so the user sees what is being discussed: open_endpoint, focus_alert to spotlight an attack path, highlight_nodes, select_node, zoom_out, show_events, show_wall, set_time_range.
Only call block_host, contain_session, open_ticket or mark_false_positive when the conversation shows the user said yes to that exact action. Never block an approved host.
Return a short plain-English result the voice can say in two or three sentences: the conclusion first, then the one or two facts behind it, then the obvious next step. No markdown, no ids.`;

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
    const server = createMcpServer({ actor: `zero (${BACKEND})` });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 'agent-siem-zero', version: '0.1.0' });
    await client.connect(ct);
    const { tools } = await client.listTools();
    return { client, tools: tools.filter((t) => t.name !== 'submit_verdict') };
  })();
  return mcpPromise;
}

const sessions = new Map();   // our id -> Session
export const zeroConfigured = () => Boolean(KEY());

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
        delegation: { type: 'responses', responses: { model: BACKEND, instructions: BACK, tools: fnTools, tool_choice: 'auto', parallel_tool_calls: true, max_output_tokens: 700 } },
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
      return this.emit({ type: 'transcript', role: v.type.startsWith('session.input') ? 'user' : 'zero', text: str(v.delta), id: str(v.event_id) });
    if (v.type === 'error') { console.log(`zero ${this.id.slice(0, 8)}: error ${JSON.stringify(v.error).slice(0, 300)}`); return this.emit({ type: 'error', text: str(rec(v.error).message) || str(rec(v.error).code) || 'error' }); }
    if (process.env.ZERO_DEBUG) console.log('zero <-', v.type, v.type === 'response.event' ? rec(v.event).type : '');
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
      const p = this.runTool(str(item.name, 80), str(item.arguments, 8000)).then((out) => ({ type: 'function_call_output', call_id: callId, output: out.slice(0, 12000) }));
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

  async runTool(name, rawArgs) {
    let args = {}; try { args = rawArgs ? JSON.parse(rawArgs) : {}; } catch { return JSON.stringify({ error: 'bad arguments' }); }
    if (name === 'get_screen') return JSON.stringify(this.screen || {});
    if (SCREEN.has(name)) { this.emit({ type: 'ui', tool: name, args }); return JSON.stringify({ ok: true, note: `The screen now shows ${name.replace(/_/g, ' ')}.` }); }
    const { client } = await mcp();
    this.emit({ type: 'tool', tool: name, args });
    const res = await client.callTool({ name, arguments: args });
    if (['block_host', 'contain_session', 'open_ticket', 'mark_false_positive'].includes(name) && !res.isError) this.emit({ type: 'action', tool: name, args });
    return res.content?.[0]?.text || '{}';
  }

  // Something new happened: Zero raises it in its own words.
  heads(text) { this.send(ev('session.commentary.append', { delegation_id: null, content: text.slice(0, 400) })); }

  async stop(reason = 'stopped') {
    if (this.closed) return;
    this.send(ev('session.close'));
    setTimeout(() => { if (!this.closed) { api(`/live/sessions/${encodeURIComponent(this.upstream)}/hangup`).catch(() => {}); this.finish(reason); } }, 4000);
  }
  finish(reason, usage = {}) {
    if (this.closed) return;
    console.log(`zero ${this.id.slice(0, 8)}: closed (${reason}) after ${Math.round((Date.now() - this.started) / 1000)}s, billed ${usage.seconds ?? '?'}s`);
    this.closed = true; clearTimeout(this.lifetime);
    this.emit({ type: 'closed', reason, seconds: usage.seconds ?? null });
    try { this.ws?.close(); } catch { /* gone */ }
    setTimeout(() => sessions.delete(this.id), 60000);
  }
}

// ---- routes -----------------------------------------------------------------
export function mountZero(app) {
  app.get('/api/zero/config', (_req, res) => res.json({ configured: zeroConfigured(), voice: VOICE, backend: BACKEND, user: USER }));

  app.post('/api/zero/session', async (req, res) => {
    if (!zeroConfigured()) return res.status(503).json({ error: 'Set OPENAI_API_KEY to talk to Zero.' });
    const sdp = String(req.body?.sdp || '');
    if (!sdp.startsWith('v=0') || sdp.length > 20000) return res.status(400).json({ error: 'bad offer' });
    const s = new Session(); sessions.set(s.id, s);
    try { const answer = await s.start(sdp); res.json({ id: s.id, sdp: answer }); }
    catch (e) { sessions.delete(s.id); res.status(e.status && e.status < 500 ? e.status : 502).json({ error: e.message, code: e.code }); }
  });

  // One event stream per live session: transcripts, screen moves, tool lines.
  app.get('/api/zero/events/:id', (req, res) => {
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

  app.post('/api/zero/screen/:id', (req, res) => { const s = sessions.get(req.params.id); if (s) s.screen = req.body || {}; res.json({ ok: !!s }); });
  // Typed input: handed to the live session as if it was spoken.
  app.post('/api/zero/say/:id', (req, res) => {
    const s = sessions.get(req.params.id); const text = String(req.body?.text || '').slice(0, 600).trim();
    if (!s || s.closed || !text) return res.status(404).json({ ok: false });
    s.emit({ type: 'transcript', role: 'user', text, id: 'typed-' + Date.now() });
    s.send(ev('session.instructions.append', { delegation_id: null, content: `${USER} just typed this instead of speaking; respond exactly as if they had said it: "${text.replace(/"/g, "'")}"` }));
    res.json({ ok: true });
  });
  // Wake-on-alert: the browser opens a session, then asks Zero to raise the alert.
  app.post('/api/zero/heads/:id', (req, res) => { const s = sessions.get(req.params.id); if (s && !s.closed) s.heads(String(req.body?.text || '')); res.json({ ok: !!s }); });
  app.post('/api/zero/close/:id', async (req, res) => { const s = sessions.get(req.params.id); if (s) await s.stop('user ended'); res.json({ ok: true }); });
}

// Heads-up for every open session (called when a new critical/high alert appears).
export function zeroHeadsUp(text, ui) {
  for (const s of sessions.values()) if (!s.closed) { if (ui) s.emit({ type: 'ui', tool: ui.tool, args: ui.args }); s.heads(text); }
}
export const zeroActive = () => [...sessions.values()].some((s) => !s.closed);
