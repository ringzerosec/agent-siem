// engineer.js — "your security engineer": a conversational agent that answers
// questions about the fleet, drives the dashboard while it explains, and can
// hand an alert to the triage agent or take an action when you agree.
//
// Two kinds of tools:
//   - graph tools, through MCP (the same server as the triage agent and /mcp);
//   - screen tools, which the browser executes (open an endpoint, spotlight an
//     attack path, select a node, show the event log...). They come back to the
//     browser as "ui" events in order, between the things the engineer says, so
//     the screen moves while the engineer is talking about it.
//
// Each reply is spoken (Kokoro, src/tts.js), so the prompt asks for plain
// spoken English: short sentences, no markdown, no ids read aloud.
//
//   ENGINEER_MODEL=claude-opus-5-5 (default)

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from './mcp-tools.js';

const MODEL = process.env.ENGINEER_MODEL || 'claude-opus-5-5';
const MAX_TURNS = 12;

const SYSTEM = `You are the user's own security engineer, sitting next to them at Agent SIEM, a security console for AI agents running on the company's endpoints. Ring Zero Security runs on each endpoint, records every action an agent takes into a FalkorDB provenance graph (process spawned, file read or written, program run, network connection, MCP tool call), and enforces policy: an edge with "allowed": false was blocked.

You talk out loud. Everything you write is spoken by a text-to-speech voice, so:
- Speak like a calm, senior colleague. Keep each reply to three short sentences at most, then stop and offer to go deeper ("Want me to check where else that key went?"). The screen carries the detail; your voice carries the point. A narration line before a screen move ("Let me pull that up.") does not count toward the three.
- Always say the product name in full: "Ring Zero Security", never "Ring Zero".
- No markdown, no bullet lists, no headings, no emoji, no code.
- Never read ids, node numbers, hashes or timestamps aloud. Say "about ten minutes ago", "the SSH private key", "the curl process".
- Say hostnames naturally: "ML WKS zero zero nine six", or the team, "the ML Research laptop".
- Lead with the answer, then the one or two facts that matter, then what you'd do next.

You drive the screen while you talk. Before explaining something, show it: open_endpoint, focus_alert to spotlight an attack path, highlight_nodes to point at specific nodes, select_node to open a node's timeline, show_events for the raw log, show_wall to go back. Say one short sentence before a screen move ("Let me pull that up.") so the user hears you while it loads. Use the screen context you are given to resolve "this", "here", "that one".

Use the graph tools for every fact. Never guess. get_alert for the path, secret_followups and host_fleet_exposure for whether it went further across the fleet, process_timeline for what the agent did around it, fleet_risk_rank for what matters most. list_alerts to see what is open.

Actions change things: block_host, contain_session, open_ticket, mark_false_positive. Propose them and wait for the user to say yes, unless they already asked you to do it. Never block an approved host. For a full written investigation of one alert, use run_triage, which starts the triage agent on screen.

If you don't know, say so and say what you'd check.`;

// Screen tools: the browser executes these; here they only describe themselves.
const SCREEN_TOOLS = [
  { name: 'show_wall', description: 'Go to the wall of all endpoints, optionally filtered to critical or high.', input_schema: { type: 'object', properties: { filter: { type: 'string', enum: ['all', 'critical', 'high'] } } } },
  { name: 'open_endpoint', description: 'Open one endpoint: its provenance graph, alerts, and summary.', input_schema: { type: 'object', properties: { device: { type: 'string' } }, required: ['device'] } },
  { name: 'focus_alert', description: 'Open an endpoint and spotlight one alert: its attack path stays lit, the rest of the graph fades, and the alert expands with its response.', input_schema: { type: 'object', properties: { device: { type: 'string' }, alert_id: { type: 'string' } }, required: ['device', 'alert_id'] } },
  { name: 'highlight_nodes', description: 'On the open endpoint, light up specific nodes (and the edges between them) to point at what you are explaining.', input_schema: { type: 'object', properties: { node_ids: { type: 'array', items: { type: 'integer' } } }, required: ['node_ids'] } },
  { name: 'select_node', description: 'Select one node on the open endpoint and show its timeline and blast radius in the side panel.', input_schema: { type: 'object', properties: { node_id: { type: 'integer' } }, required: ['node_id'] } },
  { name: 'zoom_out', description: 'Clear any spotlight and show the whole graph of the open endpoint.', input_schema: { type: 'object', properties: {} } },
  { name: 'show_events', description: 'Show the event log, optionally only events on alert paths or refused events, for one endpoint, or matching text.', input_schema: { type: 'object', properties: { filter: { type: 'string', enum: ['all', 'alert', 'refused'] }, device: { type: 'string' }, query: { type: 'string' } } } },
  { name: 'set_time_range', description: 'Change the time range of everything on screen.', input_schema: { type: 'object', properties: { range: { type: 'string', enum: ['24h', 'today', 'yesterday', '7d', 'all'] } }, required: ['range'] } },
  { name: 'run_triage', description: 'Start the triage agent on one alert; its step-by-step investigation and verdict appear in the side panel.', input_schema: { type: 'object', properties: { device: { type: 'string' }, alert_id: { type: 'string' } }, required: ['device', 'alert_id'] } },
];
const SCREEN = new Set(SCREEN_TOOLS.map((t) => t.name));

const conversations = new Map();   // sid -> messages
const jobs = new Map(); let seq = 0;
export const getEngineerJob = (id) => jobs.get(id);

export function ask({ sid, message, screen }) {
  const id = `e${++seq}`;
  const job = { id, sid, status: 'running', events: [], started: Date.now() };
  jobs.set(id, job);
  if (jobs.size > 100) jobs.delete(jobs.keys().next().value);
  run(job, message, screen).catch((e) => { job.events.push({ type: 'error', text: e.message }); job.status = 'error'; })
    .finally(() => { if (job.status === 'running') job.status = 'done'; job.finished = Date.now(); });
  return job;
}
export function reset(sid) { conversations.delete(sid); }

const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…(truncated)' : s);

async function run(job, message, screen) {
  if (!process.env.ANTHROPIC_API_KEY) { job.events.push({ type: 'say', text: 'I need an Anthropic API key to talk. Start the server with ANTHROPIC_API_KEY set.' }); return; }
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const anthropic = new Anthropic();
  const server = createMcpServer({ actor: `security-engineer (${MODEL})` });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'agent-siem-engineer', version: '0.1.0' });
  await client.connect(ct);
  try {
    const { tools } = await client.listTools();
    const graphTools = tools.filter((t) => t.name !== 'submit_verdict').map((t) => ({ name: t.name, description: t.description, input_schema: t.inputSchema }));
    const allTools = [...SCREEN_TOOLS, ...graphTools];
    const messages = conversations.get(job.sid) || [];
    messages.push({ role: 'user', content: `${message}\n\n[screen right now: ${JSON.stringify(screen || {})}]` });
    for (let turn = 0; turn < MAX_TURNS; turn++) {
      const resp = await anthropic.messages.create({ model: MODEL, max_tokens: 700, system: SYSTEM, tools: allTools, messages });
      if (resp.stop_reason === 'refusal') { job.events.push({ type: 'say', text: "I can't go further on that one. Try the triage agent on the alert." }); break; }
      messages.push({ role: 'assistant', content: resp.content });
      const results = [];
      for (const b of resp.content) {
        if (b.type === 'text' && b.text.trim()) job.events.push({ type: 'say', text: b.text.trim() });
        if (b.type !== 'tool_use') continue;
        if (SCREEN.has(b.name)) {
          job.events.push({ type: 'ui', tool: b.name, args: b.input });
          results.push({ type: 'tool_result', tool_use_id: b.id, content: `The screen now shows ${b.name.replace(/_/g, ' ')} ${JSON.stringify(b.input)}.` });
        } else {
          job.events.push({ type: 'tool', tool: b.name, args: b.input });
          const res = await client.callTool({ name: b.name, arguments: b.input });
          const txt = res.content?.[0]?.text || '';
          results.push({ type: 'tool_result', tool_use_id: b.id, content: clip(txt, 6000), is_error: !!res.isError });
          if (['block_host', 'contain_session', 'open_ticket', 'mark_false_positive'].includes(b.name) && !res.isError) job.events.push({ type: 'action', tool: b.name, args: b.input });
        }
      }
      if (!results.length) break;
      messages.push({ role: 'user', content: results });
    }
    // Keep the conversation, but trim old tool payloads so it stays small.
    // Thinking blocks are signed against the exact content before them, so
    // trimming would invalidate them; past-turn thinking isn't needed anyway.
    conversations.set(job.sid, messages.slice(-40).map((m) => (Array.isArray(m.content)
      ? { ...m, content: m.content.filter((c) => c.type !== 'thinking' && c.type !== 'redacted_thinking').map((c) => (c.type === 'tool_result' && typeof c.content === 'string' ? { ...c, content: clip(c.content, 1500) } : c)) }
      : m)).filter((m) => !Array.isArray(m.content) || m.content.length));
    // The history must start with a plain user message.
    const h = conversations.get(job.sid);
    while (h.length && !(h[0].role === 'user' && typeof h[0].content === 'string')) h.shift();
  } finally { await client.close(); await server.close(); }
}
