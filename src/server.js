// server.js — HTTP API + live updates for the dashboard.
//
//   POST /api/events            ingest a JSON array of events (or one event)
//   GET  /api/devices           every device with its alert counts (the wall)
//   GET  /api/graph/device/:id  one device's whole graph (all its sessions) + alerts
//   GET  /api/sessions          every session with its alert counts
//   GET  /api/graph/:session    nodes + edges of one session, plus its alerts
//   GET  /api/node/:id          one node's details, timeline and 2-hop blast radius
//   GET  /api/alerts            all alerts across sessions, newest first
//   GET  /api/stream            server-sent events: {session} after each ingest
//   GET  /api/bus               ingest mode and JetStream backlog (NATS_URL)
//   POST /api/reset             wipe the graph (demo convenience)

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, g, gr, wipe } from './db.js';
import { ingestMany, ingestMcpServers, ingestNotes, ingestSkills } from './ingest.js';
import * as bus from './bus.js';
import { authMiddleware, siemToken } from './auth.js';
import { startTriage, getJob, listJobs } from './triage.js';
import { createMcpServer } from './mcp-tools.js';
import { mountPepper, pepperHeadsUp } from './pepper.js';
import { syncFindings, campaigns, indicatorIntel, backfillResolution } from './intel.js';
import { aiUsage } from './aiusage.js';
import { onFinding, onDecision, listDecisions, approveDecision, dismissDecision, setOwners } from './autopilot.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { detect, detectDevice, blastRadius, invalidate, recompute, THREATS } from './detect.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);

const app = express();
// A slow graph query must never pin a browser connection: answer 503 after
// 10 s so the client can retry, and recycle idle keep-alive sockets quickly.
app.use((req, res, next) => { res.setTimeout(10000, () => { if (!res.headersSent) { res.status(503).json({ error: 'timeout' }); } }); next(); });
// In-flight request table, for diagnosing stalls: GET /api/_inflight
const inflight = new Map(); let reqSeq = 0;
app.use((req, res, next) => { const id = ++reqSeq; inflight.set(id, { path: req.originalUrl.slice(0, 80), at: Date.now() }); res.on('close', () => inflight.delete(id)); next(); });
app.get('/api/_inflight', (_req, res) => res.json([...inflight.values()].map((r) => ({ ...r, ms: Date.now() - r.at })).sort((a, b) => b.ms - a.ms)));
app.use(authMiddleware());   // one shared token for the dashboard, the API and /mcp (src/auth.js)
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- time window ---------------------------------------------------------
// ?from=<ms>&to=<ms> on reads; default is the last GRAPH_WINDOW_HOURS (24).
function windowOf(q) {
  const hours = Number(process.env.GRAPH_WINDOW_HOURS || 24);
  const to = q.to ? Number(q.to) : Date.now() + 60_000;
  const from = q.from ? Number(q.from) : (q.to ? 0 : Date.now() - hours * 3600 * 1000);
  return { from, to };
}

// --- live stream ---------------------------------------------------------
// Change log for polling clients: no long-lived connection per tab, so open
// tabs never exhaust the browser's 6-connections-per-host pool.
let changeSeq = 0; const changes = [];
function recordChange(msg) { changes.push({ seq: ++changeSeq, ...msg }); if (changes.length > 500) changes.shift(); }
app.get('/api/changes', (req, res) => {
  const since = Number(req.query.since || 0);
  res.json({ seq: changeSeq, changes: since ? changes.filter((c) => c.seq > since) : [] });
});

const clients = new Set();
function broadcast(msg) {
  recordChange(msg);
  const line = `data: ${JSON.stringify(msg)}\n\n`;
  for (const res of clients) res.write(line);
}

// Retired: live updates are polled from /api/changes. 204 tells any old tab's
// EventSource to stop reconnecting, so it releases its connection slot.
app.get('/api/stream', (_req, res) => res.status(204).end());

// Detection runs off the request path, one session at a time, each session
// at most once every 10 s. Page reads only ever see cached results, so rule
// queries can never queue a page load.
const dirtySessions = new Set(); const lastRun = new Map(); let detectBusy = false;
const hotSessions = new Set();   // sessions with fresh events run before the startup backlog
function scheduleDetect(session, hot = true) { (hot ? hotSessions : dirtySessions).add(session); }
setInterval(async () => {
  if (detectBusy || (!dirtySessions.size && !hotSessions.size)) return;
  const now = Date.now();
  const ready = (s) => now - (lastRun.get(s) || 0) >= 10000;
  let next = [...hotSessions].find(ready), from = hotSessions;
  if (!next) { next = [...dirtySessions].find(ready); from = dirtySessions; }
  if (!next) return;
  from.delete(next); dirtySessions.delete(next); lastRun.set(next, now); detectBusy = true;
  try {
    const alerts = await recompute(next);
    const dr = await gr().roQuery('MATCH (d:Device)-[:RUNS]->(s:Session {id: $session}) RETURN d.id AS id', { params: { session: next } });
    const dev = dr.data?.[0]?.id;
    broadcast({ type: 'update', device: dev, session: next, alerts: alerts.length });
    if (dev) await announceNew(dev);
  } catch (e) { console.error('detect', next, e.message); }
  finally { detectBusy = false; }
}, 250);

// New critical/high alerts become a change-log entry ('alert'), so a browser
// with Pepper asleep can wake it, and a heads-up for any live Pepper session.
// Alerts that already existed at startup are not announced.
const announced = new Set(); let announceReady = false;
async function announceNew(device) {
  try { await syncFindings(device, await detectDevice(device, { from: 0, to: Date.now() + 60_000 })); } catch (e) { console.error('intel sync', device, e.message); }
  const all = await detectDevice(device, { from: Date.now() - 6 * 3600 * 1000, to: Date.now() + 60_000 });
  for (const a of all) {
    if (!['critical', 'high'].includes(a.severity) || announced.has(a.id)) continue;
    announced.add(a.id);
    if (!announceReady) continue;
    const said = `Heads-up: new ${a.severity} alert on ${device}: ${a.title}. ${a.blocked === true ? 'You (the enforcement brain) blocked it.' : a.blocked === false ? 'You did not block it.' : ''}`;
    if (process.env.AUTOPILOT === 'off') {
      broadcast({ type: 'alert', device, alert: { id: a.id, severity: a.severity, title: a.title, blocked: a.blocked ?? null }, text: said });
      pepperHeadsUp(said, { tool: 'focus_alert', args: { device, alert_id: a.id } });
    } else onFinding(device, a);   // investigated first; Pepper speaks when the analysis is done
  }
}
setTimeout(async () => {   // seed with what exists, then start announcing
  try { for (const row of (await gr().roQuery('MATCH (d:Device) RETURN d.id AS id')).data || []) await announceNew(row.id); } catch { /* best effort */ }
  announceReady = true;
  backfillResolution().catch((e) => console.error('intel backfill', e.message));
}, 15000);

// Autopilot finished an investigation: the decision goes to the inbox (change
// log, so an asleep Pepper can wake) and to any live Pepper session.
onDecision((d) => {
  const say = `Analysis finished for ${d.headline} ${d.verdict_summary || ''} Proposed next step${d.proposals.length > 1 ? 's' : ''}: ${d.proposals.join('; ') || 'none'}. Ask whether to go ahead (decision ${d.id}).`;
  broadcast({ type: 'decision', device: d.device, decision: { id: d.id, headline: d.headline, proposals: d.proposals }, text: say });
  pepperHeadsUp(say, { tool: 'show_inbox', args: { decision: d.id } });
});

// --- ingest --------------------------------------------------------------
// With NATS_URL set, POSTs are published to JetStream and answered 202 once
// stored; the graph writer below drains the stream in batches. Without it,
// POSTs write straight to the graph (single-process demo mode).
async function writeEvents(events) {
  const sessions = await ingestMany(events);
  for (const session of sessions) scheduleDetect(session);
  return sessions;
}
async function writeMcp(servers) {
  await ingestMcpServers(servers);
  for (const d of new Set(servers.map((m) => String(m.device)))) broadcast({ type: 'update', device: d });
}
async function writeNotes(notes) {
  await ingestNotes(notes);
  for (const d of new Set(notes.map((n) => String(n.device)))) broadcast({ type: 'note', device: d });
}
const asArray = (b) => (Array.isArray(b) ? b : [b]);

app.post('/api/events', async (req, res, next) => {
  try {
    const events = asArray(req.body);
    if (bus.enabled()) { await bus.publishEvents(events); return res.status(202).json({ queued: events.length }); }
    res.json({ ingested: events.length, sessions: await writeEvents(events) });
  } catch (e) { next(e); }
});

app.post('/api/mcp-servers', async (req, res, next) => {
  try {
    const servers = asArray(req.body);
    if (bus.enabled()) { await bus.publishArray('mcp', servers); return res.status(202).json({ queued: servers.length }); }
    await writeMcp(servers); res.json({ ingested: servers.length });
  } catch (e) { next(e); }
});

app.post('/api/notes', async (req, res, next) => {
  try {
    const notes = asArray(req.body);
    if (bus.enabled()) { await bus.publishArray('notes', notes); return res.status(202).json({ queued: notes.length }); }
    await writeNotes(notes); res.json({ ingested: notes.length });
  } catch (e) { next(e); }
});

// --- Pepper: full-duplex voice (OpenAI GPT-Live) ------------------------------
mountPepper(app);

// --- triage agent ----------------------------------------------------------
app.post('/api/triage', (req, res) => {
  const { device, alert_id: alertId } = req.body || {};
  if (!device || !alertId) return res.status(400).json({ error: 'device and alert_id are required' });
  const job = startTriage({ device: String(device), alertId: String(alertId) });
  res.status(202).json({ id: job.id, mode: job.mode, model: job.model });
});
app.get('/api/triage/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'no such triage run' });
  res.json(job);
});
// Stored verdicts, actions and tickets for an endpoint (survive restarts).
app.get('/api/triage', async (req, res, next) => {
  try {
    const device = String(req.query.device || '');
    const r = await gr().roQuery(
      `MATCH (d:Device {id: $device})-[:TRIAGED|ACTION|TICKET]->(x)
       RETURN labels(x)[0] AS kind, x ORDER BY x.ts DESC LIMIT 100`, { params: { device } });
    res.json({ running: listJobs(device).filter((j) => j.status === 'running').map((j) => ({ id: j.id, alertId: j.alertId })),
      records: (r.data || []).map((row) => ({ kind: row.kind, id: row.x.id, ...row.x.properties })) });
  } catch (e) { next(e); }
});

// The same graph tools over MCP Streamable HTTP, for any outside MCP client
// (Claude Code, Claude Desktop, Cursor):  claude mcp add --transport http agent-siem http://localhost:8080/mcp
app.post('/mcp', async (req, res) => {
  const server = createMcpServer({ actor: `mcp-client:${req.get('user-agent') || 'unknown'}`.slice(0, 80) });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
  catch (e) { if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: e.message }, id: null }); }
});
app.get('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Use POST (stateless Streamable HTTP).' }, id: null }));

async function writeSkills(items) {
  await ingestSkills(items);
  for (const d of new Set(items.map((k) => String(k.device)))) broadcast({ type: 'update', device: d });
}
app.post('/api/skills', async (req, res, next) => {
  try {
    const items = asArray(req.body);
    if (bus.enabled()) { await bus.publishArray('skills', items); return res.status(202).json({ queued: items.length }); }
    await writeSkills(items); res.json({ ingested: items.length });
  } catch (e) { next(e); }
});
// MCP servers (declared, approved?, tool calls, blocked) and skills for one endpoint.
app.get('/api/surface/:device', async (req, res, next) => {
  try {
    const device = req.params.device;
    const mr = await gr().roQuery(
      `MATCH (d:Device {id: $device})
       OPTIONAL MATCH (d)-[:DECLARES]->(m:McpServer)
       WITH d, collect(m) AS declared
       OPTIONAL MATCH (d)-[:RUNS]->(:Session)-[:HAS]->(:Process)-[u:USED_TOOL]->(t:McpTool)
       WITH declared, t.server AS server, count(u) AS calls, sum(CASE WHEN u.allowed = false THEN 1 ELSE 0 END) AS refused, collect(DISTINCT t.name)[0..8] AS tools
       RETURN declared, collect({server: server, calls: calls, refused: refused, tools: tools}) AS used`, { params: { device } });
    const row = mr.data?.[0] || { declared: [], used: [] };
    const approved = new Set((process.env.APPROVED_MCP || 'filesystem,github,postgres').split(',').map((x) => x.trim()));
    const servers = new Map();
    for (const m of row.declared || []) servers.set(m.properties.name, { name: m.properties.name, declared: true, approved: !!m.properties.approved, held: !!m.properties.held, transport: m.properties.transport, agent: m.properties.agent, calls: 0, refused: 0, tools: [] });
    for (const u of row.used || []) {
      if (!u.server) continue;
      const cur = servers.get(u.server) || { name: u.server, declared: false, approved: approved.has(u.server), held: false, calls: 0, refused: 0, tools: [] };
      Object.assign(cur, { calls: u.calls, refused: u.refused, tools: u.tools }); servers.set(u.server, cur);
    }
    const sk = await gr().roQuery('MATCH (d:Device {id: $device})-[:HAS_SKILL]->(s:Skill) RETURN s ORDER BY s.finding_count DESC', { params: { device } });
    res.json({ mcp: [...servers.values()].sort((a, b) => (a.approved - b.approved) || (b.calls - a.calls)),
      skills: (sk.data || []).map((x) => ({ id: x.s.id, ...x.s.properties, findings: (() => { try { return JSON.parse(x.s.properties.findings || '[]'); } catch { return []; } })() })) });
  } catch (e) { next(e); }
});

// Threat-actor intelligence: campaigns (algo.WCC over findings and shared
// infrastructure) and everything known about one indicator.
app.get('/api/campaigns', async (_req, res, next) => { try { res.json(await campaigns()); } catch (e) { next(e); } });
app.get('/api/intel/:value', async (req, res, next) => { try { res.json(await indicatorIntel(req.params.value)); } catch (e) { next(e); } });

app.get('/api/ai-usage', async (req, res, next) => {
  try { res.json(await aiUsage(req.query.device || null, Number(req.query.from || 0))); } catch (e) { next(e); }
});

// Decision inbox (autopilot): pending analyses waiting for a yes.
app.get('/api/decisions', async (req, res, next) => { try { res.json(await listDecisions(req.query.status || null)); } catch (e) { next(e); } });
app.post('/api/decisions/:id/approve', async (req, res, next) => { try { res.json(await approveDecision(req.params.id, { only: req.body?.only, actor: 'dashboard user' })); } catch (e) { next(e); } });
app.post('/api/decisions/:id/dismiss', async (req, res, next) => { try { res.json(await dismissDecision(req.params.id, String(req.body?.reason || ''), 'dashboard user')); } catch (e) { next(e); } });
// Who owns each endpoint (for escalations): [{device, name, email, manager, team}]
app.post('/api/owners', async (req, res, next) => { try { const rows = asArray(req.body); await setOwners(rows); res.json({ ok: rows.length }); } catch (e) { next(e); } });

app.get('/api/bus', async (_req, res, next) => {
  try { res.json(bus.enabled() ? { mode: 'nats-jetstream', ...(await bus.stats()) } : { mode: 'direct' }); } catch (e) { next(e); }
});

// Live session feed: prompts and the daemon's narrative, newest last.
app.get('/api/feed/:device', async (req, res, next) => {
  try {
    const id = req.params.device;
    const r = await gr().roQuery(
      `MATCH (d:Device {id: $id})-[:RUNS]->(s:Session)
       OPTIONAL MATCH (s)-[:HAS]->(p:Process)-[:PROMPTED]->(q:Prompt)
       OPTIONAL MATCH (s)-[:NOTED]->(n:Note)
       WITH s, collect(DISTINCT {kind: 'prompt', ts: q.ts, text: q.text, model: q.model, provider: q.provider, tool: q.tool_call, flagged: q.flagged, via: p.name}) AS prompts,
            collect(DISTINCT {kind: 'note', ts: n.ts, text: n.text, level: n.level, nkind: n.kind, agent: n.agent}) AS notes
       RETURN s.id AS session, s.agent AS agent, prompts, notes`,
      { params: { id } },
    );
    const { from, to } = windowOf(req.query);
    const items = [];
    for (const row of r.data || []) {
      for (const p of row.prompts) if (p.ts && p.ts >= from && p.ts <= to) items.push({ session: row.session, ...p });
      for (const n of row.notes) if (n.ts && n.ts >= from && n.ts <= to) items.push({ session: row.session, ...n });
    }
    items.sort((a, b) => a.ts - b.ts);
    res.json({ device: id, items: items.slice(-300) });
  } catch (e) { next(e); }
});

app.get('/api/threats', (_req, res) => res.json(THREATS));

// SIEM view: every action as a flat, filterable event row.
//   ?from&to&device&agent&kind=READ|WROTE|EXECUTED|CONNECTED|SENT|RESOLVED|USED_TOOL|INSTALLED|DELETED|TAMPERED
//   &outcome=allowed|refused&q=<substring on target/process>&limit=500&format=json|cef
// edge id -> the worst alert whose path runs through it (info findings skipped).
// Built from the cached detection results, so it costs no rule queries.
const SEV_RANK = { critical: 0, high: 1, medium: 2 };
async function alertEdges(win, device) {
  const ids = device ? [device] : ((await gr().roQuery('MATCH (d:Device) RETURN d.id AS id')).data || []).map((x) => x.id);
  const map = new Map();
  for (const id of ids) {
    for (const a of await detectDevice(id, win)) {
      if (!(a.severity in SEV_RANK)) continue;
      for (const e of a.edges) {
        const prev = map.get(e);
        if (!prev || SEV_RANK[a.severity] < SEV_RANK[prev.severity]) map.set(e, { severity: a.severity, threat: a.threat, title: a.title, blocked: a.blocked });
      }
    }
  }
  return map;
}

app.get('/api/events', async (req, res, next) => {
  try {
    const { from, to } = windowOf(req.query);
    const onPath = await alertEdges({ from, to }, req.query.device || null);
    const pathOnly = req.query.outcome === 'alert';
    const limit = Math.min(Number(req.query.limit || 500), 5000);
    const kinds = req.query.kind ? String(req.query.kind).split(',') : null;
    const r = await gr().roQuery(
      `MATCH (d:Device)-[:RUNS]->(s:Session)-[:HAS]->(p:Process)-[e]->(m)
       WHERE e.ts >= $from AND e.ts <= $to AND NOT m:Session
         AND ($device IS NULL OR d.id = $device)
         AND ($agent IS NULL OR s.agent = $agent)
         AND ($kinds IS NULL OR type(e) IN $kinds)
         AND ($allowed IS NULL OR coalesce(e.allowed, true) = $allowed)
         AND ($ids IS NULL OR ID(e) IN $ids)
       WITH d, s, p, e, m,
            CASE WHEN m:File THEN m.path WHEN m:Host THEN m.name WHEN m:McpTool THEN m.server + '/' + m.name
                 WHEN m:Package THEN m.ecosystem + ':' + m.name + '@' + m.version WHEN m:Tamper THEN m.what ELSE '' END AS target,
            labels(m)[0] AS targetKind
       WHERE $q IS NULL OR toLower(target) CONTAINS toLower($q) OR toLower(p.name) CONTAINS toLower($q) OR toLower(coalesce(e.argv, '')) CONTAINS toLower($q)
       RETURN e.ts AS ts, d.id AS device, d.simulated AS simulated, s.id AS session, s.agent AS agent, p.name AS process, p.pid AS pid,
              type(e) AS action, target, targetKind, coalesce(e.allowed, true) AS allowed, e.reason AS reason, e.argv AS argv, e.port AS port,
              coalesce(m.sensitive, false) AS sensitive, coalesce(m.approved, true) AS approved, coalesce(m.vuln_count, 0) AS vulns,
              ID(m) AS targetId, ID(p) AS processId, ID(e) AS edgeId
       ORDER BY e.ts DESC LIMIT $limit`,
      { params: { from, to, device: req.query.device || null, agent: req.query.agent || null, kinds, allowed: req.query.outcome === 'allowed' ? true : req.query.outcome === 'refused' ? false : null, q: req.query.q || null, limit, ids: pathOnly ? [...onPath.keys()] : null } },
    );
    const rows = (r.data || []).map((x) => ({ ...x, alert: onPath.get(x.edgeId) || null }));
    if (req.query.format === 'cef') {
      const esc = (v) => String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\|/g, '\\|');
      const lines = rows.map((x) => `CEF:0|Ring Zero Security|Agent SIEM|0.1|${x.alert ? 'alert:' + x.alert.threat : x.action}|${x.alert ? esc(x.alert.title) : x.action + ' ' + x.targetKind}|${x.alert ? { critical: 10, high: 8, medium: 6 }[x.alert.severity] : x.allowed ? 3 : 7}|rt=${x.ts} dvc=${esc(x.device)} suser=${esc(x.agent)} sproc=${esc(x.process)} spid=${x.pid} act=${x.allowed ? 'allowed' : 'refused'} fname=${esc(x.target)} reason=${esc(x.reason || '')} cs1Label=session cs1=${esc(x.session)}${x.alert ? ` cs2Label=threat cs2=${x.alert.threat} cs3Label=severity cs3=${x.alert.severity}` : ''}`);
      res.type('text/plain').send(lines.join('\n'));
      return;
    }
    // Same filters as the alert-path view, so the shortcut's number matches what it shows.
    let alertEvents = 0;
    if (onPath.size) {
      const c = await gr().roQuery(
        `MATCH (d:Device)-[:RUNS]->(:Session)-[:HAS]->(p:Process)-[e]->(m)
         WHERE ID(e) IN $ids AND e.ts >= $from AND e.ts <= $to AND NOT m:Session AND ($device IS NULL OR d.id = $device)
         RETURN count(e) AS n`,
        { params: { ids: [...onPath.keys()], from, to, device: req.query.device || null } },
      );
      alertEvents = c.data?.[0]?.n || 0;
    }
    res.json({ window: { from, to }, count: rows.length, alertEvents, events: rows });
  } catch (e) { next(e); }
});

// Distinct filter values for the SIEM filter bar.
app.get('/api/facets', async (_req, res, next) => {
  try {
    const r = await gr().roQuery('MATCH (d:Device)-[:RUNS]->(s:Session) RETURN collect(DISTINCT d.id) AS devices, collect(DISTINCT s.agent) AS agents');
    res.json({ devices: r.data?.[0]?.devices || [], agents: r.data?.[0]?.agents || [], actions: ['READ', 'WROTE', 'DELETED', 'EXECUTED', 'CONNECTED', 'SENT', 'RESOLVED', 'USED_TOOL', 'INSTALLED', 'TAMPERED'] });
  } catch (e) { next(e); }
});

// Remove one device and everything under it (sessions, processes, their
// files/hosts/tools are kept if another device touched them too).
app.delete('/api/device/:id', async (req, res, next) => {
  try {
    await g().query(
      `MATCH (d:Device {id: $id})
       OPTIONAL MATCH (d)-[:RUNS]->(s:Session)
       OPTIONAL MATCH (s)-[:HAS]->(p:Process)
       OPTIONAL MATCH (p)-[:PROMPTED]->(q:Prompt)
       OPTIONAL MATCH (s)-[:NOTED]->(n:Note)
       OPTIONAL MATCH (d)-[:DECLARES]->(m:McpServer)
       DETACH DELETE q, n, m, p, s, d`,
      { params: { id: req.params.id } },
    );
    await g().query('MATCH (x) WHERE (x:File OR x:Host OR x:McpTool OR x:Package OR x:Tamper) AND NOT (x)--() DELETE x');
    broadcast({ type: 'reset' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/reset', async (_req, res, next) => {
  try { await wipe(); (await import('./detect.js')).forget(); broadcast({ type: 'reset' }); res.json({ ok: true }); } catch (e) { next(e); }
});

// --- reads ---------------------------------------------------------------
app.get('/api/devices', async (req, res, next) => {
  try {
    const { from, to } = windowOf(req.query);
    const r = await gr().roQuery(
      // p.last_ts (kept at ingest) skips idle processes without walking their
      // edges: an endpoint with months of history costs nothing when quiet.
      `MATCH (d:Device)
       OPTIONAL MATCH (d)-[:RUNS]->(s:Session)
       WITH d, count(DISTINCT s) AS sessions, collect(DISTINCT s.agent) AS agents
       OPTIONAL MATCH (d)-[:RUNS]->(:Session)-[:HAS]->(p:Process) WHERE coalesce(p.last_ts, p.first_ts) >= $from
       OPTIONAL MATCH (p)-[e]->() WHERE e.ts >= $from AND e.ts <= $to
       WITH d, sessions, agents, count(DISTINCT p) AS procs, count(e) AS actions, max(e.ts) AS last
       RETURN d.id AS id, d.owner AS owner, d.simulated AS simulated, sessions, procs, actions, last, agents
       ORDER BY d.simulated, coalesce(last, 0) DESC, d.id`,
      { params: { from, to } },
    );
    const out = [];
    for (const row of r.data || []) {
      const all = await detectDevice(row.id, { from, to });
      const alerts = all.filter((a) => a.severity !== 'info');   // info findings never count on the wall
      const threats = {};
      for (const a of alerts) threats[a.threat] = (threats[a.threat] || 0) + 1;
      out.push({
        ...row,
        alerts: alerts.length,
        critical: alerts.filter((a) => a.severity === 'critical').length,
        high: alerts.filter((a) => a.severity === 'high').length,
        contained: alerts.filter((a) => a.blocked === true).length,
        info: all.length - alerts.length,
        threats,
        top: alerts[0]?.summary || null,
      });
    }
    res.json(out);
  } catch (e) { next(e); }
});

// Device graph is windowed: the last `hours` of activity (default 24) and at
// most `cap` edges (default 600, newest first), or a tile would try to draw
// months of history.
app.get('/api/graph/device/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const { from, to } = windowOf(req.query);
    const cap = Math.min(Number(req.query.cap || 600), 3000);
    const r = await gr().roQuery(
      `MATCH (d:Device {id: $id})
       WITH d MATCH (d)-[:RUNS]->(s:Session)-[:HAS]->(p:Process) WHERE coalesce(p.last_ts, p.first_ts) >= $from
       WITH s, p MATCH (p)-[e]->(m)
       WHERE NOT m:Session AND NOT m:Prompt AND coalesce(e.ts, p.first_ts) >= $from AND coalesce(e.ts, p.first_ts) <= $to
       OPTIONAL MATCH (m)-[e2:HAS_VULN]->(v:Vulnerability)
       RETURN s, p, e, m, e2, v
       ORDER BY e.ts DESC LIMIT $cap`,
      { params: { id, from, to, cap } },
    );
    const nodes = new Map();
    const edges = new Map();
    for (const row of r.data || []) {
      nodes.set(row.p.id, row.p);
      if (row.m) nodes.set(row.m.id, row.m);
      if (row.e) edges.set(row.e.id, row.e);
      if (row.v) nodes.set(row.v.id, row.v);
      if (row.e2) edges.set(row.e2.id, row.e2);
    }
    const alerts = await detectDevice(id, { from, to });
    // Every node and edge on an alert path is always in the picture, even when
    // the edge cap cut it (large endpoints have tens of thousands of edges).
    const needN = [...new Set(alerts.flatMap((a) => a.nodes))].filter((n) => !nodes.has(n));
    const needE = [...new Set(alerts.flatMap((a) => a.edges))].filter((e) => !edges.has(e));
    if (needN.length) for (const row of (await gr().roQuery('MATCH (n) WHERE id(n) IN $ids RETURN n', { params: { ids: needN } })).data || []) nodes.set(row.n.id, row.n);
    if (needE.length) {
      const src = [...new Set(alerts.flatMap((a) => a.nodes))];
      for (const row of (await gr().roQuery('MATCH (a)-[e]->() WHERE id(a) IN $src AND id(e) IN $ids RETURN e', { params: { src, ids: needE } })).data || []) edges.set(row.e.id, row.e);
    }
    res.json({ device: id, nodes: [...nodes.values()], edges: [...edges.values()], alerts, window: { from, to } });
  } catch (e) { next(e); }
});

app.get('/api/sessions', async (_req, res, next) => {
  try {
    const r = await gr().roQuery(
      `MATCH (s:Session)
       OPTIONAL MATCH (s)-[:HAS]->(p:Process)
       OPTIONAL MATCH (p)-[e]->()
       WITH s, count(DISTINCT p) AS procs, count(e) AS actions, max(e.ts) AS last
       RETURN s.id AS id, s.agent AS agent, s.started AS started, procs, actions, last
       ORDER BY last DESC`,
    );
    const out = [];
    for (const row of r.data || []) {
      const alerts = await detect(row.id, undefined, { cachedOnly: true });
      out.push({
        ...row,
        alerts: alerts.length,
        critical: alerts.filter((a) => a.severity === 'critical').length,
        high: alerts.filter((a) => a.severity === 'high').length,
        top: alerts[0]?.summary || null,
      });
    }
    res.json(out);
  } catch (e) { next(e); }
});

app.get('/api/graph/:session', async (req, res, next) => {
  try {
    const session = req.params.session;
    const r = await gr().roQuery(
      `MATCH (s:Session {id: $session})-[:HAS]->(p:Process)
       OPTIONAL MATCH (p)-[e]->(m) WHERE NOT m:Session
       RETURN p, e, m`,
      { params: { session } },
    );
    const nodes = new Map();
    const edges = new Map();
    for (const row of r.data || []) {
      nodes.set(row.p.id, row.p);
      if (row.m) nodes.set(row.m.id, row.m);
      if (row.e) edges.set(row.e.id, row.e);
    }
    const alerts = await detect(session, undefined, { cachedOnly: true });
    res.json({ session, nodes: [...nodes.values()], edges: [...edges.values()], alerts });
  } catch (e) { next(e); }
});

app.get('/api/node/:id', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const nr = await gr().roQuery('MATCH (n) WHERE ID(n) = $id RETURN n', { params: { id } });
    const node = nr.data?.[0]?.n;
    if (!node) return res.status(404).json({ error: 'no such node' });
    const tl = await gr().roQuery(
      `MATCH (n) WHERE ID(n) = $id
       MATCH (n)-[e]-(m)
       RETURN type(e) AS action, e.ts AS ts, e.allowed AS allowed, e.argv AS argv, e.port AS port,
              startNode(e) = n AS outgoing, m
       ORDER BY e.ts`,
      { params: { id } },
    );
    const radius = await blastRadius(id, Number(req.query.hops || 2));
    res.json({ node, timeline: tl.data || [], radius });
  } catch (e) { next(e); }
});

app.get('/api/alerts', async (_req, res, next) => {
  try {
    const r = await g().roQuery('MATCH (s:Session) RETURN s.id AS id');
    const all = [];
    for (const row of r.data || []) {
      for (const a of await detect(row.id, undefined, { cachedOnly: true })) all.push({ session: row.id, ...a });
    }
    res.json(all);
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err.message);
  if (!res.headersSent) res.status(500).json({ error: err.message });
});

await connect();
// One-time backfill of p.last_ts / d.last_ts for graphs ingested before they existed.
{
  const r = await g().query(`MATCH (p:Process) WHERE p.last_ts IS NULL
    OPTIONAL MATCH (p)-[e]->() WITH p, max(e.ts) AS m SET p.last_ts = coalesce(m, p.first_ts) RETURN count(p) AS n`);
  const n = r.data?.[0]?.n || 0;
  if (n) {
    await g().query(`MATCH (d:Device)-[:RUNS]->(:Session)-[:HAS]->(p:Process) WITH d, max(p.last_ts) AS m SET d.last_ts = m`);
    console.log(`backfilled last activity on ${n} processes`);
  }
}
// Re-classify stored files when the sensitive-path rules change.
{
  const { isSensitive } = await import('./ingest.js');
  const r = await g().roQuery('MATCH (f:File) WHERE f.sensitive = true RETURN f.path AS path');
  const fixed = (r.data || []).map((x) => x.path).filter((p) => !isSensitive(p));
  for (let i = 0; i < fixed.length; i += 500) await g().query('UNWIND $paths AS p MATCH (f:File {path: p}) SET f.sensitive = false', { params: { paths: fixed.slice(i, i + 500) } });
  if (fixed.length) console.log(`reclassified ${fixed.length} files as not sensitive`);
}
{
  const { isRoutable } = await import('./ingest.js');
  const r = await g().roQuery('MATCH (h:Host) WHERE h.routable IS NULL RETURN h.name AS name');
  const rows = (r.data || []).map((x) => ({ name: x.name, ok: isRoutable(x.name) }));
  for (let i = 0; i < rows.length; i += 500) await g().query('UNWIND $rows AS x MATCH (h:Host {name: x.name}) SET h.routable = x.ok', { params: { rows: rows.slice(i, i + 500) } });
  if (rows.length) console.log(`classified ${rows.length} hosts (${rows.filter((x) => !x.ok).length} not routable)`);
}
// Approved hostnames → their current IPs, now and every 10 minutes; sessions
// that talked to a newly approved address get their alerts recomputed.
async function refreshIps() {
  try {
    const { refreshApprovedIps } = await import('./ingest.js');
    const r = await refreshApprovedIps();
    for (const id of r.sessions) scheduleDetect(id);
    if (r.learned || r.sessions.length) console.log(`approved IPs: +${r.learned} (${r.total} known), ${r.sessions.length} sessions to recheck`);
  } catch (e) { console.error('approved IPs', e.message); }
}
await refreshIps(); setInterval(refreshIps, 10 * 60 * 1000);
if (await bus.start()) bus.consume({ onEvents: writeEvents, onMcp: writeMcp, onNotes: writeNotes, onSkills: writeSkills });
{ const r = await gr().roQuery('MATCH (s:Session) RETURN s.id AS id ORDER BY coalesce(s.started, 0) DESC'); for (const row of r.data || []) scheduleDetect(row.id, false); }   // newest sessions first
const srv = app.listen(PORT, () => console.log(`agent-siem listening on http://localhost:${PORT}\n  sign in: http://localhost:${PORT}/?token=${process.env.SIEM_TOKEN ? '<SIEM_TOKEN>' : siemToken()}`));
srv.keepAliveTimeout = 5000; srv.headersTimeout = 11000;
