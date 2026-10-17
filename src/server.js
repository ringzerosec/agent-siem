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
//   POST /api/reset             wipe the graph (demo convenience)

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, g, gr, wipe } from './db.js';
import { ingestMany, ingestMcpServers, ingestNotes } from './ingest.js';
import { detect, detectDevice, blastRadius, invalidate, THREATS } from './detect.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);

const app = express();
// A slow graph query must never pin a browser connection: answer 503 after
// 10 s so the client can retry, and recycle idle keep-alive sockets quickly.
app.use((req, res, next) => { res.setTimeout(10000, () => { if (!res.headersSent) res.status(503).json({ error: 'timeout' }); }); next(); });
// In-flight request table, for diagnosing stalls: GET /api/_inflight
const inflight = new Map(); let reqSeq = 0;
app.use((req, res, next) => { const id = ++reqSeq; inflight.set(id, { path: req.originalUrl.slice(0, 80), at: Date.now() }); res.on('close', () => inflight.delete(id)); next(); });
app.get('/api/_inflight', (_req, res) => res.json([...inflight.values()].map((r) => ({ ...r, ms: Date.now() - r.at })).sort((a, b) => b.ms - a.ms)));
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

app.get('/api/stream', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(': connected\n\n');
  clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(ping); clients.delete(res); });
});

// Detection runs off the request path, at most once every 10 s per session,
// so a busy session cannot saturate the database with rule queries.
const pendingDetect = new Map();
function scheduleDetect(session) {
  if (pendingDetect.has(session)) return;
  pendingDetect.set(session, setTimeout(async () => {
    pendingDetect.delete(session);
    try {
      invalidate(session);
      const alerts = await detect(session);
      const dr = await g().roQuery('MATCH (d:Device)-[:RUNS]->(s:Session {id: $session}) RETURN d.id AS id', { params: { session } });
      broadcast({ type: 'update', device: dr.data?.[0]?.id, session, alerts: alerts.length, critical: alerts.filter((a) => a.severity === 'critical').length });
    } catch (e) { console.error('detect', session, e.message); }
  }, 10000));
}

// --- ingest --------------------------------------------------------------
app.post('/api/events', async (req, res, next) => {
  try {
    const events = Array.isArray(req.body) ? req.body : [req.body];
    const sessions = await ingestMany(events);
    res.json({ ingested: events.length, sessions });
    for (const session of sessions) scheduleDetect(session);
  } catch (e) { next(e); }
});

app.post('/api/mcp-servers', async (req, res, next) => {
  try {
    const servers = Array.isArray(req.body) ? req.body : [req.body];
    await ingestMcpServers(servers);
    for (const d of new Set(servers.map((m) => String(m.device)))) broadcast({ type: 'update', device: d });
    res.json({ ingested: servers.length });
  } catch (e) { next(e); }
});

app.post('/api/notes', async (req, res, next) => {
  try {
    const notes = Array.isArray(req.body) ? req.body : [req.body];
    await ingestNotes(notes);
    for (const d of new Set(notes.map((n) => String(n.device)))) broadcast({ type: 'note', device: d });
    res.json({ ingested: notes.length });
  } catch (e) { next(e); }
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
app.get('/api/events', async (req, res, next) => {
  try {
    const { from, to } = windowOf(req.query);
    const limit = Math.min(Number(req.query.limit || 500), 5000);
    const kinds = req.query.kind ? String(req.query.kind).split(',') : null;
    const r = await gr().roQuery(
      `MATCH (d:Device)-[:RUNS]->(s:Session)-[:HAS]->(p:Process)-[e]->(m)
       WHERE e.ts >= $from AND e.ts <= $to AND NOT m:Session
         AND ($device IS NULL OR d.id = $device)
         AND ($agent IS NULL OR s.agent = $agent)
         AND ($kinds IS NULL OR type(e) IN $kinds)
         AND ($allowed IS NULL OR coalesce(e.allowed, true) = $allowed)
       WITH d, s, p, e, m,
            CASE WHEN m:File THEN m.path WHEN m:Host THEN m.name WHEN m:McpTool THEN m.server + '/' + m.name
                 WHEN m:Package THEN m.ecosystem + ':' + m.name + '@' + m.version WHEN m:Tamper THEN m.what ELSE '' END AS target,
            labels(m)[0] AS targetKind
       WHERE $q IS NULL OR toLower(target) CONTAINS toLower($q) OR toLower(p.name) CONTAINS toLower($q) OR toLower(coalesce(e.argv, '')) CONTAINS toLower($q)
       RETURN e.ts AS ts, d.id AS device, d.simulated AS simulated, s.id AS session, s.agent AS agent, p.name AS process, p.pid AS pid,
              type(e) AS action, target, targetKind, coalesce(e.allowed, true) AS allowed, e.reason AS reason, e.argv AS argv, e.port AS port,
              coalesce(m.sensitive, false) AS sensitive, coalesce(m.approved, true) AS approved, coalesce(m.vuln_count, 0) AS vulns,
              ID(m) AS targetId, ID(p) AS processId
       ORDER BY e.ts DESC LIMIT $limit`,
      { params: { from, to, device: req.query.device || null, agent: req.query.agent || null, kinds, allowed: req.query.outcome === 'allowed' ? true : req.query.outcome === 'refused' ? false : null, q: req.query.q || null, limit } },
    );
    const rows = r.data || [];
    if (req.query.format === 'cef') {
      const esc = (v) => String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\|/g, '\\|');
      const lines = rows.map((x) => `CEF:0|Ring Zero Security|Agent SIEM|0.1|${x.action}|${x.action} ${x.targetKind}|${x.allowed ? 3 : 8}|rt=${x.ts} dvc=${esc(x.device)} suser=${esc(x.agent)} sproc=${esc(x.process)} spid=${x.pid} act=${x.allowed ? 'allowed' : 'refused'} fname=${esc(x.target)} reason=${esc(x.reason || '')} cs1Label=session cs1=${esc(x.session)}`);
      res.type('text/plain').send(lines.join('\n'));
      return;
    }
    res.json({ window: { from, to }, count: rows.length, events: rows });
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
  try { await wipe(); for (const k of [...(await import('./detect.js')).CACHE_KEYS()]) invalidate(k); broadcast({ type: 'reset' }); res.json({ ok: true }); } catch (e) { next(e); }
});

// --- reads ---------------------------------------------------------------
app.get('/api/devices', async (req, res, next) => {
  try {
    const { from, to } = windowOf(req.query);
    const r = await gr().roQuery(
      `MATCH (d:Device)
       OPTIONAL MATCH (d)-[:RUNS]->(s:Session)
       OPTIONAL MATCH (s)-[:HAS]->(p:Process)
       OPTIONAL MATCH (p)-[e]->() WHERE e.ts >= $from AND e.ts <= $to
       WITH d, count(DISTINCT s) AS sessions, count(DISTINCT p) AS procs, count(e) AS actions, max(e.ts) AS last,
            collect(DISTINCT s.agent) AS agents
       RETURN d.id AS id, d.owner AS owner, d.simulated AS simulated, sessions, procs, actions, last, agents
       ORDER BY d.simulated, coalesce(last, 0) DESC, d.id`,
      { params: { from, to } },
    );
    const out = [];
    for (const row of r.data || []) {
      const alerts = await detectDevice(row.id, { from, to });
      const threats = {};
      for (const a of alerts) threats[a.threat] = (threats[a.threat] || 0) + 1;
      out.push({
        ...row,
        alerts: alerts.length,
        critical: alerts.filter((a) => a.severity === 'critical').length,
        high: alerts.filter((a) => a.severity === 'high').length,
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
      `MATCH (d:Device {id: $id})-[:RUNS]->(s:Session)-[:HAS]->(p:Process)-[e]->(m)
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
      const alerts = await detect(row.id);
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
    const alerts = await detect(session);
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
      for (const a of await detect(row.id)) all.push({ session: row.id, ...a });
    }
    res.json(all);
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message });
});

await connect();
const srv = app.listen(PORT, () => console.log(`agent-siem listening on http://localhost:${PORT}`));
srv.keepAliveTimeout = 5000; srv.headersTimeout = 11000;
