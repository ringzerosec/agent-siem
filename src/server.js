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
import { connect, g, wipe } from './db.js';
import { ingestMany, ingestMcpServers, ingestNotes } from './ingest.js';
import { detect, detectDevice, blastRadius, THREATS } from './detect.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);

const app = express();
app.use(express.json({ limit: '5mb' }));
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
const clients = new Set();
function broadcast(msg) {
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

// --- ingest --------------------------------------------------------------
app.post('/api/events', async (req, res, next) => {
  try {
    const events = Array.isArray(req.body) ? req.body : [req.body];
    const sessions = await ingestMany(events);
    for (const session of sessions) {
      const alerts = await detect(session);
      const dr = await g().roQuery('MATCH (d:Device)-[:RUNS]->(s:Session {id: $session}) RETURN d.id AS id', { params: { session } });
      broadcast({ type: 'update', device: dr.data?.[0]?.id, session, alerts: alerts.length, critical: alerts.filter((a) => a.severity === 'critical').length });
    }
    res.json({ ingested: events.length, sessions });
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
    const r = await g().roQuery(
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
  try { await wipe(); broadcast({ type: 'reset' }); res.json({ ok: true }); } catch (e) { next(e); }
});

// --- reads ---------------------------------------------------------------
app.get('/api/devices', async (req, res, next) => {
  try {
    const { from, to } = windowOf(req.query);
    const r = await g().roQuery(
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
    const r = await g().roQuery(
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
    const r = await g().roQuery(
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
    const r = await g().roQuery(
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
    const nr = await g().roQuery('MATCH (n) WHERE ID(n) = $id RETURN n', { params: { id } });
    const node = nr.data?.[0]?.n;
    if (!node) return res.status(404).json({ error: 'no such node' });
    const tl = await g().roQuery(
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
app.listen(PORT, () => console.log(`graph-watch listening on http://localhost:${PORT}`));
