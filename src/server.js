// server.js — HTTP API + live updates for the dashboard.
//
//   POST /api/events            ingest a JSON array of events (or one event)
//   GET  /api/sessions          every session with its alert counts (live list)
//   GET  /api/graph/:session    nodes + edges of one session, plus its alerts
//   GET  /api/node/:id          one node's details, timeline and 2-hop blast radius
//   GET  /api/alerts            all alerts across sessions, newest first
//   GET  /api/stream            server-sent events: {session} after each ingest
//   POST /api/reset             wipe the graph (demo convenience)

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, g, wipe } from './db.js';
import { ingestMany } from './ingest.js';
import { detect, blastRadius, collect } from './detect.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

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
      broadcast({ type: 'update', session, alerts: alerts.length, critical: alerts.filter((a) => a.severity === 'critical').length });
    }
    res.json({ ingested: events.length, sessions });
  } catch (e) { next(e); }
});

app.post('/api/reset', async (_req, res, next) => {
  try { await wipe(); broadcast({ type: 'reset' }); res.json({ ok: true }); } catch (e) { next(e); }
});

// --- reads ---------------------------------------------------------------
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
