// detect.js — every alert is a Cypher pattern over the provenance graph.
//
// Rules return PATHS, not booleans: the dashboard paints the path red and the
// analyst can see exactly which process read what and where it went. Rules
// only ever add alerts; nothing here can clear a kernel refusal.

import { g } from './db.js';

// Each rule: id, severity, title, Cypher returning (nodes, edges, summary)
// per match, scoped to one session via $session.
export const RULES = [
  {
    id: 'secret-to-egress',
    severity: 'critical',
    title: 'Secret read, then connection to an unapproved host',
    // Multi-hop: the read and the connect may be different processes in the
    // same tree (agent reads .env, child curl phones home). Up to 4 SPAWNED
    // hops between them, and the connect must come after the read.
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
      MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
      WHERE h.approved = false AND cn.ts >= rd.ts
      RETURN f, h, r, c, rd, cn, nodes(path) AS pn, relationships(path) AS pr,
             'Read ' + f.path + ' then ' + c.name + ' connected to ' + h.name AS summary
      ORDER BY cn.ts DESC LIMIT 20`,
  },
  {
    id: 'secret-to-write-to-egress',
    severity: 'critical',
    title: 'Secret read, written into a file, then that tree connected out',
    // The deferred/laundered variant: the secret is encoded into a file
    // (a diagram, a config), and something later sends it.
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
      MATCH (r)-[wr:WROTE]->(out:File)
      WHERE wr.ts >= rd.ts AND out.sensitive = false
      MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
      WHERE cn.ts >= wr.ts AND h.approved = false
      RETURN f, out, h, r, c, rd, wr, cn, nodes(path) AS pn, relationships(path) AS pr,
             'Read ' + f.path + ', wrote ' + out.path + ', then ' + c.name + ' connected to ' + h.name AS summary
      ORDER BY cn.ts DESC LIMIT 20`,
  },
  {
    id: 'privilege-tool',
    severity: 'high',
    title: 'Agent tree ran a privilege or scheduling tool',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[ex:EXECUTED]->(f:File {privileged: true})
      RETURN p, f, ex, [p, f] AS pn, [ex] AS pr,
             p.name + ' ran ' + f.program + (CASE WHEN ex.allowed THEN ' (allowed)' ELSE ' (refused)' END) AS summary
      ORDER BY ex.ts DESC LIMIT 20`,
  },
  {
    id: 'instruction-file-write',
    severity: 'high',
    title: 'Agent rewrote its own instruction file',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[wr:WROTE]->(f:File {instruction: true})
      RETURN p, f, wr, [p, f] AS pn, [wr] AS pr,
             p.name + ' wrote ' + f.path AS summary
      ORDER BY wr.ts DESC LIMIT 20`,
  },
  {
    id: 'write-then-exec',
    severity: 'medium',
    title: 'Agent wrote a file and then executed it',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(w:Process)-[wr:WROTE]->(f:File)
      MATCH path = (w)-[:SPAWNED*0..3]->(x:Process)-[ex:EXECUTED]->(f)
      WHERE ex.ts >= wr.ts
      RETURN w, x, f, wr, ex, nodes(path) AS pn, relationships(path) AS pr,
             w.name + ' wrote ' + f.path + ' and ' + x.name + ' executed it' AS summary
      ORDER BY ex.ts DESC LIMIT 20`,
  },
  {
    id: 'package-install',
    severity: 'medium',
    title: 'Agent tree installed packages',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[ex:EXECUTED]->(f:File {installer: true})
      RETURN p, f, ex, [p, f] AS pn, [ex] AS pr,
             p.name + ' ran ' + ex.argv + (CASE WHEN ex.allowed THEN '' ELSE ' (refused)' END) AS summary
      ORDER BY ex.ts DESC LIMIT 20`,
  },
];

function nodeId(n) { return n.id; }

// Run every rule for one session. Returns alerts with the node and edge ids
// on the path so the UI can paint them.
export async function detect(session) {
  const graph = g();
  const alerts = [];
  for (const rule of RULES) {
    const res = await graph.roQuery(rule.cypher, { params: { session } });
    for (const row of res.data || []) {
      const pn = (row.pn || []).map(nodeId);
      const pr = (row.pr || []).map((e) => e.id);
      // Extra nodes/edges returned outside the path (f, h, out, rd, wr, cn...)
      for (const [k, v] of Object.entries(row)) {
        if (k === 'pn' || k === 'pr' || k === 'summary' || v == null || typeof v !== 'object') continue;
        if ('labels' in v) pn.push(v.id);
        else if ('relationshipType' in v) pr.push(v.id);
      }
      alerts.push({
        rule: rule.id, severity: rule.severity, title: rule.title, summary: row.summary,
        nodes: [...new Set(pn)], edges: [...new Set(pr)],
      });
    }
  }
  const order = { critical: 0, high: 1, medium: 2 };
  alerts.sort((a, b) => order[a.severity] - order[b.severity]);
  return alerts;
}

// Blast radius: everything reachable from a node within N hops, in any
// direction, inside one session. Answers "if this file leaked, what else did
// that tree touch?"
export async function blastRadius(nodeId, hops = 2) {
  const graph = g();
  const res = await graph.roQuery(
    `MATCH (n) WHERE ID(n) = $id
     MATCH path = (n)-[*1..${Math.min(Math.max(hops, 1), 4)}]-(m)
     WHERE NOT m:Session AND NOT m:Agent
     RETURN nodes(path) AS pn, relationships(path) AS pr LIMIT 500`,
    { params: { id: Number(nodeId) } },
  );
  return collect(res.data || []);
}

// All alerts on one device = union over its sessions.
export async function detectDevice(deviceId) {
  const graph = g();
  const r = await graph.roQuery('MATCH (d:Device {id: $id})-[:RUNS]->(s:Session) RETURN s.id AS id', { params: { id: deviceId } });
  const out = [];
  for (const row of r.data || []) for (const a of await detect(row.id)) out.push({ session: row.id, ...a });
  const order = { critical: 0, high: 1, medium: 2 };
  out.sort((a, b) => order[a.severity] - order[b.severity]);
  return out;
}

export function collect(rows) {
  const nodes = new Map();
  const edges = new Map();
  for (const row of rows) {
    for (const n of row.pn || []) nodes.set(n.id, n);
    for (const e of row.pr || []) edges.set(e.id, e);
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}
