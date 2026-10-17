// detect.js — every alert is a Cypher pattern over the provenance graph.
//
// Rules return PATHS, not booleans: the dashboard paints the path red and the
// analyst can see exactly which process read what and where it went. Rules
// only ever add alerts; nothing here can clear a kernel refusal.

import { g, gr } from './db.js';

// Each rule: id, severity, title, Cypher returning (nodes, edges, summary)
// per match, scoped to one session via $session.
export const RULES = [
  {
    id: 'secret-to-egress',
    threat: 'T2',
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
    threat: 'T5',
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
    threat: 'T4',
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
    threat: 'T1',
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
    threat: 'T8',
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
    threat: 'T3',
    severity: 'medium',
    title: 'Agent tree installed packages',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[ex:EXECUTED]->(f:File {installer: true})
      OPTIONAL MATCH (p)-[:INSTALLED]->(k:Package)
      WITH p, f, ex, collect({package: k.name, ecosystem: k.ecosystem, version: k.version, vuln_count: k.vuln_count, worst: k.worst, checked: k.osv_checked}) AS pk
      RETURN p, f, ex, [p, f] AS pn, [ex] AS pr,
             p.name + ' ran ' + ex.argv + (CASE WHEN ex.allowed THEN '' ELSE ' (refused)' END) AS summary,
             [x IN pk WHERE x.package IS NOT NULL] AS evidence
      ORDER BY ex.ts DESC LIMIT 20`,
  },
  {
    id: 'vulnerable-package',
    threat: 'T3',
    severity: 'high',
    title: 'Agent installed a package with known vulnerabilities (OSV)',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[ins:INSTALLED]->(k:Package)-[hv:HAS_VULN]->(v:Vulnerability)
      WITH p, k, ins, collect(v) AS vs, collect(hv) AS hvs
      WHERE size(vs) > 0
      RETURN p, k, ins, ([p, k] + vs) AS pn, ([ins] + hvs) AS pr,
             p.name + ' installed ' + k.ecosystem + ':' + k.name + '@' + k.version + ' with ' + toString(size(vs)) + ' OSV advisories (worst: ' + k.worst + ')' AS summary,
             [v IN vs | {id: v.id, severity: v.severity, summary: v.summary, cvss: v.cvss, fixed: v.fixed, aliases: v.aliases, url: v.url}] AS evidence,
             {package: k.name, ecosystem: k.ecosystem, version: k.version, worst: k.worst} AS subject
      ORDER BY ins.ts DESC LIMIT 20`,
  },
  {
    id: 'mcp-unapproved-server',
    threat: 'T3',
    severity: 'high',
    title: 'Agent used a tool from an MCP server that is not approved',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[u:USED_TOOL]->(t:McpTool)
      OPTIONAL MATCH (m:McpServer {name: t.server})
      WITH p, t, u, m WHERE (m IS NULL AND NOT t.server IN $approvedMcp) OR m.held = true OR m.approved = false
      RETURN p, t, u, [p, t] AS pn, [u] AS pr,
             p.name + ' called ' + t.server + '/' + t.name + (CASE WHEN m IS NOT NULL AND m.held THEN ' (server is held)' ELSE ' (server not approved)' END) AS summary
      ORDER BY u.ts DESC LIMIT 20`,
  },
  {
    id: 'dns-tunnel-shape',
    threat: 'T5',
    severity: 'high',
    title: 'DNS lookups shaped like tunnelling (long encoded labels)',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[r:RESOLVED]->(h:Host)
      WHERE h.longest_label >= 30 OR size(h.name) >= 60
      RETURN p, h, r, [p, h] AS pn, [r] AS pr,
             p.name + ' resolved ' + h.name AS summary
      ORDER BY r.ts DESC LIMIT 20`,
  },
  {
    id: 'bulk-read-then-egress',
    threat: 'T5',
    severity: 'high',
    title: 'Bulk file reads followed by a connection to an unapproved host',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File)
      WITH s, r, count(DISTINCT f) AS files, max(rd.ts) AS lastRead
      WHERE files >= 25
      MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
      WHERE h.approved = false AND cn.ts >= lastRead
      RETURN r, c, h, cn, nodes(path) AS pn, relationships(path) AS pr,
             r.name + ' read ' + toString(files) + ' files, then ' + c.name + ' connected to ' + h.name AS summary
      ORDER BY cn.ts DESC LIMIT 10`,
  },
  {
    id: 'tamper',
    threat: 'T8',
    severity: 'critical',
    title: 'Tamper attempt on the security daemon or a contained process',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[t:TAMPERED]->(w:Tamper)
      RETURN p, w, t, [p, w] AS pn, [t] AS pr,
             p.name + ' attempted ' + w.what + (CASE WHEN t.allowed THEN '' ELSE ' (refused)' END) AS summary
      ORDER BY t.ts DESC LIMIT 20`,
  },
  {
    id: 'flagged-prompt',
    threat: 'T1',
    severity: 'high',
    title: 'Prompt flagged by the daemon (injection or offensive content)',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[pr0:PROMPTED]->(q:Prompt {flagged: true})
      RETURN p, q, pr0, [p, q] AS pn, [pr0] AS pr,
             'Flagged prompt via ' + p.name + ': ' + left(q.text, 80) AS summary
      ORDER BY q.ts DESC LIMIT 20`,
  },
  {
    id: 'refused-egress',
    threat: 'T5',
    severity: 'medium',
    title: 'Outbound request refused by the proxy (DLP or policy)',
    cypher: `
      MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[e:CONNECTED|SENT]->(h:Host)
      WHERE e.allowed = false
      RETURN p, h, e, [p, h] AS pn, [e] AS pr,
             p.name + ' → ' + h.name + ' refused' + (CASE WHEN e.reason IS NULL OR e.reason = '' THEN '' ELSE ': ' + e.reason END) AS summary
      ORDER BY e.ts DESC LIMIT 20`,
  },
  {
    id: 'daemon-flagged-session',
    threat: 'T2',
    severity: 'high',
    title: 'The daemon flagged this session as privileged',
    cypher: `
      MATCH (s:Session {id: $session}) WHERE s.privileged = true
      MATCH (s)-[:HAS]->(p:Process)
      WITH s, p ORDER BY p.first_ts LIMIT 1
      RETURN s, p, [p] AS pn, [] AS pr,
             s.agent + ' session flagged by the daemon: ' + coalesce(s.privileged_reason, 'privileged') AS summary`,
  },
];

export const THREATS = {
  T1: 'Prompt Injection', T2: 'Credential Exfiltration', T3: 'Supply Chain Compromise', T4: 'Privilege Escalation',
  T5: 'Data Exfiltration', T6: 'Intent vs Behavior Mismatch', T7: 'Behavioral Anomaly', T8: 'C2 / Persistence', T9: 'AI Framework CVE Exploitation',
};
const APPROVED_MCP = (process.env.APPROVED_MCP || 'filesystem,github,postgres').split(',').map((s) => s.trim()).filter(Boolean);

function nodeId(n) { return n.id; }

// Run every rule for one session. Returns alerts with the node and edge ids
// on the path so the UI can paint them.
// Detection is the expensive part (14 path queries per session), so results
// are cached per session and recomputed only when that session ingests new
// events (see invalidate). Reads from the wall never touch the rules.
const cache = new Map();   // session -> alerts (unwindowed)
export function invalidate(session) { cache.delete(session); }
export function CACHE_KEYS() { return cache.keys(); }

// `win` = {from, to} in ms: keep an alert only if some edge on its path
// happened inside the window.
export async function detect(session, win) {
  let all = cache.get(session);
  if (!all) { all = await detectUncached(session); cache.set(session, all); }
  if (!win) return all;
  return all.filter((a) => !a.ts.length || a.ts.some((t) => t >= win.from && t <= win.to));
}

async function detectUncached(session) {
  const graph = g();
  const alerts = [];
  for (const rule of RULES) {
    let res;
    try { res = await graph.roQuery(rule.cypher, { params: { session, approvedMcp: APPROVED_MCP }, TIMEOUT: 4000 }); }
    catch (e) { console.error(`rule ${rule.id} on ${session}: ${e.message}`); continue; }
    for (const row of res.data || []) {
      const pn = (row.pn || []).map(nodeId);
      const pr = (row.pr || []).map((e) => e.id);
      // Extra nodes/edges returned outside the path (f, h, out, rd, wr, cn...)
      for (const [k, v] of Object.entries(row)) {
        if (k === 'pn' || k === 'pr' || k === 'summary' || k === 'evidence' || k === 'subject' || v == null || typeof v !== 'object') continue;
        if ('labels' in v) pn.push(v.id);
        else if ('relationshipType' in v) pr.push(v.id);
      }
      const ts = [...(row.pr || []), ...Object.values(row).filter((v) => v && typeof v === 'object' && 'relationshipType' in v)].map((e) => e.properties?.ts).filter(Boolean);
      if (!ts.length && row.s?.properties?.started) ts.push(row.s.properties.started);   // session-level findings date from the session start
      alerts.push({
        ts,
        rule: rule.id, threat: rule.threat, threatName: THREATS[rule.threat], severity: rule.severity, title: rule.title, summary: row.summary,
        evidence: row.evidence || undefined, subject: row.subject || undefined,
        nodes: [...new Set(pn)], edges: [...new Set(pr)],
      });
    }
  }
  // One alert per distinct finding: the same secret→host chain or the same
  // install line must not count once per event it touched.
  const seen = new Set();
  const unique = alerts.filter((a) => { const k = `${a.rule}|${a.summary}`; if (seen.has(k)) return false; seen.add(k); return true; });
  const order = { critical: 0, high: 1, medium: 2 };
  unique.sort((a, b) => order[a.severity] - order[b.severity]);
  return unique;
}

// Blast radius: everything reachable from a node within N hops, in any
// direction, inside one session. Answers "if this file leaked, what else did
// that tree touch?"
export async function blastRadius(nodeId, hops = 2) {
  const graph = gr();
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
export async function detectDevice(deviceId, win) {
  const graph = gr();
  const r = await graph.roQuery('MATCH (d:Device {id: $id})-[:RUNS]->(s:Session) RETURN s.id AS id', { params: { id: deviceId } });
  const out = [];
  for (const row of r.data || []) for (const a of await detect(row.id, win)) out.push({ session: row.id, ...a });
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
