// detect.js — every alert is a Cypher pattern over the provenance graph.
//
// Rules return PATHS, not booleans: the dashboard paints the path red and the
// analyst can see exactly which process read what and where it went. Rules
// only ever add alerts; nothing here can clear a kernel refusal.

import { createHash } from 'node:crypto';
import { gd, gr } from './db.js';

// Each rule: id, severity, title, Cypher returning (nodes, edges, summary)
// per match, scoped to one session via $session.
// Only real network destinations count as egress (h.routable is set at ingest
// by isRoutable; FalkorDB has no regex operator).
const ROUTABLE = (h) => `coalesce(${h}.routable, true) = true`;

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
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
      WITH s, r, rd, f MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
      WHERE h.approved = false AND cn.ts >= rd.ts AND ${ROUTABLE('h')}
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
      // Rare things first: secret reads, then unapproved egress, and only then
      // the write that sits between them (writes are the most numerous edge).
      // WITH barriers pin the plan to start at the session index; without them
      // FalkorDB starts from a scan of every File node.
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
      WITH s, r, rd, f MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host {approved: false})
      WHERE cn.ts >= rd.ts AND ${ROUTABLE('h')}
      WITH s, r, rd, f, path, c, cn, h MATCH (r)-[wr:WROTE]->(out:File {sensitive: false})
      WHERE wr.ts >= rd.ts AND wr.ts <= cn.ts
      WITH f, h, r, c, rd, cn, path, collect([out, wr])[0] AS w
      WITH f, h, r, c, rd, cn, path, w[0] AS out, w[1] AS wr
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
    severity: 'info',   // a clean install is context, not an alert; vulnerable-package raises the alert
    title: 'Agent installed a package',
    cypher: `
      // Only real installs: the install line must have produced packages.
      // Running the toolchain (cargo test, npm run build) is not an install.
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[:INSTALLED]->(k:Package)
      WITH s, p, k MATCH (p)-[ex:EXECUTED]->(f:File {installer: true})
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
  // MCP: a tool call to a server that is not approved (or held) on that
  // endpoint. Critical when the call went through, high when it was blocked.
  {
    id: 'mcp-untrusted-call',
    threat: 'T3',
    severity: 'critical',
    title: 'Agent called a tool on an untrusted MCP server',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[u:USED_TOOL]->(t:McpTool) WHERE coalesce(u.allowed, true)
      OPTIONAL MATCH (m:McpServer {name: t.server, device: s.device})
      WITH p, t, u, m WHERE (m IS NULL AND NOT t.server IN $approvedMcp) OR m.held = true OR m.approved = false
      RETURN p, t, u, [p, t] AS pn, [u] AS pr,
             p.name + ' called ' + t.server + '/' + t.name + ' (' + (CASE WHEN m IS NOT NULL AND m.held THEN 'server is held' WHEN m IS NULL THEN 'server not declared or approved' ELSE 'server not approved' END) + ')' AS summary
      ORDER BY u.ts DESC LIMIT 20`,
  },
  {
    id: 'mcp-untrusted-call-blocked',
    threat: 'T3',
    severity: 'high',
    title: 'Blocked a tool call to an untrusted MCP server',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[u:USED_TOOL]->(t:McpTool) WHERE u.allowed = false
      OPTIONAL MATCH (m:McpServer {name: t.server, device: s.device})
      WITH p, t, u, m WHERE (m IS NULL AND NOT t.server IN $approvedMcp) OR m.held = true OR m.approved = false
      RETURN p, t, u, [p, t] AS pn, [u] AS pr,
             p.name + ' tried ' + t.server + '/' + t.name + ' (untrusted MCP server, refused)' AS summary
      ORDER BY u.ts DESC LIMIT 20`,
  },
  {
    id: 'mcp-untrusted-then-egress',
    threat: 'T5',
    severity: 'critical',
    title: 'Untrusted MCP tool call, then a connection to an unapproved host',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[u:USED_TOOL]->(t:McpTool)
      OPTIONAL MATCH (m:McpServer {name: t.server, device: s.device})
      WITH s, p, t, u, m WHERE (m IS NULL AND NOT t.server IN $approvedMcp) OR m.held = true OR m.approved = false
      WITH s, p, t, u MATCH path = (p)-[:SPAWNED*0..3]->(c:Process)-[cn:CONNECTED|SENT]->(h:Host {approved: false})
      WHERE cn.ts >= u.ts AND coalesce(h.routable, true) = true
      RETURN p, t, u, c, cn, h, nodes(path) + [t] AS pn, relationships(path) + [u] AS pr,
             p.name + ' used ' + t.server + '/' + t.name + ', then ' + c.name + ' connected to ' + h.name AS summary
      ORDER BY cn.ts DESC LIMIT 20`,
  },
  // Shadow AI (src/shadowai.js): AI calls recognized by protocol, not hostname.
  {
    id: 'secret-to-shadow-ai',
    threat: 'T2',
    severity: 'critical',
    title: 'Secret read, then sent to an unapproved AI service',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
      WITH r, rd, f MATCH path = (r)-[:SPAWNED*0..3]->(c:Process)-[ca:CALLED_AI]->(a:AiService {approved: false})
      WHERE ca.ts >= rd.ts
      RETURN r, f, rd, c, ca, a, nodes(path) + [f, a] AS pn, relationships(path) + [rd, ca] AS pr,
             'Read ' + f.path + ', then ' + c.name + ' called ' + a.provider + ' at ' + a.host + (CASE WHEN ca.allowed = false THEN ' (refused)' ELSE '' END) AS summary
      ORDER BY ca.ts DESC LIMIT 10`,
  },
  {
    id: 'shadow-ai',
    threat: 'T5',
    severity: 'high',
    title: 'Data sent to an unapproved AI service (shadow AI)',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[ca:CALLED_AI]->(a:AiService {approved: false})
      WITH p, a, count(ca) AS calls, collect(ca)[0] AS ca, max(ca.ts) AS last, collect(DISTINCT ca.model)[0..3] AS models
      RETURN p, a, ca, [p, a] AS pn, [ca] AS pr,
             p.name + ' called ' + a.provider + ' at ' + a.host + (CASE WHEN a.gateway THEN ' (gateway)' ELSE '' END) + ', ' + toString(calls) + ' call' + (CASE WHEN calls > 1 THEN 's' ELSE '' END)
             + (CASE WHEN size([m IN models WHERE m <> '']) > 0 THEN ', model ' + [m IN models WHERE m <> ''][0] ELSE '' END) AS summary
      ORDER BY last DESC LIMIT 10`,
  },
  {
    id: 'unregistered-ai-agent',
    threat: 'T7',
    severity: 'high',
    title: 'Unregistered AI agent: a process that is not a known agent is calling an AI API',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[ca:CALLED_AI]->(a:AiService)
      WHERE p.known_agent = false
      WITH p, a, count(ca) AS calls, collect(ca)[0] AS ca
      RETURN p, a, ca, [p, a] AS pn, [ca] AS pr,
             p.name + ' made ' + toString(calls) + ' AI call' + (CASE WHEN calls > 1 THEN 's' ELSE '' END) + ' to ' + a.provider + ' (' + a.host + '): an agent nobody registered' AS summary
      LIMIT 10`,
  },
  // Threat intel (src/intel.js): a host never seen in an attack, on the same
  // non-shared IP as a host from a known finding on another endpoint. Same
  // actor, new domain: flagged on first contact.
  {
    id: 'linked-to-campaign-infra',
    threat: 'T5',
    severity: 'critical',
    title: 'Connection to infrastructure shared with a known attack',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (s)-[:HAS]->(p:Process)-[cn:CONNECTED|SENT|RESOLVED]->(h:Host)
      WHERE NOT coalesce(h.approved, false)
      WITH s, p, cn, h MATCH (h)-[r1:RESOLVES_TO]->(ip:Ip)<-[r2:RESOLVES_TO]-(bad:Host)
      WHERE bad <> h
      WITH s, p, cn, h, r1, ip, r2, bad MATCH (f:Finding)-[:INVOLVES]->(bad)
      WHERE f.severity IN ['critical', 'high'] AND f.device <> s.device AND f.rule <> 'linked-to-campaign-infra'
      WITH p, cn, h, r1, ip, r2, bad, collect(f)[0] AS f
      RETURN p, h, ip, bad, cn, [p, h, ip, bad] AS pn, [cn, r1, r2] AS pr,
             p.name + ' contacted ' + h.name + ', which shares ' + ip.addr + ' with ' + bad.name + ' from an attack on ' + f.device + (CASE WHEN cn.allowed = false THEN ' (refused)' ELSE '' END) AS summary
      ORDER BY cn.ts DESC LIMIT 10`,
  },
  // Skills: an agent reading or running files inside a skill the skill scanner
  // flagged. The static finding is now live behaviour.
  {
    id: 'flagged-skill-loaded',
    threat: 'T1',
    severity: 'critical',
    title: 'Agent loaded a skill the scanner flagged',
    cypher: `
      MATCH (s:Session {id: $session})
      WITH s MATCH (sk:Skill {device: s.device}) WHERE sk.risk IN ['high', 'critical']
      WITH s, sk MATCH (s)-[:HAS]->(p:Process)-[e:READ|EXECUTED]->(f:File)
      WHERE f.path STARTS WITH sk.path
      RETURN p, f, e, sk, [p, f, sk] AS pn, [e] AS pr,
             p.name + ' loaded ' + f.path + ' from flagged ' + sk.kind + ' (' + coalesce(sk.top_finding, 'scanner finding') + ')' AS summary
      ORDER BY e.ts DESC LIMIT 20`,
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
      WHERE h.approved = false AND cn.ts >= lastRead AND ${ROUTABLE('h')}
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
      WHERE e.allowed = false AND ${ROUTABLE('h')}
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
// MITRE ATT&CK (and ATLAS for model-layer threats) technique per threat, so
// alerts line up with what a SOC already tracks.
export const ATTACK = {
  T1: 'ATLAS AML.T0051 LLM Prompt Injection', T2: 'T1552.001 Credentials in Files · T1567 Exfiltration Over Web Service',
  T3: 'T1195.001 Compromise Software Dependencies', T4: 'T1548 Abuse Elevation Control Mechanism',
  T5: 'T1048 Exfiltration Over Alternative Protocol', T8: 'T1105 Ingress Tool Transfer · T1562 Impair Defenses',
  T9: 'T1203 Exploitation for Client Execution',
};
// First response an analyst should take for each threat.
export const RESPONSE = {
  T1: 'Pause the agent session, remove or quarantine the skill or instruction file, and review what it told the agent to do.',
  T2: 'Rotate the credential that was read, block the destination host, and contain the session.',
  T3: 'Pin or remove the package, upgrade to the fixed version, and re-scan the lockfile.',
  T4: 'Revoke the elevated tool or sudo grant and confirm the session owner approved it.',
  T5: 'Block the destination, check what left the endpoint, and contain the session.',
  T6: 'Compare the stated task with the actions taken and contain the session if they diverge.',
  T7: 'Identify the owner of the process, register it as an agent with a policy, or stop it.',
  T8: 'Isolate the endpoint, remove the dropped binary, and check the daemon’s integrity.',
  T9: 'Patch the AI framework to the fixed version and review sessions that used it.',
};
// When Ring Zero Security already refused the step that mattered, the analyst
// is following up, not stopping an attack.
const CONTAINED_RESPONSE = {
  T2: 'Blocked by Ring Zero Security: nothing left the endpoint. Rotate the credential that was read as a precaution and review why the agent read it.',
  T5: 'Blocked by Ring Zero Security: the outbound connection was refused. Review the session to see what the agent was trying to send.',
  T8: 'Blocked by Ring Zero Security. Check the endpoint for anything the agent dropped before the block.',
};
const enrich = (a) => ({ ...a, attack: ATTACK[a.threat], response: a.blocked === true ? (CONTAINED_RESPONSE[a.threat] || 'Blocked by Ring Zero Security. Review the session to confirm intent.') : RESPONSE[a.threat] });

const APPROVED_MCP = (process.env.APPROVED_MCP || 'filesystem,github,postgres').split(',').map((s) => s.trim()).filter(Boolean);

function nodeId(n) { return n.id; }

// Run every rule for one session. Returns alerts with the node and edge ids
// on the path so the UI can paint them.
// Detection is the expensive part (14 path queries per session), so results
// are cached per session and recomputed only when that session ingests new
// events (see invalidate). Reads from the wall never touch the rules.
const cache = new Map();   // session -> alerts (unwindowed)
// The cache is saved to disk so a restart shows alerts immediately instead of
// waiting for every session to be recomputed.
import fs from 'node:fs';
const CACHE_FILE = process.env.ALERT_CACHE || new URL('../data/alerts-cache.json', import.meta.url).pathname;
try { for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')))) cache.set(k, v); } catch { /* first run */ }
let saveTimer;
function saveCache() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.mkdirSync(new URL('.', 'file://' + CACHE_FILE), { recursive: true }); fs.writeFileSync(CACHE_FILE + '.tmp', JSON.stringify(Object.fromEntries(cache))); fs.renameSync(CACHE_FILE + '.tmp', CACHE_FILE); }
    catch (e) { console.error('alert cache save', e.message); }
  }, 2000);
}
export function forget(session) { if (session ? cache.delete(session) : (cache.clear(), true)) saveCache(); }
export function invalidate(session) { /* keep serving the old result until the job replaces it */ }
export function hasCache(session) { return cache.has(session); }
export function CACHE_KEYS() { return cache.keys(); }

// `win` = {from, to} in ms: keep an alert only if some edge on its path
// happened inside the window.
// cachedOnly: page reads never trigger rule queries; a session not yet
// evaluated shows no alerts until the background job reaches it.
export async function detect(session, win, { cachedOnly = false } = {}) {
  let all = cache.get(session);
  if (!all) { if (cachedOnly) return []; all = await detectUncached(session); cache.set(session, all); }
  if (!win) return all.map(enrich);
  // Undated findings only show in the all-time view, never in a dated window.
  return all.filter((a) => (a.ts.length ? a.ts.some((t) => t >= win.from && t <= win.to) : !win.from)).map(enrich);
}

export async function recompute(session) { const all = await detectUncached(session); cache.set(session, all); saveCache(); return all; }

async function detectUncached(session) {
  const graph = gd();
  const alerts = [];
  for (const rule of RULES) {
    let res;
    try { res = await graph.roQuery(rule.cypher, { params: { session, approvedMcp: APPROVED_MCP }, TIMEOUT: 1500 }); }
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
      // Session-level findings date from the session start, or the first process seen.
      if (!ts.length) { const t0 = row.s?.properties?.started || row.p?.properties?.first_ts; if (t0) ts.push(t0); }
      const pathEdges = [...(row.pr || []), ...Object.values(row).filter((v) => v && typeof v === 'object' && 'relationshipType' in v)];
      alerts.push({
        ts, blocked: pathEdges.some((e) => e.properties?.allowed === false),
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
  const order = { critical: 0, high: 1, medium: 2, info: 3 };
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
  // The same finding in many sessions (e.g. every session of an agent touching
  // the same secret) is one alert with a session count, not N rows.
  const byKey = new Map();
  for (const row of r.data || []) for (const a of await detect(row.id, win, { cachedOnly: true })) {
    const k = `${a.rule}|${a.summary}`; const prev = byKey.get(k);
    if (!prev) { byKey.set(k, { session: row.id, sessions: 1, ...a }); continue; }
    prev.sessions += 1; prev.ts = [...prev.ts, ...a.ts];
    prev.nodes = [...new Set([...prev.nodes, ...a.nodes])]; prev.edges = [...new Set([...prev.edges, ...a.edges])];
    if (a.blocked === false) prev.blocked = false;
  }
  // Device-level: skills and MCP configs the skill scanner flagged at rest.
  {
    const sr = await graph.roQuery(
      `MATCH (d:Device {id: $id})-[:HAS_SKILL]->(sk:Skill) WHERE sk.risk IN ['medium', 'high', 'critical']
       AND (sk.scanned_at IS NULL OR $from = 0 OR sk.scanned_at >= $from) RETURN sk`,
      { params: { id: deviceId, from: win?.from || 0 } });
    for (const row of sr.data || []) {
      const p = row.sk.properties;
      const sev = p.risk === 'critical' ? 'critical' : p.risk === 'high' ? 'high' : 'medium';
      const k = `skill-flagged|${p.path}`;
      if (byKey.has(k)) continue;
      byKey.set(k, enrich({ rule: 'skill-flagged', threat: p.kind === 'mcp' ? 'T3' : 'T1', severity: sev, title: p.kind === 'mcp' ? 'MCP config flagged by the skill scanner' : `Agent ${p.kind === 'skills' ? 'skill' : p.kind} flagged by the skill scanner`,
        summary: `${p.agent} ${p.kind} ${p.path}: ${p.top_finding || 'finding'}${p.finding_count > 1 ? ` (+${p.finding_count - 1} more)` : ''}`,
        evidence: (() => { try { return JSON.parse(p.findings || '[]').slice(0, 8); } catch { return []; } })(),
        nodes: [row.sk.id], edges: [], ts: p.scanned_at ? [p.scanned_at] : [], session: null, sessions: 0, blocked: null }));
    }
  }
  // Threat intel: a skill on this endpoint that matches one flagged elsewhere.
  {
    const xr = await graph.roQuery(
      `MATCH (d:Device {id: $id})-[:HAS_SKILL]->(k:Skill)-[:SIGNATURE]->(sg:SkillSig)<-[:SIGNATURE]-(o:Skill)
       WHERE o.device <> $id AND o.risk IN ['high', 'critical']
       RETURN k, sg.sig AS sig, collect(DISTINCT o.device) AS elsewhere`, { params: { id: deviceId } });
    for (const row of xr.data || []) {
      const p = row.k.properties; const k = `skill-in-campaign|${p.path}`;
      if (byKey.has(k)) continue;
      byKey.set(k, enrich({ rule: 'skill-in-campaign', threat: 'T1', severity: 'high', title: 'Skill flagged on other endpoints is installed here',
        summary: `${p.agent} ${p.kind} "${row.sig}" is installed here and was flagged on ${row.elsewhere.length} other endpoint${row.elsewhere.length > 1 ? 's' : ''} (${row.elsewhere.slice(0, 3).join(', ')})`,
        nodes: [row.k.id], edges: [], ts: p.scanned_at ? [p.scanned_at] : [], session: null, sessions: 0, blocked: null }));
    }
  }
  // Stable id per finding on this device, so an agent or a person can refer to it.
  for (const a of byKey.values()) a.id = createHash('sha1').update(`${deviceId}|${a.rule}|${a.summary}`).digest('hex').slice(0, 10);
  out.push(...byKey.values());
  const order = { critical: 0, high: 1, medium: 2, info: 3 };
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
