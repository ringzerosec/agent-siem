// intel.js — threat-actor intelligence on the provenance graph.
//
// The idea (GraphRAG anti-fraud, applied to agents): an attacker reuses
// infrastructure. A brand-new domain or a renamed skill is not trustworthy just
// because it is new; if it connects to something already tied to an attack, it
// inherits that suspicion before it does anything else.
//
//   (:Finding)-[:INVOLVES]->(:Host | :McpTool | :Skill)    every alert, materialized
//   (:Host)-[:RESOLVES_TO]->(:Ip)                          from events and our own DNS
//   (:Skill)-[:SIGNATURE]->(:SkillSig)                     same skill on many laptops
//
// Campaigns are connected components (FalkorDB algo.WCC) of that layer: findings
// that share infrastructure, across endpoints, are one actor. Shared CDN IPs are
// never linked, or every site behind Cloudflare would become one "campaign".

import dns from 'node:dns';
import { g, gr } from './db.js';

// Shared hosting / CDN ranges: an IP here proves nothing about who runs a site.
const SHARED = [
  ['104.16.0.0', 13], ['172.64.0.0', 13], ['173.245.48.0', 20], ['188.114.96.0', 20], ['190.93.240.0', 20], ['197.234.240.0', 22], ['198.41.128.0', 17], ['162.158.0.0', 15], ['141.101.64.0', 18], ['108.162.192.0', 18], ['131.0.72.0', 22],   // Cloudflare
  ['151.101.0.0', 16], ['199.232.0.0', 16],   // Fastly
  ['13.32.0.0', 15], ['13.224.0.0', 14], ['18.64.0.0', 14], ['52.84.0.0', 15], ['54.230.0.0', 16], ['99.84.0.0', 16],   // CloudFront
  ['23.0.0.0', 12], ['104.64.0.0', 10],   // Akamai
  ['140.82.112.0', 20], ['185.199.108.0', 22],   // GitHub
];
const ipNum = (ip) => ip.split('.').reduce((n, o) => (n * 256) + Number(o), 0);
export function isSharedIp(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return true;
  const n = ipNum(ip);
  return SHARED.some(([base, bits]) => { const size = 2 ** (32 - bits); const b = ipNum(base); return n >= b && n < b + size; });
}

// ---- enrichment ---------------------------------------------------------------
export async function linkIp(host, ip) {
  if (!host || !ip || host === ip) return;
  // Shared CDN addresses get their own label so the campaign algorithm never
  // walks through them (WCC filters by label, not by property).
  const label = isSharedIp(ip) ? 'SharedIp' : 'Ip';
  await g().query(
    `MATCH (h:Host {name: $host})
     MERGE (i:${label} {addr: $ip})
     MERGE (h)-[:RESOLVES_TO]->(i)`, { params: { host, ip } });
}

// Resolve unapproved domains ourselves (real hosts don't come with their IPs).
const resolving = new Set(), resolved = new Set();
export function enrichHost(host) {
  if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host) || resolved.has(host) || resolving.has(host)) return;
  resolving.add(host);
  dns.promises.resolve4(host).then(async (ips) => { for (const ip of ips.slice(0, 4)) await linkIp(host, ip); })
    .catch(() => {}).finally(() => { resolving.delete(host); resolved.add(host); });
}

// Only named artifacts (a skill, plugin, command or extension directory) are
// signatures. Generic config files (.claude.json, mcp.json, rules) share names
// on every machine and would glue unrelated laptops into one "campaign".
const NAMED_KINDS = new Set(['skills', 'plugins', 'commands', 'extensions']);
export async function skillSignature(device, path, kind) {
  if (kind && !NAMED_KINDS.has(kind)) return;
  const sig = String(path).split('/').filter(Boolean).pop() || path;
  if (/^\.|\.(json|toml|ya?ml|md)$/i.test(sig)) return;
  await g().query(
    `MATCH (k:Skill {device: $device, path: $path})
     MERGE (s:SkillSig {sig: $sig})
     MERGE (k)-[:SIGNATURE]->(s)`, { params: { device, path, sig } });
}

// Resolve the hosts already tied to findings (startup backfill).
export async function backfillResolution() {
  const r = await gr().roQuery(`MATCH (:Finding)-[:INVOLVES]->(h:Host) WHERE NOT (h)-[:RESOLVES_TO]->() RETURN DISTINCT h.name AS n`);
  for (const row of r.data || []) enrichHost(row.n);
  // Drop signatures made by the old (too loose) rule.
  await g().query(`MATCH (s:SkillSig) WHERE s.sig STARTS WITH '.' OR s.sig ENDS WITH '.json' OR s.sig ENDS WITH '.toml' OR s.sig ENDS WITH '.md' DETACH DELETE s`);
}

// ---- findings layer -------------------------------------------------------------
const synced = new Map();   // finding id -> signature of what was written
export async function syncFindings(device, alerts) {
  for (const a of alerts) {
    if (a.severity === 'info' || !a.id) continue;
    const sig = `${a.severity}|${a.blocked}|${a.nodes.length}`;
    if (synced.get(a.id) === sig) continue;
    synced.set(a.id, sig);
    await g().query(
      `MERGE (f:Finding {id: $id})
       SET f.device = $device, f.rule = $rule, f.threat = $threat, f.severity = $severity, f.blocked = $blocked,
           f.title = $title, f.summary = $summary, f.ts = $ts
       WITH f MATCH (n) WHERE ID(n) IN $nodes AND (n:Host OR n:McpTool OR n:Skill)
         AND NOT (n:Host AND coalesce(n.approved, false))
       MERGE (f)-[:INVOLVES]->(n)`,
      { params: { id: a.id, device, rule: a.rule, threat: a.threat, severity: a.severity, blocked: a.blocked ?? null, title: a.title, summary: String(a.summary || '').slice(0, 300), ts: Math.min(...(a.ts?.length ? a.ts : [Date.now()])), nodes: a.nodes } });
  }
}

// ---- campaigns (algo.WCC) ---------------------------------------------------------
let campaignCache = { at: 0, data: null };
export async function campaigns() {
  if (campaignCache.data && Date.now() - campaignCache.at < 10_000) return campaignCache.data;
  // Components over findings and the infrastructure they share. Shared CDN IPs
  // are excluded by giving them no edges in the projection (they are filtered below).
  const r = await gr().roQuery(
    `CALL algo.WCC({nodeLabels: ['Finding', 'Host', 'McpTool', 'Skill', 'SkillSig', 'Ip'], relationshipTypes: ['INVOLVES', 'RESOLVES_TO', 'SIGNATURE']})
     YIELD node, componentId
     WITH node, componentId WHERE node:Finding
     RETURN componentId AS c, collect(node) AS findings`);
  const out = [];
  for (const row of r.data || []) {
    const fs = row.findings.map((n) => ({ id: n.properties.id, ...n.properties }));
    const ids = row.findings.map((n) => n.id);
    // Indicators of this component (reachable from its findings, 2 hops, excluding shared IPs).
    const ir = await gr().roQuery(
      `MATCH (f:Finding) WHERE ID(f) IN $ids
       MATCH (f)-[:INVOLVES]->(x)
       OPTIONAL MATCH (x)-[:RESOLVES_TO]->(ip:Ip)
       OPTIONAL MATCH (x)-[:SIGNATURE]->(sg:SkillSig)
       RETURN collect(DISTINCT x) AS xs, collect(DISTINCT ip.addr) AS ips, collect(DISTINCT sg.sig) AS sigs`, { params: { ids } });
    const xs = ir.data?.[0]?.xs || [];
    const devices = [...new Set(fs.map((f) => f.device))];
    const hosts = xs.filter((x) => x.labels.includes('Host')).map((x) => x.properties.name);
    const tools = xs.filter((x) => x.labels.includes('McpTool')).map((x) => `${x.properties.server}/${x.properties.name}`);
    const skills = [...new Set([...(ir.data?.[0]?.sigs || [])])];
    if (fs.length < 2 && devices.length < 2) continue;   // a lone finding is not a campaign
    const blocked = fs.filter((f) => f.blocked === true).length;
    const worst = fs.some((f) => f.severity === 'critical') ? 'critical' : fs.some((f) => f.severity === 'high') ? 'high' : 'medium';
    const name = hosts.length ? `${hosts.slice(0, 2).join(' / ')} infrastructure` : skills.length ? `“${skills[0]}” skill` : tools.length ? `${tools[0].split('/')[0]} MCP server` : 'linked activity';
    out.push({
      id: `C-${String(row.c).slice(-5)}`, component: row.c, name, severity: worst, endpoints: devices, findings: fs.length, blocked,
      threats: [...new Set(fs.map((f) => f.threat))].sort(), first: Math.min(...fs.map((f) => f.ts || Infinity)), last: Math.max(...fs.map((f) => f.ts || 0)),
      indicators: { hosts, ips: ir.data?.[0]?.ips || [], skills, mcp_tools: tools },
      finding_ids: fs.map((f) => f.id), devices_findings: fs.map((f) => ({ id: f.id, device: f.device, title: f.title, severity: f.severity, blocked: f.blocked })),
    });
  }
  out.sort((a, b) => b.endpoints.length - a.endpoints.length || b.findings - a.findings);
  campaignCache = { at: Date.now(), data: out };
  return out;
}

// Everything the graph knows about one indicator: which campaign, which findings,
// which endpoints, what it shares infrastructure with.
export async function indicatorIntel(value) {
  const r = await gr().roQuery(
    `MATCH (x) WHERE (x:Host AND x.name = $v) OR (x:Ip AND x.addr = $v) OR (x:SkillSig AND x.sig = $v) OR (x:McpTool AND x.server = $v)
     OPTIONAL MATCH (x)-[:RESOLVES_TO|SIGNATURE]-(y)
     OPTIONAL MATCH (f:Finding)-[:INVOLVES]->(x)
     OPTIONAL MATCH (y)<-[:RESOLVES_TO]-(sib:Host) WHERE sib <> x
     OPTIONAL MATCH (sf:Finding)-[:INVOLVES]->(sib)
     RETURN labels(x)[0] AS kind, collect(DISTINCT coalesce(y.addr, y.sig, y.name)) AS linked,
            collect(DISTINCT {id: f.id, device: f.device, title: f.title, severity: f.severity, blocked: f.blocked}) AS findings,
            collect(DISTINCT sib.name) AS same_infrastructure, collect(DISTINCT sf.device) AS infra_endpoints`, { params: { v: value } });
  const rows = r.data || [];
  if (!rows.length) return { indicator: value, known: false };
  const all = await campaigns();
  const camp = all.find((c) => c.indicators.hosts.includes(value) || c.indicators.ips.includes(value) || c.indicators.skills.includes(value) || c.indicators.mcp_tools.some((t) => t.startsWith(value + '/')));
  return { indicator: value, known: true, ...rows[0], findings: rows[0].findings.filter((f) => f.id), campaign: camp ? { id: camp.id, name: camp.name, endpoints: camp.endpoints, findings: camp.findings } : null };
}
