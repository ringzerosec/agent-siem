// mcp-tools.js — the provenance graph as MCP tools.
//
// One MCP server, two ways in:
//   - in-process (InMemoryTransport) for the built-in triage agent, and
//   - Streamable HTTP at POST /mcp, so any MCP client (Claude Desktop, Cursor,
//     Claude Code, another agent) can investigate the same graph.
//
// Investigation tools are read-only Cypher against FalkorDB. Action tools write
// what the agent decided back into the graph as (:Action)/(:Ticket)/(:Triage)
// nodes linked to what they act on, and publish the action on NATS
// (rzs.actions.<device>) for the endpoint daemon to pick up. Every tool result
// says which query produced it, so the verdict can be traced step by step.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { g, gr } from './db.js';
import { detectDevice, blastRadius } from './detect.js';
import * as bus from './bus.js';
import { campaigns as listCampaignsIntel, indicatorIntel } from './intel.js';
import { aiUsage } from './aiusage.js';

const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 1) }] });
const fail = (msg) => ({ content: [{ type: 'text', text: JSON.stringify({ error: msg }) }], isError: true });

// Compact, model-friendly view of a node or edge.
export function brief(n) {
  if (!n) return null;
  const p = n.properties || {};
  const kind = (n.labels || [])[0];
  const name = p.path || p.name || p.id || p.key || '';
  const out = { id: n.id, kind, name };
  if (kind === 'Process') Object.assign(out, { pid: p.pid, session: p.session });
  if (kind === 'File') Object.assign(out, { secret: !!p.sensitive, instruction_file: !!p.instruction, installer: !!p.installer });
  if (kind === 'Host') Object.assign(out, { approved: !!p.approved, resolved_as: p.resolved_as || undefined, denied: !!p.denied || undefined });
  if (kind === 'Package') Object.assign(out, { ecosystem: p.ecosystem, version: p.version, vulns: p.vuln_count || 0 });
  return out;
}
const edgeBrief = (e) => e && ({ id: e.id, type: e.relationshipType, from: e.sourceId, to: e.destinationId, ts: e.properties?.ts, allowed: e.properties?.allowed !== false, reason: e.properties?.reason || undefined, argv: e.properties?.argv || undefined });

async function findAlert(device, alertId) {
  const alerts = await detectDevice(device, { from: 0, to: Date.now() + 60_000 });
  return { alerts, alert: alerts.find((a) => a.id === alertId) };
}

async function recordAction({ device, alertId, type, target, reason, by }) {
  const ts = Date.now();
  const r = await g().query(
    `MERGE (d:Device {id: $device})
     CREATE (a:Action {type: $type, target: $target, reason: $reason, by: $by, alert: $alertId, device: $device, ts: $ts, status: 'queued'})
     CREATE (d)-[:ACTION]->(a)
     RETURN ID(a) AS id`,
    { params: { device, type, target, reason, by, alertId: alertId || '', ts } },
  );
  const id = r.data?.[0]?.id;
  if (bus.enabled()) {
    try { await bus.publishAction(device, { id, type, target, reason, alert: alertId, by, ts }); } catch { /* the graph record is the source of truth */ }
  }
  return { action_id: id, type, target, status: bus.enabled() ? 'queued for the endpoint daemon on rzs.actions.' + device : 'recorded (no event bus)' };
}

export function createMcpServer({ actor = 'triage-agent' } = {}) {
  const server = new McpServer({ name: 'agent-siem-graph', version: '0.1.0' });

  // ---- investigation (read-only) -----------------------------------------
  server.registerTool('list_alerts', {
    title: 'List alerts',
    description: 'Open alerts across the fleet or on one endpoint, worst first. Each has an id, threat (T1-T9 from the Ring Zero Security threat model), severity, whether Ring Zero Security already blocked it, and a one-line summary.',
    inputSchema: { device: z.string().optional().describe('Endpoint hostname, e.g. ML-WKS-0096'), min_severity: z.enum(['critical', 'high', 'medium']).optional() },
  }, async ({ device, min_severity }) => {
    const rank = { critical: 0, high: 1, medium: 2, info: 3 };
    const ids = device ? [device] : ((await gr().roQuery('MATCH (d:Device) RETURN d.id AS id')).data || []).map((x) => x.id);
    const out = [];
    for (const d of ids) for (const a of await detectDevice(d, { from: 0, to: Date.now() + 60_000 })) {
      if (a.severity === 'info' || (min_severity && rank[a.severity] > rank[min_severity])) continue;
      out.push({ device: d, id: a.id, threat: a.threat, severity: a.severity, blocked: a.blocked ?? null, title: a.title, summary: a.summary, sessions: a.sessions });
    }
    out.sort((x, y) => rank[x.severity] - rank[y.severity]);
    return text({ count: out.length, alerts: out.slice(0, 40) });
  });

  server.registerTool('get_alert', {
    title: 'Get alert path',
    description: 'The exact provenance path behind one alert: every node (process, secret file, host...) and every edge (read, wrote, spawned, connected) with timestamps and whether each step was allowed or refused. Start every investigation here.',
    inputSchema: { device: z.string(), alert_id: z.string() },
  }, async ({ device, alert_id }) => {
    const { alert } = await findAlert(device, alert_id);
    if (!alert) return fail(`no alert ${alert_id} on ${device}`);
    const nodes = alert.nodes.length ? (await gr().roQuery('MATCH (n) WHERE ID(n) IN $ids RETURN n', { params: { ids: alert.nodes } })).data.map((x) => brief(x.n)) : [];
    const edges = alert.edges.length ? (await gr().roQuery('MATCH (a)-[e]->() WHERE ID(a) IN $src AND ID(e) IN $ids RETURN e', { params: { src: alert.nodes, ids: alert.edges } })).data.map((x) => edgeBrief(x.e)) : [];
    edges.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    return text({ device, id: alert.id, rule: alert.rule, threat: alert.threat, severity: alert.severity, title: alert.title, summary: alert.summary, blocked: alert.blocked ?? null, mitre: alert.attack, sessions: alert.sessions, evidence: alert.evidence, nodes, edges });
  });

  // One call instead of four round trips: the voice assistant asks this when
  // the user wants to know what happened, so the answer comes back in one hop.
  server.registerTool('investigate_alert', {
    title: 'Investigate alert (one call)',
    description: 'Everything needed to explain one alert, in a single call: the exact path (nodes, edges, allowed or refused), whether each secret on it was read or sent anywhere else in the fleet, whether each external host on it was contacted from other endpoints, and what the acting process did around it. Prefer this over calling get_alert, secret_followups, host_fleet_exposure and process_timeline separately.',
    inputSchema: { device: z.string(), alert_id: z.string() },
  }, async ({ device, alert_id }) => {
    const { alert } = await findAlert(device, alert_id);
    if (!alert) return fail(`no alert ${alert_id} on ${device}`);
    const nodes = alert.nodes.length ? (await gr().roQuery('MATCH (n) WHERE ID(n) IN $ids RETURN n', { params: { ids: alert.nodes } })).data.map((x) => brief(x.n)) : [];
    const edges = alert.edges.length ? (await gr().roQuery('MATCH (a)-[e]->() WHERE ID(a) IN $src AND ID(e) IN $ids RETURN e', { params: { src: alert.nodes, ids: alert.edges } })).data.map((x) => edgeBrief(x.e)) : [];
    edges.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const secrets = nodes.filter((n) => n.kind === 'File' && n.secret).slice(0, 3);
    const hosts = nodes.filter((n) => n.kind === 'Host').slice(0, 3);
    const proc = nodes.find((n) => n.kind === 'Process');
    const [followups, exposure, timeline] = await Promise.all([
      Promise.all(secrets.map(async (f) => {
        const r = await gr().roQuery(
          `MATCH (f:File {path: $path})<-[rd:READ]-(p:Process) MATCH (s:Session)-[:HAS]->(p)
           OPTIONAL MATCH (p)-[:SPAWNED*0..3]->(c:Process)-[cn:CONNECTED|SENT]->(h:Host) WHERE cn.ts >= rd.ts AND coalesce(h.routable, true)
           RETURN s.device AS device, p.name AS reader, collect(DISTINCT {host: h.name, approved: h.approved, allowed: cn.allowed}) AS egress LIMIT 30`, { params: { path: f.name } });
        const rows = (r.data || []).map((x) => ({ ...x, egress: x.egress.filter((e) => e.host) }));
        return { secret: f.name, read_on_endpoints: [...new Set(rows.map((x) => x.device))], unapproved_egress_after_read: rows.flatMap((x) => x.egress.filter((e) => !e.approved).map((e) => ({ device: x.device, host: e.host, allowed: e.allowed !== false }))) };
      })),
      Promise.all(hosts.map(async (h) => {
        const r = await gr().roQuery(
          `MATCH (h:Host {name: $host})<-[e:CONNECTED|SENT|RESOLVED]-(p:Process)<-[:HAS]-(s:Session)
           RETURN s.device AS device, count(e) AS attempts, sum(CASE WHEN coalesce(e.allowed, true) THEN 1 ELSE 0 END) AS allowed`, { params: { host: h.name } });
        const rows = r.data || [];
        return { host: h.name, approved: h.approved, endpoints: rows.map((x) => x.device), attempts: rows.reduce((n, x) => n + x.attempts, 0), allowed: rows.reduce((n, x) => n + x.allowed, 0) };
      })),
      proc ? gr().roQuery(`MATCH (p:Process) WHERE ID(p) = $id MATCH (p)-[e]->(m) WHERE e.ts IS NOT NULL RETURN type(e) AS action, e.allowed AS allowed, m ORDER BY e.ts LIMIT 40`, { params: { id: proc.id } })
        .then((r) => (r.data || []).map((x) => `${x.action.toLowerCase()} ${brief(x.m).name}${x.allowed === false ? ' (refused)' : ''}`)) : [],
    ]);
    return text({ device, id: alert.id, title: alert.title, summary: alert.summary, severity: alert.severity, threat: alert.threat, blocked: alert.blocked ?? null, mitre: alert.attack, recommended: alert.response, sessions: alert.sessions, path: { nodes, edges }, secrets: followups, hosts: exposure, process_timeline: timeline });
  });

  server.registerTool('mcp_and_skills', {
    title: 'MCP servers and skills',
    description: 'What an endpoint\'s agents can load: every MCP server declared or used (approved, untrusted or held; how many tool calls; how many were blocked) and every skill, plugin, rule file or MCP config the skill scanner found, with its risk and findings. Use it for questions about MCPs, skills, plugins or supply chain.',
    inputSchema: { device: z.string() },
  }, async ({ device }) => {
    const approvedSet = new Set((process.env.APPROVED_MCP || 'filesystem,github,postgres').split(',').map((x) => x.trim()));
    const d = await gr().roQuery('MATCH (:Device {id: $device})-[:DECLARES]->(m:McpServer) RETURN m', { params: { device } });
    const u = await gr().roQuery(
      `MATCH (:Device {id: $device})-[:RUNS]->(:Session)-[:HAS]->(:Process)-[e:USED_TOOL]->(t:McpTool)
       RETURN t.server AS server, count(e) AS calls, sum(CASE WHEN e.allowed = false THEN 1 ELSE 0 END) AS blocked, collect(DISTINCT t.name)[0..6] AS tools`, { params: { device } });
    const servers = new Map();
    for (const r of d.data || []) { const p = r.m.properties; servers.set(p.name, { name: p.name, declared: true, trust: p.held ? 'held' : p.approved ? 'approved' : 'untrusted', transport: p.transport, calls: 0, blocked: 0 }); }
    for (const r of u.data || []) { const cur = servers.get(r.server) || { name: r.server, declared: false, trust: approvedSet.has(r.server) ? 'approved' : 'untrusted', calls: 0, blocked: 0 }; Object.assign(cur, { calls: r.calls, blocked: r.blocked, tools: r.tools }); servers.set(r.server, cur); }
    const sk = await gr().roQuery('MATCH (:Device {id: $device})-[:HAS_SKILL]->(k:Skill) RETURN k', { params: { device } });
    const skills = (sk.data || []).map((r) => { const p = r.k.properties; let f = []; try { f = JSON.parse(p.findings || '[]'); } catch {} return { id: r.k.id, agent: p.agent, kind: p.kind, path: p.path, risk: p.risk, findings: f.slice(0, 4) }; });
    return text({ device, mcp_servers: [...servers.values()], skills });
  });

  server.registerTool('ai_usage', {
    title: 'AI usage and shadow AI',
    description: 'Every AI service the fleet (or one endpoint) talks to, recognized by protocol fingerprint (OpenAI/Anthropic/Gemini/Bedrock/Ollama request and response shapes), not only by hostname: provider, whether it is a gateway or self-hosted, approved or shadow, which endpoints and processes call it, unregistered agents (processes that are not known agents but call AI APIs), call counts, blocked calls, models. Use for "shadow AI", "who uses which AI", "unregistered agents".',
    inputSchema: { device: z.string().optional() },
  }, async ({ device }) => {
    const rows = await aiUsage(device || null, 0);
    return text({ services: rows, shadow: rows.filter((x) => !x.approved).length, unregistered_agents: [...new Set(rows.flatMap((x) => x.unregistered))] });
  });

  server.registerTool('list_campaigns', {
    title: 'Campaigns (threat-actor view)',
    description: 'Groups of findings across endpoints that share infrastructure (same server IP under different domain names, the same skill on many laptops, the same MCP server), computed with FalkorDB algo.WCC. Each has endpoints, findings, how many were blocked, threats and its indicators. Use for "is this one actor?", "what campaigns are active?".',
    inputSchema: {},
  }, async () => text({ algorithm: 'algo.WCC over Finding, Host, Ip, Skill, SkillSig, McpTool', campaigns: (await listCampaignsIntel()).map(({ finding_ids, devices_findings, component, ...c }) => c) }));

  server.registerTool('indicator_intel', {
    title: 'Who else is connected to this?',
    description: 'Everything the graph knows about one indicator (a hostname, an IP, a skill name or an MCP server name): its campaign, the findings that involve it, the endpoints, and other hosts on the same infrastructure. Use for "have we seen this before?" and "who else is connected to this?".',
    inputSchema: { value: z.string().describe('hostname, IP, skill name, or MCP server name') },
  }, async ({ value }) => text(await indicatorIntel(value)));

  server.registerTool('process_timeline', {
    title: 'Process timeline',
    description: 'Everything one process did, in time order: files read and written, programs run, children spawned, hosts contacted, MCP tools used. Use it to see what an agent did before and after the suspicious step.',
    inputSchema: { process_id: z.number().int().describe('Node id of a Process from get_alert'), limit: z.number().int().min(1).max(200).optional() },
  }, async ({ process_id, limit = 60 }) => {
    const r = await gr().roQuery(
      `MATCH (p:Process) WHERE ID(p) = $id
       MATCH (p)-[e]->(m) WHERE e.ts IS NOT NULL
       RETURN e, m ORDER BY e.ts LIMIT $limit`, { params: { id: process_id, limit } });
    return text({ process_id, steps: (r.data || []).map((x) => ({ ...edgeBrief(x.e), target: brief(x.m) })) });
  });

  server.registerTool('blast_radius', {
    title: 'Blast radius',
    description: 'Everything within N hops of a node (files, hosts, processes, packages): what else a compromised process or a stolen secret could have reached.',
    inputSchema: { node_id: z.number().int(), hops: z.number().int().min(1).max(3).optional() },
  }, async ({ node_id, hops = 2 }) => {
    const r = await blastRadius(node_id, hops);
    const by = {};
    for (const n of r.nodes) { const b = brief(n); (by[b.kind] ||= []).push(b); }
    return text({ node_id, hops, counts: Object.fromEntries(Object.entries(by).map(([k, v]) => [k, v.length])), secrets: (by.File || []).filter((f) => f.secret), hosts: by.Host || [], sample_files: (by.File || []).slice(0, 15) });
  });

  server.registerTool('host_fleet_exposure', {
    title: 'Host exposure across the fleet',
    description: 'Which endpoints, sessions and processes contacted this host, and how many of those connections Ring Zero Security allowed or refused. Answers: is this one machine or a fleet-wide campaign?',
    inputSchema: { host: z.string().describe('Hostname or IP') },
  }, async ({ host }) => {
    const r = await gr().roQuery(
      `MATCH (h:Host {name: $host})
       MATCH (d:Device)-[:RUNS]->(s:Session)-[:HAS]->(p:Process)-[e:CONNECTED|SENT|RESOLVED]->(h)
       RETURN d.id AS device, s.id AS session, p.name AS process, count(e) AS attempts,
              sum(CASE WHEN coalesce(e.allowed, true) THEN 1 ELSE 0 END) AS allowed, min(e.ts) AS first, max(e.ts) AS last
       ORDER BY attempts DESC LIMIT 50`, { params: { host } });
    const hr = await gr().roQuery('MATCH (h:Host {name: $host}) RETURN h', { params: { host } });
    const rows = r.data || [];
    return text({ host: brief(hr.data?.[0]?.h) || { name: host, known: false }, endpoints: [...new Set(rows.map((x) => x.device))].length, total_attempts: rows.reduce((n, x) => n + x.attempts, 0), allowed: rows.reduce((n, x) => n + x.allowed, 0), by_session: rows });
  });

  server.registerTool('secret_followups', {
    title: 'Secret follow-ups',
    description: 'For a secret file: every process across the fleet that read it, and any outbound connection the same process tree made after the read. Answers: did this secret leave anywhere else?',
    inputSchema: { path: z.string().describe('Full path of the secret file') },
  }, async ({ path }) => {
    const r = await gr().roQuery(
      `MATCH (f:File {path: $path})<-[rd:READ]-(p:Process)
       MATCH (s:Session)-[:HAS]->(p)
       OPTIONAL MATCH (p)-[:SPAWNED*0..3]->(c:Process)-[cn:CONNECTED|SENT]->(h:Host)
       WHERE cn.ts >= rd.ts AND coalesce(h.routable, true)
       RETURN s.device AS device, s.id AS session, p.name AS reader, rd.ts AS read_at, rd.allowed AS read_allowed,
              collect(DISTINCT {host: h.name, approved: h.approved, allowed: cn.allowed, by: c.name}) AS egress_after
       ORDER BY rd.ts DESC LIMIT 30`, { params: { path } });
    return text({ path, readers: (r.data || []).map((x) => ({ ...x, egress_after: x.egress_after.filter((e) => e.host) })) });
  });

  server.registerTool('fleet_risk_rank', {
    title: 'Fleet risk rank (PageRank)',
    description: 'Runs FalkorDB PageRank over the whole provenance graph and returns the secrets and external hosts with the highest centrality: the assets the most activity flows through, so the most valuable to protect or to block.',
    inputSchema: { limit: z.number().int().min(1).max(25).optional() },
  }, async ({ limit = 10 }) => {
    const r = await gr().roQuery(
      `CALL algo.pageRank(NULL, NULL) YIELD node, score
       WITH node, score WHERE (node:File AND node.sensitive = true) OR (node:Host AND coalesce(node.routable, true) AND NOT node.name IN ['127.0.0.1', '127.0.0.53'])
       RETURN node, score ORDER BY score DESC LIMIT $limit`, { params: { limit } });
    return text({ algorithm: 'algo.pageRank over all nodes and edges', ranked: (r.data || []).map((x) => ({ ...brief(x.node), score: Number(x.score.toFixed(6)) })) });
  });

  server.registerTool('run_readonly_cypher', {
    title: 'Read-only Cypher',
    description: 'Run any read-only Cypher query against the provenance graph (labels: Device, Session, Process, File, Host, McpTool, McpServer, Package, Vulnerability, Prompt; edges: RUNS, HAS, SPAWNED, READ, WROTE, EXECUTED, CONNECTED, SENT, RESOLVED, USED_TOOL, INSTALLED, HAS_VULN). Writes are rejected. Results are capped at 50 rows.',
    inputSchema: { query: z.string() },
  }, async ({ query }) => {
    if (/\b(CREATE|MERGE|DELETE|SET|REMOVE|DROP|CALL\s+db\.|LOAD\s+CSV)\b/i.test(query)) return fail('read-only: writes are not allowed here');
    try {
      const r = await gr().roQuery(query, { TIMEOUT: 3000 });
      const rows = (r.data || []).slice(0, 50).map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, v && typeof v === 'object' && ('labels' in v) ? brief(v) : v && typeof v === 'object' && ('relationshipType' in v) ? edgeBrief(v) : v])));
      return text({ rows, truncated: (r.data || []).length > 50 });
    } catch (e) { return fail(e.message); }
  });

  // ---- actions (write back to the graph + the endpoint) -------------------
  server.registerTool('block_host', {
    title: 'Block host',
    description: 'Deny an external host for an endpoint (or the whole fleet with device="*"). Marks the Host denied in the graph and queues the block for the Ring Zero Security daemon. Use when the graph shows exfiltration or command-and-control to that host. Never block an approved host.',
    inputSchema: { host: z.string(), device: z.string().describe('Endpoint hostname, or * for fleet-wide'), reason: z.string(), alert_id: z.string().optional() },
  }, async ({ host, device, reason, alert_id }) => {
    const hr = await gr().roQuery('MATCH (h:Host {name: $host}) RETURN h.approved AS approved', { params: { host } });
    if (hr.data?.[0]?.approved) return fail(`${host} is on the approved list; refusing to block it`);
    await g().query('MERGE (h:Host {name: $host}) SET h.denied = true, h.denied_reason = $reason, h.denied_at = $ts', { params: { host, reason, ts: Date.now() } });
    return text(await recordAction({ device, alertId: alert_id, type: 'block_host', target: host, reason, by: actor }));
  });

  server.registerTool('contain_session', {
    title: 'Contain session',
    description: 'Contain one agent session: the daemon stops its process tree from making new network connections or reading secrets until a human releases it. Use when the session is still active and the graph shows intent to exfiltrate.',
    inputSchema: { device: z.string(), session: z.string(), reason: z.string(), alert_id: z.string().optional() },
  }, async ({ device, session, reason, alert_id }) => {
    await g().query('MATCH (s:Session {id: $session}) SET s.contained = true, s.contained_reason = $reason, s.contained_at = $ts', { params: { session, reason, ts: Date.now() } });
    return text(await recordAction({ device, alertId: alert_id, type: 'contain_session', target: session, reason, by: actor }));
  });

  server.registerTool('open_ticket', {
    title: 'Open ticket',
    description: 'Open a follow-up ticket for a human, e.g. rotate a credential that was read, or review an instruction file the agent rewrote.',
    inputSchema: { device: z.string(), title: z.string(), body: z.string(), severity: z.enum(['critical', 'high', 'medium', 'low']), alert_id: z.string().optional() },
  }, async ({ device, title, body, severity, alert_id }) => {
    const r = await g().query(
      `MERGE (d:Device {id: $device})
       CREATE (t:Ticket {title: $title, body: $body, severity: $severity, alert: $alertId, by: $by, ts: $ts, status: 'open'})
       CREATE (d)-[:TICKET]->(t) RETURN ID(t) AS id`,
      { params: { device, title, body, severity, alertId: alert_id || '', by: actor, ts: Date.now() } });
    return text({ ticket_id: r.data?.[0]?.id, title, severity, status: 'open' });
  });

  server.registerTool('mark_false_positive', {
    title: 'Mark false positive',
    description: 'Record that an alert is benign, with the reason, so it is suppressed on the wall and the reason is kept for audit.',
    inputSchema: { device: z.string(), alert_id: z.string(), reason: z.string() },
  }, async ({ device, alert_id, reason }) => text(await recordAction({ device, alertId: alert_id, type: 'false_positive', target: alert_id, reason, by: actor })));

  server.registerTool('submit_verdict', {
    title: 'Submit triage verdict',
    description: 'Finish the investigation. Call exactly once, after any actions. The verdict, confidence, reasoning and the evidence (node and edge ids you relied on) are stored on the alert in the graph.',
    inputSchema: {
      device: z.string(), alert_id: z.string(),
      verdict: z.enum(['true_positive_contained', 'true_positive_active', 'false_positive', 'needs_human']),
      confidence: z.number().min(0).max(1),
      summary: z.string().describe('Two or three plain sentences a CISO can read'),
      evidence: z.array(z.string()).describe('Facts from the graph, each citing node/edge ids'),
    },
  }, async ({ device, alert_id, verdict, confidence, summary, evidence }) => {
    const r = await g().query(
      `MERGE (d:Device {id: $device})
       CREATE (t:Triage {alert: $alert, verdict: $verdict, confidence: $confidence, summary: $summary, evidence: $evidence, by: $by, ts: $ts})
       CREATE (d)-[:TRIAGED]->(t) RETURN ID(t) AS id`,
      { params: { device, alert: alert_id, verdict, confidence, summary, evidence, by: actor, ts: Date.now() } });
    return text({ triage_id: r.data?.[0]?.id, verdict, recorded: true });
  });

  return server;
}

export const TOOL_KIND = {
  list_alerts: 'read', get_alert: 'read', investigate_alert: 'read', mcp_and_skills: 'read', ai_usage: 'read', list_campaigns: 'algorithm', indicator_intel: 'read', process_timeline: 'read', blast_radius: 'read', host_fleet_exposure: 'read',
  secret_followups: 'read', fleet_risk_rank: 'algorithm', run_readonly_cypher: 'read',
  block_host: 'action', contain_session: 'action', open_ticket: 'action', mark_false_positive: 'action', submit_verdict: 'verdict',
};
