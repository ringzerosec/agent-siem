// governance.js — fleet deep scan, endpoint posture, policy proposals and
// ISO/IEC 42001 readiness evidence.
//
// "Pepper, do a deep scan of the fleet":
//   1. a (:Command {type: 'deep_scan'}) per endpoint. Real endpoints: the RZS
//      adapter picks it up on its next poll, calls the daemon's scanners
//      (skill scan, non-human identities, health, status, supply chain,
//      compliance self-assessment) and posts the results back. Simulated
//      endpoints are scanned from what the graph already holds.
//   2. results become a (:Posture) per endpoint plus the usual skill nodes.
//   3. propose_policies turns what the scan found into decisions in the inbox
//      (block an unapproved AI service fleet-wide, remove an untrusted MCP
//      server, quarantine a flagged skill, register an unregistered agent…).
//   4. the ISO 42001 view maps the evidence to the standard's Annex A areas.
// It is evidence for an audit, not a certification.

import { randomUUID } from 'node:crypto';
import { g, gr } from './db.js';
import { aiUsage } from './aiusage.js';
import { campaigns } from './intel.js';

const now = () => Date.now();
const rec = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

// ---- deep scan --------------------------------------------------------------
export async function startDeepScan(devices) {
  const all = ((await gr().roQuery("MATCH (d:Device) WHERE d.id <> '*' RETURN d.id AS id, coalesce(d.simulated, false) AS sim")).data || []);
  const targets = devices?.length ? all.filter((d) => devices.includes(d.id)) : all;
  const job = 'S-' + randomUUID().slice(0, 6);
  for (const d of targets) {
    await g().query(`CREATE (:Command {id: $id, job: $job, device: $device, type: 'deep_scan', status: 'pending', ts: $ts, simulated: $sim})`,
      { params: { id: 'C-' + randomUUID().slice(0, 8), job, device: d.id, ts: now(), sim: d.sim } });
    if (d.sim) await scanFromGraph(d.id, job);   // no daemon behind it: posture from what we know
  }
  return { job, endpoints: targets.length, real: targets.filter((d) => !d.sim).map((d) => d.id), simulated: targets.filter((d) => d.sim).length };
}

// Commands waiting for an adapter (real endpoints only).
export async function pendingCommands(devices) {
  const r = await gr().roQuery(`MATCH (c:Command {status: 'pending', simulated: false}) WHERE $devices IS NULL OR c.device IN $devices RETURN c ORDER BY c.ts LIMIT 20`, { params: { devices: devices?.length ? devices : null } });
  return (r.data || []).map((x) => x.c.properties);
}

// Results from an adapter (or from the graph, for simulated endpoints).
export async function storeScan(commandId, device, results) {
  const st = rec(results.status), health = rec(results.health), nhi = rec(results.nhi), sc = rec(results.supply_chain), comp = rec(results.compliance);
  const comps = Array.isArray(health.components) ? health.components : [];
  const p = {
    device, scanned_at: now(), source: results.source || 'daemon',
    enforce_mode: st.enforce_mode ?? null, ebpf_active: st.ebpf_active ?? null, kernel_monitoring: st.kernel_monitoring || '', daemon_version: st.version || '',
    health: health.status || '', health_issues: JSON.stringify(comps.filter((c) => c.status && c.status !== 'ok').map((c) => `${c.label}: ${c.detail || c.status}`).slice(0, 8)),
    nhi_count: Number(nhi.nhi_count ?? (Array.isArray(nhi.identities) ? nhi.identities.length : 0)) || 0,
    nhi_sample: JSON.stringify((nhi.identities || []).slice(0, 6).map((i) => ({ actor: i.actor, reason: i.reason }))),
    supply_total: Number(sc.total) || 0, supply_malicious: Number(sc.malicious) || 0, supply_quarantine: Number(sc.quarantine) || 0,
    self_assessment: JSON.stringify(comp.frameworks || {}),
    skills_found: Number(results.skills_found) || 0,
    reachable: !results.unreachable,
  };
  await g().query(
    `MERGE (d:Device {id: $device})
     MERGE (x:Posture {device: $device})
     SET x += $p
     MERGE (d)-[:POSTURE]->(x)
     WITH d MATCH (c:Command {id: $cmd}) SET c.status = 'done', c.done_at = $ts`,
    { params: { device, p, cmd: commandId || '', ts: now() } });
}

async function scanFromGraph(device, job) {
  const r = await gr().roQuery(`MATCH (c:Command {job: $job, device: $device}) RETURN c.id AS id`, { params: { job, device } });
  const sk = await gr().roQuery(`MATCH (:Device {id: $device})-[:HAS_SKILL]->(k:Skill) RETURN count(k) AS n`, { params: { device } });
  await storeScan(r.data?.[0]?.id, device, { source: 'simulated endpoint (from graph)', status: { enforce_mode: true, ebpf_active: true, kernel_monitoring: 'active', version: 'sim' }, health: { status: 'ok', components: [] }, skills_found: sk.data?.[0]?.n || 0 });
}

export async function scanStatus(job) {
  const r = await gr().roQuery(`MATCH (c:Command {job: $job}) RETURN c.device AS device, c.status AS status, c.simulated AS simulated`, { params: { job } });
  const rows = r.data || [];
  return { job, total: rows.length, done: rows.filter((x) => x.status === 'done').length, pending: rows.filter((x) => x.status !== 'done').map((x) => x.device) };
}

// ---- inventory + posture per endpoint ----------------------------------------
export async function fleetInventory() {
  const r = await gr().roQuery(
    `MATCH (d:Device) WHERE d.id <> '*'
     OPTIONAL MATCH (d)-[:POSTURE]->(x:Posture)
     OPTIONAL MATCH (p:Person)-[:USES]->(d)
     OPTIONAL MATCH (d)-[:RUNS]->(s:Session)
     WITH d, x, p, collect(DISTINCT s.agent) AS agents
     OPTIONAL MATCH (d)-[:HAS_SKILL]->(k:Skill)
     WITH d, x, p, agents, count(k) AS skills, sum(CASE WHEN k.risk IN ['high','critical'] THEN 1 ELSE 0 END) AS risky_skills
     OPTIONAL MATCH (d)-[:DECLARES]->(m:McpServer)
     RETURN d.id AS device, coalesce(d.simulated, false) AS simulated, d.owner AS team, p.name AS owner, p.email AS email,
            agents, skills, risky_skills, count(m) AS mcp, sum(CASE WHEN m.approved = false OR m.held = true THEN 1 ELSE 0 END) AS untrusted_mcp,
            x AS posture
     ORDER BY d.id`);
  const ai = await aiUsage(null, 0);
  return (r.data || []).map((row) => {
    const x = row.posture?.properties || null;
    const mine = ai.filter((a) => a.endpoints.includes(row.device));
    return { ...row, posture: x ? { ...x, health_issues: JSON.parse(x.health_issues || '[]'), self_assessment: JSON.parse(x.self_assessment || '{}'), nhi_sample: JSON.parse(x.nhi_sample || '[]') } : null,
      ai_services: mine.map((a) => ({ host: a.host, provider: a.provider, approved: a.approved })), shadow_ai: mine.filter((a) => !a.approved).length,
      unregistered_agents: [...new Set(mine.flatMap((a) => a.unregistered))] };
  });
}

// ---- policy proposals -> decisions in the inbox ---------------------------------
export async function proposePolicies() {
  const inv = await fleetInventory();
  const ai = await aiUsage(null, 0);
  const out = [];
  for (const a of ai.filter((x) => !x.approved)) {
    out.push({ key: `block-ai:${a.host}`, severity: 'high', title: `Block unapproved AI service ${a.provider} (${a.host})`, summary: `${a.calls} calls from ${a.endpoints.length} endpoint(s) by ${a.processes.join(', ')}. Not an approved AI provider for company data.`,
      proposals: [{ type: 'block_host', label: `Block ${a.host} fleet-wide`, args: { host: a.host, device: '*', reason: 'unapproved AI service (governance)' } }], devices: a.endpoints });
  }
  const mcp = await gr().roQuery(`MATCH (d:Device)-[:DECLARES]->(m:McpServer) WHERE m.approved = false OR m.held = true RETURN m.name AS name, collect(d.id) AS devices`);
  for (const m of mcp.data || []) out.push({ key: `mcp:${m.name}`, severity: 'high', title: `Remove untrusted MCP server "${m.name}"`, summary: `Declared on ${m.devices.length} endpoint(s): ${m.devices.join(', ')}.`,
    proposals: [{ type: 'open_ticket', label: `Ticket to remove ${m.name} from ${m.devices.length} endpoint(s)`, args: { device: m.devices[0], title: `Remove untrusted MCP server ${m.name}`, body: `Remove "${m.name}" from the agent configuration on: ${m.devices.join(', ')}.`, severity: 'high' } }], devices: m.devices });
  const sk = await gr().roQuery(`MATCH (d:Device)-[:HAS_SKILL]->(k:Skill) WHERE k.risk IN ['high','critical'] RETURN k.path AS path, k.kind AS kind, collect(d.id) AS devices, max(k.top_finding) AS finding`);
  for (const k of sk.data || []) out.push({ key: `skill:${k.path}`, severity: 'critical', title: `Quarantine flagged ${k.kind} ${String(k.path).split('/').pop()}`, summary: `${k.finding}. On ${k.devices.length} endpoint(s): ${k.devices.join(', ')}.`,
    proposals: [{ type: 'open_ticket', label: `Ticket to quarantine it on ${k.devices.length} endpoint(s)`, args: { device: k.devices[0], title: `Quarantine ${k.path}`, body: `Flagged by the skill scanner: ${k.finding}. Remove it from: ${k.devices.join(', ')}.`, severity: 'critical' } }], devices: k.devices });
  for (const d of inv.filter((x) => x.unregistered_agents.length)) out.push({ key: `unreg:${d.device}`, severity: 'medium', title: `Register or stop unregistered agent ${d.unregistered_agents.join(', ')} on ${d.device}`, summary: `It calls AI APIs but is not a known agent, so no agent policy applies to it.`,
    proposals: [{ type: 'open_ticket', label: `Ask ${d.owner || 'the owner'} to register it`, args: { device: d.device, title: `Register ${d.unregistered_agents.join(', ')} as an agent`, body: `Process(es) ${d.unregistered_agents.join(', ')} on ${d.device} call AI APIs. Register with a policy, or stop.`, severity: 'medium' } }], devices: [d.device] });
  for (const d of inv.filter((x) => x.posture && x.posture.enforce_mode === false)) out.push({ key: `enforce:${d.device}`, severity: 'high', title: `Turn on enforce mode on ${d.device}`, summary: 'The daemon is only watching on this endpoint.', proposals: [], devices: [d.device] });
  // Store as decisions (one per key, not repeated while pending).
  let created = 0;
  for (const p of out) {
    const ex = await gr().roQuery(`MATCH (x:Decision {policy: $key}) WHERE x.status = 'pending' RETURN x.id LIMIT 1`, { params: { key: p.key } });
    if (ex.data?.length) continue;
    await g().query(
      `MERGE (dev:Device {id: $device})
       CREATE (x:Decision {id: $id, policy: $key, alert: '', device: $device, severity: $severity, title: $title, summary: $summary, headline: $title,
         verdict: 'policy proposal', verdict_summary: $summary, owner: '', owner_email: '', proposals: $proposals, status: 'pending', ts: $ts, triage_mode: 'governance'})
       CREATE (dev)-[:DECISION]->(x)`,
      { params: { device: p.devices[0] || 'fleet', id: 'P-' + randomUUID().slice(0, 6), key: p.key, severity: p.severity, title: p.title, summary: p.summary, proposals: JSON.stringify(p.proposals), ts: now() } });
    created++;
  }
  return { proposals: out.length, created, items: out.map((p) => ({ title: p.title, severity: p.severity, endpoints: p.devices.length })) };
}

// ---- ISO/IEC 42001 readiness ----------------------------------------------------
export async function iso42001() {
  const inv = await fleetInventory();
  const ai = await aiUsage(null, 0);
  const camps = await campaigns();
  const q = async (cy, params = {}) => (await gr().roQuery(cy, { params })).data?.[0] || {};
  const f = await q(`MATCH (f:Finding) RETURN count(f) AS n, sum(CASE WHEN f.blocked = true THEN 1 ELSE 0 END) AS blocked, sum(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical`);
  const t = await q(`MATCH (t:Triage) RETURN count(t) AS n`);
  const dec = await q(`MATCH (x:Decision) RETURN count(x) AS n, sum(CASE WHEN x.status = 'approved' THEN 1 ELSE 0 END) AS approved, sum(CASE WHEN x.status = 'dismissed' THEN 1 ELSE 0 END) AS dismissed, sum(CASE WHEN x.status = 'pending' THEN 1 ELSE 0 END) AS pending`);
  const esc = await q(`MATCH (e:Escalation) RETURN count(e) AS n`);
  const ev = await q(`MATCH ()-[e:READ|WROTE|EXECUTED|CONNECTED|SENT|USED_TOOL|CALLED_AI]->() RETURN count(e) AS n, min(e.ts) AS first`);
  const mcp = await q(`MATCH (m:McpServer) RETURN count(m) AS n, sum(CASE WHEN m.approved THEN 1 ELSE 0 END) AS approved`);
  const sk = await q(`MATCH (k:Skill) RETURN count(k) AS n, sum(CASE WHEN k.risk IN ['high','critical'] THEN 1 ELSE 0 END) AS risky`);
  const pk = await q(`MATCH (p:Package) RETURN count(p) AS n, sum(CASE WHEN coalesce(p.vuln_count, 0) > 0 THEN 1 ELSE 0 END) AS vulnerable`);
  const owned = inv.filter((d) => d.owner).length, scanned = inv.filter((d) => d.posture && d.posture.reachable !== false).length, enforced = inv.filter((d) => d.posture?.enforce_mode === true).length;
  const shadow = ai.filter((a) => !a.approved), unreg = [...new Set(ai.flatMap((a) => a.unregistered))];
  const status = (ok, partial) => (ok ? 'evidenced' : partial ? 'partial' : 'gap');
  const areas = [
    { id: 'A.2', name: 'Policies related to AI', status: status(enforced === inv.length && inv.length > 0, enforced > 0),
      evidence: [`Approved AI providers, MCP servers and hosts are defined (APPROVED_AI, APPROVED_MCP, APPROVED_HOSTS).`, `${enforced} of ${inv.length} endpoints run the daemon in enforce mode${scanned < inv.length ? ` (${inv.length - scanned} not scanned yet)` : ''}.`],
      gaps: enforced < inv.length ? ['Run a deep scan on every endpoint and turn on enforce mode where it is off.'] : [] },
    { id: 'A.3', name: 'Internal organization', status: status(owned === inv.length && inv.length > 0, owned > 0),
      evidence: [`${owned} of ${inv.length} endpoints have a named owner and a manager for escalation.`, `${dec.approved || 0} decisions approved and ${dec.dismissed || 0} dismissed, each with who decided and when.`],
      gaps: owned < inv.length ? [`Assign owners to ${inv.length - owned} endpoint(s).`] : [] },
    { id: 'A.4', name: 'Resources for AI systems (inventory)', status: status(scanned === inv.length && inv.length > 0, true),
      evidence: [`Inventory of ${inv.length} endpoints, agents ${[...new Set(inv.flatMap((d) => d.agents))].filter(Boolean).join(', ')}.`, `${ai.length} AI services, ${mcp.n || 0} MCP server declarations, ${sk.n || 0} skill surfaces, ${pk.n || 0} packages.`],
      gaps: scanned < inv.length ? [`Deep-scan ${inv.length - scanned} endpoint(s) for a complete inventory.`] : [] },
    { id: 'A.5', name: 'Assessing impacts of AI systems', status: status((f.n || 0) > 0 && (t.n || 0) > 0, (f.n || 0) > 0),
      evidence: [`${f.n || 0} findings mapped to the AI-agent threat model (T1-T9) and MITRE ATT&CK, ${f.critical || 0} critical.`, `${camps.length} campaigns identified across endpoints; ${t.n || 0} triage investigations with cited evidence.`],
      gaps: (t.n || 0) === 0 ? ['Run triage on open critical findings.'] : [] },
    { id: 'A.6', name: 'AI system life cycle: monitoring and logging', status: status((ev.n || 0) > 0, false),
      evidence: [`${ev.n || 0} agent actions recorded in the provenance graph${ev.first ? ` since ${new Date(ev.first).toISOString().slice(0, 10)}` : ''}; event stream kept a week for replay (NATS JetStream).`, `Exportable to SIEMs as CEF.`], gaps: [] },
    { id: 'A.7', name: 'Data for AI systems', status: status(shadow.length === 0, true),
      evidence: [`${ai.filter((a) => a.approved).length} approved AI services in use; ${shadow.length} unapproved (shadow AI) services seen.`, `Secrets read by agents and their follow-up egress are tracked per finding.`],
      gaps: shadow.length ? [`Stop or approve: ${shadow.map((a) => `${a.provider} (${a.host})`).join(', ')}.`] : [] },
    { id: 'A.8', name: 'Information for interested parties', status: status((esc.n || 0) > 0, (dec.n || 0) > 0),
      evidence: [`${esc.n || 0} escalations to employees (and their managers) about their agents.`, `Findings, verdicts and decisions are reportable per endpoint and per person.`],
      gaps: (esc.n || 0) === 0 ? ['Escalate pending decisions to the people involved.'] : [] },
    { id: 'A.9', name: 'Use of AI systems', status: status(unreg.length === 0 && (dec.pending || 0) === 0, true),
      evidence: [`Human oversight: autopilot proposes, a person approves; ${dec.pending || 0} decisions waiting.`, `${unreg.length} unregistered agents (processes calling AI APIs that are not known agents).`],
      gaps: [...(unreg.length ? [`Register or stop: ${unreg.join(', ')}.`] : []), ...((dec.pending || 0) ? [`Decide ${dec.pending} pending item(s) in the inbox.`] : [])] },
    { id: 'A.10', name: 'Third-party and supplier relationships', status: status((mcp.n || 0) === (mcp.approved || 0) && (sk.risky || 0) === 0 && (pk.vulnerable || 0) === 0, true),
      evidence: [`MCP servers: ${mcp.approved || 0} of ${mcp.n || 0} approved. Skills: ${sk.risky || 0} of ${sk.n || 0} flagged by the scanner. Packages: ${pk.vulnerable || 0} of ${pk.n || 0} with OSV advisories.`, `AI providers and gateways are inventoried with their approval state.`],
      gaps: [...((mcp.n || 0) - (mcp.approved || 0) > 0 ? [`Remove or approve ${(mcp.n || 0) - (mcp.approved || 0)} untrusted MCP server declaration(s).`] : []), ...((sk.risky || 0) ? [`Quarantine ${sk.risky} flagged skill surface(s).`] : [])] },
  ];
  const score = Math.round(100 * areas.reduce((n, a) => n + (a.status === 'evidenced' ? 1 : a.status === 'partial' ? 0.5 : 0), 0) / areas.length);
  return { standard: 'ISO/IEC 42001:2023 (Annex A areas)', note: 'Evidence for an audit from the provenance graph. Not a certification.', generated_at: new Date().toISOString(), readiness: score, areas,
    self_assessments: inv.filter((d) => d.posture && Object.keys(d.posture.self_assessment || {}).length).map((d) => ({ device: d.device, claims: d.posture.self_assessment })) };
}
