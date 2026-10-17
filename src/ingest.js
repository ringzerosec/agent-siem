// ingest.js — turn agent activity events into the provenance graph.
//
// Event shape (JSONL, one per line). It mirrors the public SecurityEvent of
// the Ring Zero Security daemon so a real export drops in unchanged:
//   { id, ts, device, owner, session, agent, kind, pid, ppid, process, target, allowed, extra }
// kind ∈ exec | read | write | connect | tool | spawn
//
// Graph model:
//   (:Device {id, owner, first_ts})      one employee machine
//   (:Session {id, agent, started, device})
//   (Device)-[:RUNS]->(Session)
//   (:Agent {name})
//   (:Process {key: session+pid, pid, name, first_ts})
//   (:File {path, sensitive})          sensitive = looks like a credential
//   (:Host {name, approved})
//   (:McpTool {name, server})
//   (Session)-[:RAN_BY]->(Agent)
//   (Session)-[:HAS]->(Process)
//   (Process)-[:SPAWNED {ts}]->(Process)
//   (Process)-[:READ|WROTE|EXECUTED {ts, event, allowed}]->(File)
//   (Process)-[:CONNECTED {ts, event, allowed, port}]->(Host)
//   (Process)-[:USED_TOOL {ts, event, allowed}]->(McpTool)

import { g } from './db.js';
import { parseInstall, lookup } from './osv.js';
import { linkIp, enrichHost, skillSignature } from './intel.js';
import { fingerprint, aiApproved, isKnownAgent } from './shadowai.js';
import { isLlmCall } from './brain.js';

const SENSITIVE = [
  /\/\.env($|\.)/, /\/\.ssh\//, /\/\.aws\//, /\/\.gnupg\//, /\/\.docker\/config\.json$/,
  /\/\.netrc$/, /\/\.npmrc$/, /\/\.pypirc$/, /credentials?(\.json|\.yml|\.yaml)?$/i,
  /secret|token|apikey|api_key|private_key|id_rsa|id_ed25519/i,
];
const INSTRUCTION_FILES = [/CLAUDE\.md$/, /AGENTS\.md$/, /\.cursorrules$/, /\/\.cursor\//, /\/\.claude\//, /SKILL\.md$/];
const PRIVILEGED = new Set(['sudo', 'su', 'pkexec', 'doas', 'run0', 'systemd-run', 'at', 'batch', 'crontab']);
const INSTALLERS = new Set(['pip', 'pip3', 'npm', 'npx', 'uv', 'cargo', 'apt', 'apt-get', 'brew', 'gem']);

// Never store a secret value in the graph: prompts and notes pass through this.
const SECRET_VALUES = [
  /sk-[A-Za-z0-9_-]{16,}/g, /ghp_[A-Za-z0-9]{20,}/g, /gho_[A-Za-z0-9]{20,}/g, /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /AKIA[0-9A-Z]{16}/g, /AIza[0-9A-Za-z_-]{30,}/g, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*["']?[^\s"']{6,}/gi, /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];
export function redact(text) {
  let t = String(text || '').slice(0, 1500);
  for (const r of SECRET_VALUES) t = t.replace(r, '[redacted]');
  return t;
}

// Source, build output and package caches are code, not credentials, even
// when the file is called tokenize.js or secrets-page.css.
const NOT_SECRET = [
  /\/(node_modules|site-packages|dist-packages|__pycache__|\.cargo\/registry|\.npm\/_cacache|dist|build|target)\//,
  /\.(m?[jt]sx?|cjs|d\.ts|css|scss|map|pyc|py|rs|go|java|kt|rb|php|html|md|svg|png|jpg|woff2?|wasm)$/i,
  /\.env\.(example|sample|template|dist)$/i,
];
export function isSensitive(path) {
  if (/\/\.env(\.[A-Za-z0-9_-]+)?$/.test(path) && !NOT_SECRET[2].test(path)) return true;
  if (NOT_SECRET.some((r) => r.test(path))) return false;
  // Keyword matches ("token", "secret") only count on absolute paths; a bare
  // relative name like "token-types" is usually a package, not a credential.
  if (!path.startsWith('/') && !path.startsWith('~')) return SENSITIVE.slice(0, -1).some((r) => r.test('/' + path));
  return SENSITIVE.some((r) => r.test(path));
}
export function isInstructionFile(path) { return INSTRUCTION_FILES.some((r) => r.test(path)); }

const APPROVED_HOSTS = new Set(
  (process.env.APPROVED_HOSTS || 'api.anthropic.com,api.openai.com,github.com,registry.npmjs.org,pypi.org,crates.io,files.pythonhosted.org')
    .split(',').map((s) => s.trim()).filter(Boolean),
);
// Daemons often see the IP, not the name: npm connects to 104.16.x.34, not
// registry.npmjs.org. Each approved name is resolved on a timer and its exact
// addresses are approved too (never whole CDN ranges: attackers host on
// Cloudflare as well). Addresses are kept once seen, since CDNs rotate them.
// APPROVED_IPS adds fixed addresses by hand.
const APPROVED_IPS = new Map(  // ip -> approved hostname it belongs to
  (process.env.APPROVED_IPS || '').split(',').map((s) => s.trim()).filter(Boolean).map((ip) => [ip, 'APPROVED_IPS']),
);
export function approvedAs(name) { return APPROVED_HOSTS.has(name) ? name : APPROVED_IPS.get(name) || null; }
export function isApprovedHost(name) { return approvedAs(name) !== null; }
export async function refreshApprovedIps() {
  const { promises: dns } = await import('node:dns');
  const fresh = [];
  await Promise.all([...APPROVED_HOSTS].map(async (h) => {
    for (const fam of ['resolve4', 'resolve6']) {
      try { for (const ip of await dns[fam](h)) if (!APPROVED_IPS.has(ip)) { APPROVED_IPS.set(ip, h); fresh.push({ ip, host: h }); } } catch { /* no records of this family */ }
    }
  }));
  // Mark every stored Host that is one of these addresses as approved.
  const rows = [...APPROVED_IPS].map(([ip, host]) => ({ ip, host }));
  const r = await g().query(
    `UNWIND $rows AS x MATCH (h:Host {name: x.ip})
     WHERE coalesce(h.approved, false) = false OR h.resolved_as IS NULL
     SET h.approved = true, h.resolved_as = x.host
     WITH h MATCH (s:Session)-[:HAS]->(:Process)-[:CONNECTED|SENT]->(h)
     RETURN DISTINCT s.id AS id`,
    { params: { rows } },
  );
  return { learned: fresh.length, total: APPROVED_IPS.size, sessions: (r.data || []).map((x) => x.id) };
}
// A real network destination, not a parse fragment ("0.0.0.0", ".so.1", "Root_CA.crt").
export function isRoutable(name) {
  const n = String(name || '');
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(n)) return n !== '0.0.0.0' && !n.startsWith('127.');
  return /^([A-Za-z0-9-]+\.)+[A-Za-z]{2,24}$/.test(n) && !/\.(crt|pem|so|key|cer|der|js|json|txt|md|log)$/i.test(n) && n !== 'localhost';
}

function base(cmd) {
  const first = (cmd || '').trim().split(/\s+/)[0] || '';
  return first.split('/').pop();
}

// One event → one or two MERGEs. Returns the session id so the server can
// notify dashboards watching it.
export async function ingestEvent(ev) {
  const graph = g();
  const session = String(ev.session);
  const device = String(ev.device || 'unknown-device');
  const owner = ev.owner || null;   // null keeps an owner set earlier
  const agent = ev.agent || 'unknown-agent';
  const pid = Number(ev.pid);
  const key = `${session}:${pid}`;
  const ts = Number(ev.ts) || Date.now();
  const allowed = ev.allowed !== false;
  const procName = ev.process || 'unknown';

  await graph.query(
    `MERGE (d:Device {id: $device})
       ON CREATE SET d.first_ts = $ts, d.simulated = $simulated
     SET d.owner = coalesce($owner, d.owner)
     MERGE (s:Session {id: $session})
       ON CREATE SET s.agent = $agent, s.started = $ts, s.device = $device
     SET s.agent = coalesce(s.agent, $agent), s.device = coalesce(s.device, $device), s.state = coalesce($state, s.state), s.privileged = coalesce($priv, s.privileged), s.privileged_reason = coalesce($preason, s.privileged_reason)
     MERGE (d)-[:RUNS]->(s)
     MERGE (a:Agent {name: $agent})
     MERGE (s)-[:RAN_BY]->(a)
     MERGE (p:Process {key: $key})
       ON CREATE SET p.pid = $pid, p.name = $proc, p.first_ts = $ts, p.session = $session
     SET p.last_ts = CASE WHEN coalesce(p.last_ts, 0) < $ts THEN $ts ELSE p.last_ts END,
         d.last_ts = CASE WHEN coalesce(d.last_ts, 0) < $ts THEN $ts ELSE d.last_ts END
     MERGE (s)-[:HAS]->(p)`,
    { params: { session, device, owner, agent, key, pid, proc: procName, ts, simulated: ev.simulated === true, state: ev.session_state ?? null, priv: ev.session_privileged ?? null, preason: ev.session_reason ?? null } },
  );

  if (ev.ppid) {
    const pkey = `${session}:${Number(ev.ppid)}`;
    await graph.query(
      `MATCH (c:Process {key: $key}), (s:Session {id: $session})
       MERGE (pp:Process {key: $pkey})
         ON CREATE SET pp.pid = $ppid, pp.name = $pname, pp.first_ts = $ts, pp.session = $session
       MERGE (s)-[:HAS]->(pp)
       MERGE (pp)-[:SPAWNED]->(c)`,
      { params: { key, pkey, ppid: Number(ev.ppid), pname: ev.parent_process || 'parent', ts, session } },
    );
  }

  const target = ev.target || '';
  switch (ev.kind) {
    case 'read':
    case 'write': {
      const rel = ev.kind === 'read' ? 'READ' : 'WROTE';
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (f:File {path: $path})
           ON CREATE SET f.sensitive = $sensitive, f.instruction = $instruction
         CREATE (p)-[:${rel} {ts: $ts, event: $id, allowed: $allowed}]->(f)`,
        { params: { key, path: target, sensitive: isSensitive(target), instruction: isInstructionFile(target), ts, id: ev.id || '', allowed } },
      );
      break;
    }
    case 'exec': {
      const prog = base(target);
      const pkgs = parseInstall(target);
      if (pkgs.length) await recordPackages(key, ts, pkgs);
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (f:File {path: $path})
           ON CREATE SET f.sensitive = false, f.instruction = false
         SET f.program = $prog, f.privileged = $priv, f.installer = $inst
         CREATE (p)-[:EXECUTED {ts: $ts, event: $id, allowed: $allowed, argv: $argv}]->(f)`,
        { params: { key, path: target.split(/\s+/)[0] || target, prog, priv: PRIVILEGED.has(prog), inst: INSTALLERS.has(prog), ts, id: ev.id || '', allowed, argv: target } },
      );
      break;
    }
    case 'connect': {
      const [host, port] = target.split(':');
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (h:Host {name: $host})
           ON CREATE SET h.approved = $approved, h.routable = $routable, h.resolved_as = $resolvedAs
         CREATE (p)-[:CONNECTED {ts: $ts, event: $id, allowed: $allowed, port: $port, reason: $reason}]->(h)`,
        { params: { key, host, approved: isApprovedHost(host), routable: isRoutable(host), resolvedAs: approvedAs(host), ts, id: ev.id || '', allowed, port: Number(port) || 443, reason: ev.reason || '' } },
      );
      await intelOn(host, ev);
      break;
    }
    case 'tool': {
      const [server, tool] = target.includes('/') ? target.split('/') : ['local', target];
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (t:McpTool {name: $tool, server: $server})
           ON CREATE SET t.approved = $trusted
         CREATE (p)-[:USED_TOOL {ts: $ts, event: $id, allowed: $allowed, reason: $reason}]->(t)`,
        { params: { key, tool, server, ts, id: ev.id || '', allowed, reason: ev.reason || '', trusted: isApprovedMcp(server) } },
      );
      break;
    }
    case 'delete': {
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (f:File {path: $path}) ON CREATE SET f.sensitive = $sensitive, f.instruction = $instruction
         CREATE (p)-[:DELETED {ts: $ts, event: $id, allowed: $allowed}]->(f)`,
        { params: { key, path: target, sensitive: isSensitive(target), instruction: isInstructionFile(target), ts, id: ev.id || '', allowed } },
      );
      break;
    }
    case 'send': {
      const [host, port] = target.split(':');
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (h:Host {name: $host}) ON CREATE SET h.approved = $approved, h.routable = $routable, h.resolved_as = $resolvedAs
         CREATE (p)-[:SENT {ts: $ts, event: $id, allowed: $allowed, port: $port, reason: $reason}]->(h)`,
        { params: { key, host, approved: isApprovedHost(host), routable: isRoutable(host), resolvedAs: approvedAs(host), ts, id: ev.id || '', allowed, port: Number(port) || 443, reason: ev.reason || '' } },
      );
      break;
    }
    case 'dns': {
      const name = target.toLowerCase();
      const labels = name.split('.');
      const longest = Math.max(...labels.map((l) => l.length));
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (h:Host {name: $host}) ON CREATE SET h.approved = $approved, h.routable = $routable, h.resolved_as = $resolvedAs
         SET h.longest_label = $longest, h.labels = $nlabels
         CREATE (p)-[:RESOLVED {ts: $ts, event: $id, allowed: $allowed}]->(h)`,
        { params: { key, host: name, approved: isApprovedHost(name), routable: isRoutable(name), resolvedAs: approvedAs(name), longest, nlabels: labels.length, ts, id: ev.id || '', allowed } },
      );
      break;
    }
    case 'prompt': {
      await graph.query(
        `MATCH (p:Process {key: $key})
         CREATE (q:Prompt {ts: $ts, event: $id, text: $text, provider: $provider, model: $model, tool_call: $tool, flagged: $flagged, session: $session})
         CREATE (p)-[:PROMPTED {ts: $ts}]->(q)`,
        { params: { key, ts, id: ev.id || '', text: redact(ev.text), provider: ev.provider || '', model: ev.model || '', tool: redact(ev.tool_call || ''), flagged: !!ev.flagged, session } },
      );
      // The daemon recognized this provider by name: register it as an AI service too.
      if (ev.provider) {
        const prov = String(ev.provider); const host = { openai: 'api.openai.com', anthropic: 'api.anthropic.com', google: 'generativelanguage.googleapis.com', local: 'localhost' }[prov.toLowerCase()] || prov.toLowerCase();
        const name = { openai: 'OpenAI', anthropic: 'Anthropic', google: 'Google', local: 'Self-hosted / internal gateway' }[prov.toLowerCase()] || prov;
        await graph.query(
          `MATCH (p:Process {key: $key})
           SET p.known_agent = $knownAgent
           MERGE (a:AiService {host: $host}) ON CREATE SET a.first_ts = $ts
           SET a.provider = $name, a.family = $fam, a.gateway = false, a.self_hosted = $local, a.approved = $approvedAi, a.last_ts = $ts
           CREATE (p)-[:CALLED_AI {ts: $ts, event: $id, allowed: true, path: '', model: $model, streaming: false, confidence: 1.0, signals: 'recognized by the daemon proxy'}]->(a)`,
          { params: { key, host, name, fam: prov.toLowerCase(), local: prov.toLowerCase() === 'local', approvedAi: aiApproved(host, name), ts, id: ev.id || '', model: ev.model || '', knownAgent: isKnownAgent(ev.process || procName) } });
      }
      break;
    }
    // HTTP request metadata (from the daemon's proxy, or the simulator). The
    // connection goes in like any other; if the protocol fingerprint says it is
    // an AI API call, it also becomes a CALLED_AI edge to an (:AiService).
    case 'http': {
      const host = String(ev.host || target.split(/[/:]/)[0] || '').toLowerCase();
      const fp = fingerprint({ host, method: ev.method, path: ev.path, content_type: ev.content_type, accept: ev.accept, req_headers: ev.req_headers, body_keys: ev.body_keys, resp_content_type: ev.resp_content_type, resp_keys: ev.resp_keys, model: ev.model });
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (h:Host {name: $host})
           ON CREATE SET h.approved = $approved, h.routable = $routable, h.resolved_as = $resolvedAs
         CREATE (p)-[:CONNECTED {ts: $ts, event: $id, allowed: $allowed, port: $port, reason: $reason, path: $path}]->(h)`,
        { params: { key, host, approved: isApprovedHost(host), routable: isRoutable(host) || /^(localhost|127\.|10\.|192\.168\.)/.test(host) || /\.(internal|corp|lan)$/.test(host), resolvedAs: approvedAs(host), ts, id: ev.id || '', allowed, port: Number(ev.port) || 443, reason: ev.reason || '', path: String(ev.path || '').slice(0, 200) } },
      );
      // Below the rule threshold but not nothing: ask the local model (Vega).
      if (!fp.ai && fp.score >= 2) {
        const m = await isLlmCall({ host, path: ev.path, accept: ev.accept, content_type: ev.content_type, body_keys: ev.body_keys, req_headers: ev.req_headers, resp_content_type: ev.resp_content_type, resp_keys: ev.resp_keys });
        if (m && !m.abstain && m.p >= 0.9) Object.assign(fp, { ai: true, confidence: m.p, provider: fp.provider || 'Unknown AI endpoint', signals: [...fp.signals, `local model (${m.backend}): LLM call p=${m.p.toFixed(2)}`] });
      }
      if (fp.ai) {
        const approvedAi = aiApproved(host, fp.provider);
        await graph.query(
          `MATCH (p:Process {key: $key})
           SET p.known_agent = $knownAgent
           MERGE (a:AiService {host: $host})
             ON CREATE SET a.first_ts = $ts
           SET a.provider = $provider, a.family = $family, a.gateway = $gateway, a.self_hosted = $selfHosted, a.approved = $approvedAi, a.last_ts = $ts
           CREATE (p)-[:CALLED_AI {ts: $ts, event: $id, allowed: $allowed, path: $path, model: $model, streaming: $streaming, confidence: $conf, signals: $signals}]->(a)
           WITH a MATCH (h:Host {name: $host}) MERGE (a)-[:AT]->(h)`,
          { params: { key, host, provider: fp.provider, family: fp.family || '', gateway: !!fp.gateway, selfHosted: !!fp.self_hosted, approvedAi, ts, id: ev.id || '', allowed, path: String(ev.path || '').slice(0, 200), model: String(ev.model || ''), streaming: !!fp.streaming, conf: Number(fp.confidence.toFixed(2)), signals: fp.signals.slice(0, 12).join('; '), knownAgent: isKnownAgent(ev.process || procName) } },
        );
      }
      await intelOn(host, ev);
      break;
    }
    case 'tamper': {
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (t:Tamper {what: $what})
         CREATE (p)-[:TAMPERED {ts: $ts, event: $id, allowed: $allowed}]->(t)`,
        { params: { key, what: target || 'unknown', ts, id: ev.id || '', allowed } },
      );
      break;
    }
    case 'spawn':
      break; // the ppid MERGE above already recorded it
    default:
      throw new Error(`unknown event kind: ${ev.kind}`);
  }
  return session;
}

// Threat intel: the IP an event says a host had, and our own resolution for
// unapproved domains, so new domains on known-bad infrastructure link up.
async function intelOn(host, ev) {
  try {
    if (ev.ip) await linkIp(host, String(ev.ip));
    if (!isApprovedHost(host) && isRoutable(host)) enrichHost(host);
  } catch { /* enrichment is best effort */ }
}

export async function ingestMany(events) {
  const touched = new Set();
  for (const ev of events) touched.add(await ingestEvent(ev));
  return [...touched];
}

// Installed packages → (:Package) with OSV advisories attached as (:Vulnerability).
async function recordPackages(key, ts, pkgs) {
  const graph = g();
  const enriched = await lookup(pkgs);
  for (const p of enriched) {
    const worst = (p.vulns || []).reduce((w, v) => RANK[v.severity] > RANK[w] ? v.severity : w, 'none');
    await graph.query(
      `MATCH (pr:Process {key: $key})
       MERGE (k:Package {name: $name, ecosystem: $eco, version: $version})
       SET k.vuln_count = $count, k.worst = $worst, k.osv_checked = $checked
       CREATE (pr)-[:INSTALLED {ts: $ts}]->(k)`,
      { params: { key, name: p.name, eco: p.ecosystem, version: p.version || '*', count: (p.vulns || []).length, worst, checked: p.vulns !== null, ts } },
    );
    for (const v of (p.vulns || []).slice(0, 25)) {
      await graph.query(
        `MATCH (k:Package {name: $name, ecosystem: $eco, version: $version})
         MERGE (v:Vulnerability {id: $id})
           ON CREATE SET v.summary = $summary, v.severity = $severity, v.details = $details, v.aliases = $aliases, v.cvss = $cvss,
                         v.fixed = $fixed, v.introduced = $introduced, v.published = $published, v.url = $url
         MERGE (k)-[:HAS_VULN]->(v)`,
        { params: { name: p.name, eco: p.ecosystem, version: p.version || '*', id: v.id, summary: v.summary || '', severity: v.severity || 'unknown', details: v.details || '', aliases: (v.aliases || []).join(','), cvss: v.cvss || '', fixed: (v.fixed || []).join(','), introduced: (v.introduced || []).join(','), published: v.published || '', url: v.url || `https://osv.dev/vulnerability/${v.id}` } },
      );
    }
  }
}
const RANK = { none: 0, unknown: 1, low: 2, moderate: 3, medium: 3, high: 4, critical: 5 };

// MCP servers declared in agent configs (from the daemon's inventory scan).
// Skill surfaces from the daemon's skill scanner (skills, plugins, rules, MCP
// configs, instruction files), with what the scanner found in them.
//   { device, agent, kind, path, owner, files_scanned, risk, findings: [{severity, category, message, file, source}] }
export async function ingestSkills(items) {
  const graph = g();
  const rank = { critical: 3, high: 2, medium: 1, low: 0, clean: 0 };
  for (const k of items) {
    const findings = (k.findings || []).slice(0, 25).map((f) => ({ severity: String(f.severity || 'medium').toLowerCase(), category: f.category || '', message: redact(f.message || '').slice(0, 300), file: f.file || '', source: f.source || '' }));
    findings.sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));
    const worst = findings[0]?.severity;
    const risk = String(k.risk || worst || 'clean').toLowerCase();
    await graph.query(
      `MERGE (d:Device {id: $device})
       MERGE (sk:Skill {device: $device, path: $path})
       SET sk.agent = $agent, sk.kind = $kind, sk.owner = $owner, sk.files_scanned = $files, sk.risk = $risk,
           sk.finding_count = $count, sk.top_finding = $top, sk.findings = $findings, sk.scanned_at = $ts, sk.simulated = $sim
       MERGE (d)-[:HAS_SKILL]->(sk)`,
      { params: { device: String(k.device), path: String(k.path), agent: k.agent || '', kind: k.kind || '', owner: k.owner || '', files: Number(k.files_scanned) || 0, risk, count: findings.length, top: findings[0] ? `${findings[0].category || findings[0].severity}: ${findings[0].message}`.slice(0, 200) : '', findings: JSON.stringify(findings), ts: Number(k.ts) || Date.now(), sim: k.simulated === true } },
    );
    await skillSignature(String(k.device), String(k.path), k.kind);
  }
}

export async function ingestMcpServers(servers) {
  const graph = g();
  for (const m of servers) {
    await graph.query(
      `MERGE (d:Device {id: $device})
       MERGE (s:McpServer {name: $name, device: $device})
       SET s.agent = $agent, s.transport = $transport, s.url = $url, s.command = $command, s.scope = $scope, s.held = $held,
           s.approved = $approved
       MERGE (d)-[:DECLARES]->(s)`,
      { params: { device: String(m.device), name: m.name, agent: m.agent || '', transport: m.transport || '', url: m.url || '', command: redact(m.command || ''), scope: m.scope || '', held: !!m.held, approved: isApprovedMcp(m.name, m.url) } },
    );

  }
}
const APPROVED_MCP = new Set((process.env.APPROVED_MCP || 'filesystem,github,postgres').split(',').map((s) => s.trim()).filter(Boolean));
export function isApprovedMcp(name, url) {
  if (APPROVED_MCP.has(name)) return true;
  try { return url ? isApprovedHost(new URL(url).hostname) : false; } catch { return false; }
}

// Narrative lines from the daemon's commentary → (:Note) on the session.
export async function ingestNotes(notes) {
  const graph = g();
  for (const n of notes) {
    await graph.query(
      `MERGE (s:Session {id: $session})
       CREATE (n:Note {seq: $seq, ts: $ts, level: $level, kind: $kind, text: $text, agent: $agent})
       CREATE (s)-[:NOTED]->(n)`,
      { params: { session: String(n.session), seq: Number(n.seq) || 0, ts: Number(n.ts) || Date.now(), level: n.level || 'info', kind: n.kind || '', text: redact(n.text), agent: n.agent || '' } },
    );
  }
}
