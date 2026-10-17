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

export function isSensitive(path) { return SENSITIVE.some((r) => r.test(path)); }
export function isInstructionFile(path) { return INSTRUCTION_FILES.some((r) => r.test(path)); }

const APPROVED_HOSTS = new Set(
  (process.env.APPROVED_HOSTS || 'api.anthropic.com,api.openai.com,github.com,registry.npmjs.org,pypi.org,crates.io,files.pythonhosted.org')
    .split(',').map((s) => s.trim()).filter(Boolean),
);
export function isApprovedHost(name) { return APPROVED_HOSTS.has(name); }

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
  const owner = ev.owner || '';
  const agent = ev.agent || 'unknown-agent';
  const pid = Number(ev.pid);
  const key = `${session}:${pid}`;
  const ts = Number(ev.ts) || Date.now();
  const allowed = ev.allowed !== false;
  const procName = ev.process || 'unknown';

  await graph.query(
    `MERGE (d:Device {id: $device})
       ON CREATE SET d.owner = $owner, d.first_ts = $ts, d.simulated = $simulated
     MERGE (s:Session {id: $session})
       ON CREATE SET s.agent = $agent, s.started = $ts, s.device = $device
     SET s.agent = coalesce(s.agent, $agent), s.device = coalesce(s.device, $device), s.state = coalesce($state, s.state), s.privileged = coalesce($priv, s.privileged), s.privileged_reason = coalesce($preason, s.privileged_reason)
     MERGE (d)-[:RUNS]->(s)
     MERGE (a:Agent {name: $agent})
     MERGE (s)-[:RAN_BY]->(a)
     MERGE (p:Process {key: $key})
       ON CREATE SET p.pid = $pid, p.name = $proc, p.first_ts = $ts, p.session = $session
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
           ON CREATE SET h.approved = $approved
         CREATE (p)-[:CONNECTED {ts: $ts, event: $id, allowed: $allowed, port: $port}]->(h)`,
        { params: { key, host, approved: isApprovedHost(host), ts, id: ev.id || '', allowed, port: Number(port) || 443 } },
      );
      break;
    }
    case 'tool': {
      const [server, tool] = target.includes('/') ? target.split('/') : ['local', target];
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (t:McpTool {name: $tool, server: $server})
         CREATE (p)-[:USED_TOOL {ts: $ts, event: $id, allowed: $allowed}]->(t)`,
        { params: { key, tool, server, ts, id: ev.id || '', allowed } },
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
         MERGE (h:Host {name: $host}) ON CREATE SET h.approved = $approved
         CREATE (p)-[:SENT {ts: $ts, event: $id, allowed: $allowed, port: $port, reason: $reason}]->(h)`,
        { params: { key, host, approved: isApprovedHost(host), ts, id: ev.id || '', allowed, port: Number(port) || 443, reason: ev.reason || '' } },
      );
      break;
    }
    case 'dns': {
      const name = target.toLowerCase();
      const labels = name.split('.');
      const longest = Math.max(...labels.map((l) => l.length));
      await graph.query(
        `MATCH (p:Process {key: $key})
         MERGE (h:Host {name: $host}) ON CREATE SET h.approved = $approved
         SET h.longest_label = $longest, h.labels = $nlabels
         CREATE (p)-[:RESOLVED {ts: $ts, event: $id, allowed: $allowed}]->(h)`,
        { params: { key, host: name, approved: isApprovedHost(name), longest, nlabels: labels.length, ts, id: ev.id || '', allowed } },
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
