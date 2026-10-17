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

const SENSITIVE = [
  /\/\.env($|\.)/, /\/\.ssh\//, /\/\.aws\//, /\/\.gnupg\//, /\/\.docker\/config\.json$/,
  /\/\.netrc$/, /\/\.npmrc$/, /\/\.pypirc$/, /credentials?(\.json|\.yml|\.yaml)?$/i,
  /secret|token|apikey|api_key|private_key|id_rsa|id_ed25519/i,
];
const INSTRUCTION_FILES = [/CLAUDE\.md$/, /AGENTS\.md$/, /\.cursorrules$/, /\/\.cursor\//, /\/\.claude\//, /SKILL\.md$/];
const PRIVILEGED = new Set(['sudo', 'su', 'pkexec', 'doas', 'run0', 'systemd-run', 'at', 'batch', 'crontab']);
const INSTALLERS = new Set(['pip', 'pip3', 'npm', 'npx', 'uv', 'cargo', 'apt', 'apt-get', 'brew', 'gem']);

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
       ON CREATE SET d.owner = $owner, d.first_ts = $ts
     MERGE (s:Session {id: $session})
       ON CREATE SET s.agent = $agent, s.started = $ts, s.device = $device
     MERGE (d)-[:RUNS]->(s)
     MERGE (a:Agent {name: $agent})
     MERGE (s)-[:RAN_BY]->(a)
     MERGE (p:Process {key: $key})
       ON CREATE SET p.pid = $pid, p.name = $proc, p.first_ts = $ts, p.session = $session
     MERGE (s)-[:HAS]->(p)`,
    { params: { session, device, owner, agent, key, pid, proc: procName, ts } },
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
