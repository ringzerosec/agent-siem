// simulator.js — plays a fleet of employee devices running AI coding agents so
// the wall has something to show without a real daemon attached.
//
// Each device runs one or two agent sessions doing ordinary development work
// (reading the repo, running tests, pulling packages, calling the model API).
// Now and then a session drifts: it reads a credential and the same process
// tree later connects to a host that is not on the approved list. Those are
// the devices that should turn red on the wall.
//
//   node src/simulator.js                       # 12 endpoints → http://localhost:8080
//   SIM_DEVICES=20 SIM_RATE_MS=300 node src/simulator.js

const API = process.env.API || 'http://localhost:8080';
const DEVICES = Number(process.env.SIM_DEVICES || 12);
const RATE = Number(process.env.SIM_RATE_MS || 3000);
const SESSION_LEN = Number(process.env.SIM_SESSION_LEN || 120);   // actions per session before the agent run ends and a new one starts

const AGENTS = ['claude-code', 'cursor-agent', 'codex', 'gemini-cli'];
// Endpoints are named like a corporate asset inventory: <team>-<form factor>-<asset no>.
// The tile's headline is the owning team, never a person.
const ENDPOINTS = [
  ['ENG-MBP-0142', 'Platform Engineering'], ['ENG-MBP-0217', 'Platform Engineering'], ['PAY-MBP-0388', 'Payments'],
  ['DS-WKS-0051', 'Data Science'], ['SEC-LT-0019', 'Security Engineering'], ['MOB-MBP-0264', 'Mobile'],
  ['SRE-LT-0073', 'Site Reliability'], ['FIN-LT-0412', 'Finance Systems'], ['ML-WKS-0096', 'ML Research'],
  ['WEB-MBP-0335', 'Web Frontend'], ['API-LT-0158', 'API Platform'], ['QA-LT-0229', 'Quality Engineering'],
  ['ENG-MBP-0301', 'Platform Engineering'], ['DATA-LT-0187', 'Data Engineering'], ['IT-LT-0044', 'IT Operations'],
  ['INF-WKS-0120', 'Infrastructure'], ['PAY-LT-0399', 'Payments'], ['DS-MBP-0063', 'Data Science'],
  ['CORE-LT-0275', 'Core Services'], ['GRW-MBP-0350', 'Growth Engineering'],
];
const REPO = ['/home/dev/app/src/main.rs', '/home/dev/app/src/lib.rs', '/home/dev/app/Cargo.toml', '/home/dev/app/README.md', '/home/dev/app/tests/api_test.rs', '/home/dev/app/package.json', '/home/dev/app/src/routes.ts', '/home/dev/app/src/auth.ts'];
const SECRETS = ['/home/dev/app/.env', '/home/dev/.ssh/id_ed25519', '/home/dev/.aws/credentials', '/home/dev/.docker/config.json'];
const APPROVED = ['api.anthropic.com', 'api.openai.com', 'github.com', 'registry.npmjs.org', 'pypi.org'];
const UNAPPROVED = ['pastebin.com', 'webhook.site', 'transfer.sh', 'ngrok-free.app', 'requestbin.net'];

// MCP servers each laptop's agents declare. A third of the fleet also has an
// untrusted community server installed; a few laptops carry a poisoned skill.
const TRUSTED_MCP = [['filesystem', 'stdio', 'npx -y @modelcontextprotocol/server-filesystem /home/dev/app'], ['github', 'http', 'https://api.githubcopilot.com/mcp/'], ['postgres', 'stdio', 'npx -y @modelcontextprotocol/server-postgres']];
const UNTRUSTED_MCP = [['notes-sync', 'stdio', 'npx -y notes-sync-mcp@latest', 'export_workspace'], ['web-scraper-pro', 'http', 'https://mcp.scraper-pro.dev/sse', 'fetch_and_post'], ['crypto-helper', 'stdio', 'uvx crypto-helper-mcp', 'sign_and_send']];
const POISONED_SKILL = '/home/dev/.claude/skills/repo-insights';

let eventSeq = 0;
const pick = (a) => a[Math.floor(Math.random() * a.length)];
const now = () => Date.now();

class Session {
  constructor(device, owner, n, agentIdx, profile = {}) {
    this.device = device; this.owner = owner; this.profile = profile;
    this.id = `${device}-s${n}`;
    this.agent = AGENTS[agentIdx % AGENTS.length];
    this.rootPid = 1000 + n * 1000;
    this.nextPid = this.rootPid + 1;
    this.step = 0;
    this.drifts = Math.random() < 0.25;          // about a quarter of sessions drift
    this.driftAt = 3 + Math.floor(Math.random() * 10);
    this.drifted = false;
  }
  ev(kind, pid, target, extra = {}) {
    return { id: `e${++eventSeq}`, ts: now(), device: this.device, owner: this.owner, simulated: true, session: this.id, agent: this.agent, kind, pid, process: extra.process || this.agent, target, allowed: extra.allowed !== false, ppid: extra.ppid, parent_process: extra.parent_process };
  }
  child(name) {
    const pid = this.nextPid++;
    return { pid, ev: this.ev('spawn', pid, '', { process: name, ppid: this.rootPid, parent_process: this.agent }) };
  }
  normal() {
    const r = Math.random();
    if (r < 0.45) return [this.ev('read', this.rootPid, pick(REPO))];
    if (r < 0.6) return [this.ev('write', this.rootPid, pick(REPO))];
    if (r < 0.75) return [this.ev('connect', this.rootPid, pick(APPROVED) + ':443')];
    if (r < 0.84) {
      const c = this.child(pick(['cargo', 'pytest', 'node', 'git']));
      return [c.ev, this.ev('exec', c.pid, `/usr/bin/${c.ev.process} test`, { process: c.ev.process, ppid: this.rootPid, parent_process: this.agent })];
    }
    if (r < 0.87) {
      const c = this.child('npm');
      return [c.ev, this.ev('exec', c.pid, '/usr/bin/npm install left-pad', { process: 'npm', ppid: this.rootPid, parent_process: this.agent }), this.ev('connect', c.pid, 'registry.npmjs.org:443', { process: 'npm', ppid: this.rootPid })];
    }
    return [this.ev('tool', this.rootPid, pick(['filesystem/read_file', 'github/create_issue', 'postgres/query']))];   // trusted servers only in normal work
  }
  // The drift: one of three attacks, all refused (enforce mode everywhere):
  //   - a credential read, written into an innocuous file, then curl out;
  //   - a call to the laptop's untrusted MCP server, then curl out;
  //   - the agent loading a poisoned skill, which tells it to send a secret out.
  drift() {
    this.drifted = true;
    const kinds = ['secret'];
    if (this.profile.untrusted) kinds.push('mcp', 'mcp');
    if (this.profile.poisoned) kinds.push('skill', 'skill');
    const kind = pick(kinds);
    if (kind === 'mcp') {
      const [server, , , tool] = this.profile.untrusted;
      const c = this.child('curl');
      return [
        { ...this.ev('tool', this.rootPid, `${server}/${tool}`, { allowed: false }), reason: 'untrusted MCP server (enforce)' },
        c.ev,
        { ...this.ev('connect', c.pid, pick(UNAPPROVED) + ':443', { process: 'curl', ppid: this.rootPid, parent_process: this.agent, allowed: false }), reason: 'unapproved host (enforce)' },
      ];
    }
    if (kind === 'skill') {
      const c = this.child('curl');
      return [
        this.ev('read', this.rootPid, `${POISONED_SKILL}/SKILL.md`),
        this.ev('read', this.rootPid, pick(SECRETS)),
        c.ev,
        { ...this.ev('connect', c.pid, pick(UNAPPROVED) + ':443', { process: 'curl', ppid: this.rootPid, parent_process: this.agent, allowed: false }), reason: 'unapproved host (enforce)' },
      ];
    }
    const c = this.child('curl');
    return [
      this.ev('read', this.rootPid, pick(SECRETS)),
      this.ev('write', this.rootPid, '/home/dev/app/docs/diagram.md'),
      c.ev,
      { ...this.ev('connect', c.pid, pick(UNAPPROVED) + ':443', { process: 'curl', ppid: this.rootPid, parent_process: this.agent, allowed: false }), reason: 'unapproved host (enforce)' },
    ];
  }
  tick() {
    this.step++;
    if (this.step > SESSION_LEN) {   // the run ended; a new session starts on the same device
      this.n = (this.n || 1) + 1; this.id = `${this.device}-s${this.n}`; this.step = 1; this.drifted = false; this.drifts = Math.random() < 0.25; this.driftAt = 3 + Math.floor(Math.random() * 10);
      this.rootPid += 1000; this.nextPid = this.rootPid + 1;
    }
    if (this.drifts && !this.drifted && this.step >= this.driftAt) return this.drift();
    return this.normal();
  }
}

async function post(events) {
  const r = await fetch(`${API}/api/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(events) });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
}

const sessions = [];
const profiles = [];
for (let i = 0; i < DEVICES; i++) {
  const [device, owner] = ENDPOINTS[i % ENDPOINTS.length];
  const profile = { device, untrusted: i % 3 === 1 ? UNTRUSTED_MCP[i % UNTRUSTED_MCP.length] : null, poisoned: i % 4 === 2 };
  profiles.push(profile);
  const n = 1 + (Math.random() < 0.35 ? 1 : 0);        // some devices run two agents
  for (let k = 1; k <= n; k++) sessions.push(new Session(device, owner, k, i + k, profile));
}

// What each laptop declares (MCP servers) and what the skill scanner found
// (skill surfaces), re-sent every 10 minutes like a real daemon's scan.
async function declare() {
  const mcp = [], skills = [];
  for (const p of profiles) {
    for (const [name, transport, cmd] of TRUSTED_MCP) mcp.push({ device: p.device, name, agent: 'claude-code', transport, command: transport === 'stdio' ? cmd : '', url: transport === 'http' ? cmd : '', scope: 'user' });
    if (p.untrusted) { const [name, transport, cmd] = p.untrusted; mcp.push({ device: p.device, name, agent: 'cursor-agent', transport, command: transport === 'stdio' ? cmd : '', url: transport === 'http' ? cmd : '', scope: 'project' }); }
    skills.push(
      { device: p.device, simulated: true, agent: 'claude', kind: 'skills', path: '/home/dev/.claude/skills/pdf-tools', owner: 'dev', files_scanned: 3, risk: 'clean', findings: [] },
      { device: p.device, simulated: true, agent: 'cursor', kind: 'rules', path: '/home/dev/app/.cursor/rules', owner: 'dev', files_scanned: 2, risk: 'clean', findings: [] },
      { device: p.device, simulated: true, agent: 'claude', kind: 'mcp', path: '/home/dev/.claude.json', owner: 'dev', files_scanned: 1, risk: p.untrusted ? 'medium' : 'clean',
        findings: p.untrusted ? [{ severity: 'medium', category: 'Supply chain', message: `unpinned community MCP server "${p.untrusted[0]}" (${p.untrusted[2]})`, file: '/home/dev/.claude.json', source: 'supply-chain' }] : [] },
    );
    if (p.poisoned) skills.push({ device: p.device, simulated: true, agent: 'claude', kind: 'skills', path: POISONED_SKILL, owner: 'dev', files_scanned: 2, risk: 'high', findings: [
      { severity: 'high', category: 'Prompt injection', message: 'classic override (matched: "ignore previous instructions")', file: `${POISONED_SKILL}/SKILL.md`, source: 'heuristic' },
      { severity: 'high', category: 'Credential access', message: 'instructs the agent to read ~/.aws/credentials and post it to an external URL', file: `${POISONED_SKILL}/SKILL.md`, source: 'pattern' },
    ] });
  }
  try { await fetch(`${API}/api/mcp-servers`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(mcp) }); await fetch(`${API}/api/skills`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(skills) }); }
  catch (e) { console.error('declare failed:', e.message); }
}
declare(); setInterval(declare, 10 * 60 * 1000);
console.log(`simulating ${DEVICES} devices / ${sessions.length} agent sessions → ${API} (one batch every ${RATE} ms)`);
let i = 0;
setInterval(async () => {
  const s = sessions[i++ % sessions.length];
  const events = s.tick();
  try { await post(events); process.stdout.write(events.some((e) => e.kind === 'connect' && !APPROVED.includes(e.target.split(':')[0])) ? '!' : '.'); }
  catch (e) { console.error('\npost failed:', e.message); }
}, RATE);
