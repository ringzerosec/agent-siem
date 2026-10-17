// simulator.js — plays a fleet of employee devices running AI coding agents so
// the wall has something to show without a real daemon attached.
//
// Each device runs one or two agent sessions doing ordinary development work
// (reading the repo, running tests, pulling packages, calling the model API).
// Now and then a session drifts: it reads a credential and the same process
// tree later connects to a host that is not on the approved list. Those are
// the devices that should turn red on the wall.
//
//   node src/simulator.js                       # 12 devices → http://localhost:8080
//   SIM_DEVICES=20 SIM_RATE_MS=300 node src/simulator.js

const API = process.env.API || 'http://localhost:8080';
const DEVICES = Number(process.env.SIM_DEVICES || 12);
const RATE = Number(process.env.SIM_RATE_MS || 1000);

const AGENTS = ['claude-code', 'cursor-agent', 'codex', 'gemini-cli'];
const OWNERS = ['priya', 'arjun', 'meera', 'rahul', 'ananya', 'vikram', 'sneha', 'karthik', 'divya', 'rohan', 'neha', 'aditya', 'ishita', 'manish', 'pooja', 'sameer', 'tanvi', 'varun', 'kavya', 'nikhil'];
const REPO = ['/home/dev/app/src/main.rs', '/home/dev/app/src/lib.rs', '/home/dev/app/Cargo.toml', '/home/dev/app/README.md', '/home/dev/app/tests/api_test.rs', '/home/dev/app/package.json', '/home/dev/app/src/routes.ts', '/home/dev/app/src/auth.ts'];
const SECRETS = ['/home/dev/app/.env', '/home/dev/.ssh/id_ed25519', '/home/dev/.aws/credentials', '/home/dev/.docker/config.json'];
const APPROVED = ['api.anthropic.com', 'api.openai.com', 'github.com', 'registry.npmjs.org', 'pypi.org'];
const UNAPPROVED = ['pastebin.com', 'webhook.site', 'transfer.sh', 'ngrok-free.app', 'requestbin.net'];

let eventSeq = 0;
const pick = (a) => a[Math.floor(Math.random() * a.length)];
const now = () => Date.now();

class Session {
  constructor(device, owner, n, agentIdx) {
    this.device = device; this.owner = owner;
    this.id = `${device}-s${n}`;
    this.agent = AGENTS[agentIdx % AGENTS.length];
    this.rootPid = 1000 + n * 1000;
    this.nextPid = this.rootPid + 1;
    this.step = 0;
    this.drifts = Math.random() < 0.25;          // about a quarter of sessions drift
    this.driftAt = 8 + Math.floor(Math.random() * 20);
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
    return [this.ev('tool', this.rootPid, pick(['filesystem/read_file', 'github/create_issue', 'postgres/query']))];
  }
  // The drift: read a credential, write it into an innocuous file, spawn a
  // child that connects to an unapproved host.
  drift() {
    this.drifted = true;
    const c = this.child('curl');
    return [
      this.ev('read', this.rootPid, pick(SECRETS)),
      this.ev('write', this.rootPid, '/home/dev/app/docs/diagram.md'),
      c.ev,
      this.ev('connect', c.pid, pick(UNAPPROVED) + ':443', { process: 'curl', ppid: this.rootPid, parent_process: this.agent }),
    ];
  }
  tick() {
    this.step++;
    if (this.drifts && !this.drifted && this.step >= this.driftAt) return this.drift();
    return this.normal();
  }
}

async function post(events) {
  const r = await fetch(`${API}/api/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(events) });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
}

const sessions = [];
for (let i = 0; i < DEVICES; i++) {
  const owner = OWNERS[i % OWNERS.length];
  const device = `${owner}-laptop`;
  const n = 1 + (Math.random() < 0.35 ? 1 : 0);        // some devices run two agents
  for (let k = 1; k <= n; k++) sessions.push(new Session(device, owner, k, i + k));
}
console.log(`simulating ${DEVICES} devices / ${sessions.length} agent sessions → ${API} (one batch every ${RATE} ms)`);
let i = 0;
setInterval(async () => {
  const s = sessions[i++ % sessions.length];
  const events = s.tick();
  try { await post(events); process.stdout.write(events.some((e) => e.kind === 'connect' && !APPROVED.includes(e.target.split(':')[0])) ? '!' : '.'); }
  catch (e) { console.error('\npost failed:', e.message); }
}, RATE);
