// simulator.js — feeds the dashboard with live agent activity so it has
// something to show without a real daemon attached.
//
// It plays several concurrent "sessions" of an AI coding agent doing ordinary
// work (reading the repo, running tests, pulling packages, calling its model
// API). Now and then one session drifts: it reads a credential and the same
// process tree later connects to a host that is not on the approved list.
// Those are the sessions the dashboard should turn red.
//
//   node src/simulator.js            # posts to http://localhost:8080
//   SIM_SESSIONS=4 SIM_RATE_MS=800 node src/simulator.js

const API = process.env.API || 'http://localhost:8080';
const SESSIONS = Number(process.env.SIM_SESSIONS || 3);
const RATE = Number(process.env.SIM_RATE_MS || 900);

const AGENTS = ['claude-code', 'cursor-agent', 'codex', 'gemini-cli'];
const REPO = ['/home/dev/app/src/main.rs', '/home/dev/app/src/lib.rs', '/home/dev/app/Cargo.toml', '/home/dev/app/README.md', '/home/dev/app/tests/api_test.rs', '/home/dev/app/package.json', '/home/dev/app/src/routes.ts'];
const SECRETS = ['/home/dev/app/.env', '/home/dev/.ssh/id_ed25519', '/home/dev/.aws/credentials', '/home/dev/.docker/config.json'];
const APPROVED = ['api.anthropic.com', 'api.openai.com', 'github.com', 'registry.npmjs.org', 'pypi.org'];
const UNAPPROVED = ['pastebin.com', 'webhook.site', 'transfer.sh', 'ngrok-free.app', 'requestbin.net'];

let eventSeq = 0;
const pick = (a) => a[Math.floor(Math.random() * a.length)];
const now = () => Date.now();

class Session {
  constructor(i) {
    this.id = `sess-${String(i).padStart(2, '0')}`;
    this.agent = AGENTS[(i - 1) % AGENTS.length];
    this.rootPid = 1000 + i * 100;
    this.nextPid = this.rootPid + 1;
    this.step = 0;
    // Roughly one in three sessions will drift at some point.
    this.drifts = Math.random() < 0.34;
    this.driftAt = 6 + Math.floor(Math.random() * 10);
    this.drifted = false;
  }
  ev(kind, pid, target, extra = {}) {
    return { id: `e${++eventSeq}`, ts: now(), session: this.id, agent: this.agent, kind, pid, process: extra.process || this.agent, target, allowed: extra.allowed !== false, ppid: extra.ppid, parent_process: extra.parent_process };
  }
  child(name) {
    const pid = this.nextPid++;
    return { pid, ev: this.ev('spawn', pid, '', { process: name, ppid: this.rootPid, parent_process: this.agent }) };
  }
  // One tick of ordinary work.
  normal() {
    const r = Math.random();
    if (r < 0.45) return [this.ev('read', this.rootPid, pick(REPO))];
    if (r < 0.6) return [this.ev('write', this.rootPid, pick(REPO))];
    if (r < 0.75) return [this.ev('connect', this.rootPid, pick(APPROVED) + ':443')];
    if (r < 0.85) {
      const c = this.child(pick(['cargo', 'pytest', 'node', 'git']));
      return [c.ev, this.ev('exec', c.pid, `/usr/bin/${c.ev.process} test`, { process: c.ev.process, ppid: this.rootPid, parent_process: this.agent })];
    }
    if (r < 0.92) {
      const c = this.child('npm');
      return [c.ev, this.ev('exec', c.pid, '/usr/bin/npm install left-pad', { process: 'npm', ppid: this.rootPid, parent_process: this.agent }), this.ev('connect', c.pid, 'registry.npmjs.org:443', { process: 'npm', ppid: this.rootPid })];
    }
    return [this.ev('tool', this.rootPid, pick(['filesystem/read_file', 'github/create_issue', 'postgres/query']))];
  }
  // The drift: read a credential, write it into an innocuous file, spawn a
  // child that connects to an unapproved host.
  drift() {
    this.drifted = true;
    const secret = pick(SECRETS);
    const out = '/home/dev/app/docs/diagram.md';
    const c = this.child('curl');
    return [
      this.ev('read', this.rootPid, secret),
      this.ev('write', this.rootPid, out),
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

const sessions = Array.from({ length: SESSIONS }, (_, i) => new Session(i + 1));
console.log(`simulating ${SESSIONS} sessions → ${API} (one event batch every ${RATE} ms)`);
let i = 0;
setInterval(async () => {
  const s = sessions[i++ % sessions.length];
  const events = s.tick();
  try { await post(events); process.stdout.write(events.some((e) => e.kind === 'connect' && !APPROVED.includes(e.target.split(':')[0])) ? '!' : '.'); }
  catch (e) { console.error('\npost failed:', e.message); }
}, RATE);
