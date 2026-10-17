// auth.js — who may use Agent SIEM, and what they may do.
//
// Agent SIEM can block hosts, contain sessions and start paid voice sessions,
// so nothing is open by default. Two roles:
//   admin   everything. Programs (simulator, RZS adapter, MCP clients) send
//           Authorization: Bearer <SIEM_TOKEN>; people sign in with the master
//           password (SIEM_PASSWORD) on the login page.
//   viewer  read-only, for judges and demos. Signed in through a judge link
//           (/j/<signed token>) an admin creates; it expires and can be revoked.
//           Viewers can look at everything, investigate and talk to Pepper,
//           but anything that changes state is refused on the server.
//
// Browsers hold a signed session cookie, never the password or the token. The
// signing key is derived from SIEM_TOKEN + SIEM_PASSWORD, so changing either
// signs everyone out. Wrong passwords lock that client out for 15 minutes
// after 5 tries.
//
//   SIEM_TOKEN=...      program token. If unset, generated on first start and
//                       saved to data/siem-token (mode 600).
//   SIEM_PASSWORD=...   master password. If unset, the token doubles as it.

import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const DATA = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
const TOKEN_FILE = path.join(DATA, 'siem-token');
const LINKS_FILE = path.join(DATA, 'judge-links.json');
const ADMIN_TTL = 12 * 3600_000;
const VIEWER_TTL = 12 * 3600_000;
const MAX_FAILS = 5, LOCK_MS = 15 * 60_000;

export function siemToken() {
  if (process.env.SIEM_TOKEN) return process.env.SIEM_TOKEN;
  try { const t = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); if (t) return t; } catch { /* first start */ }
  const t = randomBytes(24).toString('base64url');
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, t + '\n', { mode: 0o600 });
  return t;
}
const password = () => process.env.SIEM_PASSWORD || siemToken();

const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
let KEY;
const key = () => (KEY ||= createHmac('sha256', 'agent-siem-session').update(siemToken() + '\0' + password()).digest());
const b64 = (s) => Buffer.from(s).toString('base64url');
function sign(payload) { const p = b64(JSON.stringify(payload)); return `${p}.${createHmac('sha256', key()).update(p).digest('base64url')}`; }
function verify(str) {
  const [p, mac] = String(str || '').split('.');
  if (!p || !mac || !same(mac, createHmac('sha256', key()).update(p).digest('base64url'))) return null;
  try { const v = JSON.parse(Buffer.from(p, 'base64url').toString()); return v.exp > Date.now() ? v : null; } catch { return null; }
}

// ---- judge links ------------------------------------------------------------
let links = null;
function loadLinks() { if (!links) { try { links = JSON.parse(fs.readFileSync(LINKS_FILE, 'utf8')); } catch { links = []; } } return links; }
function saveLinks() { fs.mkdirSync(DATA, { recursive: true }); fs.writeFileSync(LINKS_FILE, JSON.stringify(links, null, 2), { mode: 0o600 }); }
const liveLink = (id) => loadLinks().find((l) => l.id === id && !l.revoked && l.exp > Date.now());

export function createJudgeLink({ label = 'Judges', hours = 72 } = {}) {
  const h = Math.min(Math.max(Number(hours) || 72, 1), 24 * 14);
  const link = { id: randomBytes(6).toString('hex'), label: String(label).slice(0, 60), created: Date.now(), exp: Date.now() + h * 3600_000, revoked: false };
  loadLinks().push(link); saveLinks();
  return { ...link, path: `/j/${sign({ t: 'judge', id: link.id, exp: link.exp })}` };
}
export function listJudgeLinks() {
  return loadLinks().map((l) => ({ ...l, active: !l.revoked && l.exp > Date.now() }));
}
export function revokeJudgeLink(id) {
  const l = loadLinks().find((x) => x.id === id);
  if (l) { l.revoked = true; saveLinks(); }
  return !!l;
}

// ---- login lockout ------------------------------------------------------------
const fails = new Map();   // client -> { n, until }
// Behind a proxy every request comes from the proxy, so a shared lockout would
// let anyone lock everyone out. A trusted proxy can name the client in a header (CLIENT_IP_HEADER; it
// overwrites any value a client sends). Behind a local reverse proxy (Caddy)
// requests come from loopback: take the client from X-Forwarded-For there.
// Otherwise the socket address.
function clientOf(req) {
  const ch = process.env.CLIENT_IP_HEADER?.toLowerCase(); if (ch && req.headers[ch]) return String(req.headers[ch]);
  const sock = req.socket?.remoteAddress || '';
  const loop = sock === '127.0.0.1' || sock === '::1' || sock === '::ffff:127.0.0.1';
  return (loop && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || sock;
}
function locked(c) { const f = fails.get(c); return f && f.until > Date.now(); }
function failed(c) {
  const f = fails.get(c) || { n: 0, until: 0 };
  f.n += 1; if (f.n >= MAX_FAILS) { f.until = Date.now() + LOCK_MS; f.n = 0; }
  fails.set(c, f);
}

// ---- pages --------------------------------------------------------------------
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const page = (msg = '') => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent SIEM</title>
<style>body{font:15px system-ui,sans-serif;background:#fafafa;color:#0a0a0a;display:grid;place-items:center;min-height:100vh;margin:0}form{background:#fff;border:1px solid #e5e5e5;border-radius:12px;padding:28px;width:min(360px,90vw)}h1{font-size:18px;margin:0 0 6px}p{color:#737373;font-size:13px;margin:0 0 16px}.err{color:#b42318}input{width:100%;box-sizing:border-box;height:38px;border:1px solid #e5e5e5;border-radius:8px;padding:0 10px;font:14px system-ui}button{margin-top:12px;width:100%;height:38px;border:0;border-radius:8px;background:#01696f;color:#fff;font:600 14px system-ui;cursor:pointer}
@media (prefers-color-scheme:dark){body{background:#0a0a0a;color:#fafafa}form{background:#171717;border-color:#262626}input{background:#0a0a0a;color:#fafafa;border-color:#262626}}</style>
<form method="post" action="/login"><h1>Agent SIEM</h1><p>Ring Zero Security</p>${msg ? `<p class="err">${esc(msg)}</p>` : ''}<input name="password" type="password" autocomplete="current-password" placeholder="Password" autofocus required><button>Sign in</button></form>`;

const secure = (req) => req.secure || req.headers['x-forwarded-proto'] === 'https';
function setSession(req, res, payload) {
  const maxAge = Math.max(1, Math.floor((payload.exp - Date.now()) / 1000));
  res.setHeader('Set-Cookie', `siem_session=${sign(payload)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`);
}
const cookieOf = (req) => (req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).find(([k]) => k === 'siem_session')?.[1];

function readForm(req, limit = 4096) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > limit) { req.destroy(); resolve({}); } });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(body))));
    req.on('error', () => resolve({}));
  });
}

// What a viewer may POST: investigations and talking to Pepper. Everything
// else that changes state (approve, block, contain, scan, ingest, reset, /mcp)
// is admin only.
const VIEWER_POSTS = [/^\/api\/triage$/, /^\/api\/pepper\/(session|screen|say|heads|close)(\/|$)/];

export function authMiddleware() {
  const token = siemToken();
  return async (req, res, next) => {
    // Sign in with the master password.
    if (req.path === '/login' && req.method === 'POST') {
      const c = clientOf(req);
      if (locked(c)) return res.status(429).type('html').send(page('Too many attempts. Try again in 15 minutes.'));
      const { password: pw = '' } = await readForm(req);
      if (pw && same(pw, password())) {
        fails.delete(c);
        setSession(req, res, { role: 'admin', exp: Date.now() + ADMIN_TTL });
        return res.redirect(303, '/');
      }
      failed(c);
      return res.status(401).type('html').send(page('Wrong password.'));
    }
    if (req.path === '/logout') {
      res.setHeader('Set-Cookie', 'siem_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
      return res.redirect(303, '/');
    }
    // Judge link: a signed, expiring, revocable read-only sign-in.
    if (req.method === 'GET' && req.path.startsWith('/j/')) {
      const v = verify(req.path.slice(3));
      const link = v?.t === 'judge' && liveLink(v.id);
      if (!link) return res.status(401).type('html').send(page('This link has expired or was revoked.'));
      setSession(req, res, { role: 'viewer', link: link.id, exp: Math.min(link.exp, Date.now() + VIEWER_TTL) });
      return res.redirect(303, '/');
    }

    // Who is this?
    let role = null, link = null;
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (bearer && same(bearer, token)) role = 'admin';
    else {
      const s = verify(cookieOf(req));
      if (s?.role === 'admin') role = 'admin';
      else if (s?.role === 'viewer' && liveLink(s.link)) { role = 'viewer'; link = s.link; }   // revocation takes effect at once
    }
    // Local convenience: /?token=<SIEM_TOKEN> signs in as admin, then drops the token from the URL.
    if (!role && req.method === 'GET' && typeof req.query.token === 'string' && same(req.query.token, token)) {
      setSession(req, res, { role: 'admin', exp: Date.now() + ADMIN_TTL });
      return res.redirect(302, req.path);
    }

    if (!role) {
      if (req.path.startsWith('/api/') || req.path === '/mcp') return res.status(401).json({ error: 'unauthorized: sign in, or send Authorization: Bearer <SIEM_TOKEN>' });
      if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) return res.status(401).type('html').send(page());
      return res.status(401).end();
    }
    req.role = role; req.judgeLink = link;
    if (role === 'viewer' && !['GET', 'HEAD'].includes(req.method) && !VIEWER_POSTS.some((r) => r.test(req.path))) {
      return res.status(403).json({ error: 'read-only access: this action needs the admin password' });
    }
    next();
  };
}

// Admin-only routes (reads that expose more than the dashboard shows).
export function adminOnly(req, res, next) {
  if (req.role === 'admin') return next();
  res.status(403).json({ error: 'admin only' });
}
