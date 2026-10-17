// auth.js — one shared token for everything: the dashboard, the API, /mcp.
//
// Agent SIEM can block hosts, contain sessions and start paid voice sessions,
// so nothing is open by default.
//   - Programs (simulator, RZS adapter, MCP clients) send  Authorization: Bearer <token>.
//   - Browsers open  /?token=<token>  once; the server sets an HttpOnly cookie.
//
//   SIEM_TOKEN=...   the token. If unset, one is generated on first start,
//                    saved to data/siem-token (mode 600) and printed.

import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'siem-token');

export function siemToken() {
  if (process.env.SIEM_TOKEN) return process.env.SIEM_TOKEN;
  try { const t = fs.readFileSync(FILE, 'utf8').trim(); if (t) return t; } catch { /* first start */ }
  const t = randomBytes(24).toString('base64url');
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, t + '\n', { mode: 0o600 });
  return t;
}

const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const cookieOf = (req) => (req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).find(([k]) => k === 'siem_token')?.[1];

const LOGIN = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent SIEM</title>
<style>body{font:15px system-ui,sans-serif;background:#fafafa;color:#0a0a0a;display:grid;place-items:center;min-height:100vh;margin:0}form{background:#fff;border:1px solid #e5e5e5;border-radius:12px;padding:28px;width:min(360px,90vw)}h1{font-size:18px;margin:0 0 6px}p{color:#737373;font-size:13px;margin:0 0 16px}input{width:100%;box-sizing:border-box;height:38px;border:1px solid #e5e5e5;border-radius:8px;padding:0 10px;font:13px ui-monospace,monospace}button{margin-top:12px;width:100%;height:38px;border:0;border-radius:8px;background:#01696f;color:#fff;font:600 14px system-ui}</style>
<form method="get" action="/"><h1>Agent SIEM</h1><p>Ring Zero Security. Enter the access token (SIEM_TOKEN, or data/siem-token on the server).</p><input name="token" type="password" autocomplete="current-password" placeholder="access token" autofocus><button>Open</button></form>`;

export function authMiddleware() {
  const token = siemToken();
  return (req, res, next) => {
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const ok = (bearer && same(bearer, token)) || (cookieOf(req) && same(cookieOf(req), token));
    // Browser sign-in: /?token=... sets the cookie and strips the token from the URL.
    if (req.method === 'GET' && typeof req.query.token === 'string') {
      if (same(req.query.token, token)) {
        res.setHeader('Set-Cookie', `siem_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000`);
        return res.redirect(302, req.path);
      }
      return res.status(401).type('html').send(LOGIN);
    }
    if (ok) return next();
    if (req.path.startsWith('/api/') || req.path === '/mcp') return res.status(401).json({ error: 'unauthorized: send Authorization: Bearer <SIEM_TOKEN>' });
    if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) return res.status(401).type('html').send(LOGIN);
    return res.status(401).end();
  };
}
