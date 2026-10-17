// osv.js — enrich installed packages with Google's OSV vulnerability database.
//
// POST https://api.osv.dev/v1/querybatch with {package:{name, ecosystem}, version}.
// Without a version OSV returns every advisory that ever affected the package,
// which is still useful signal for "an agent just pulled this in". Results are
// cached per (ecosystem, name, version) for an hour; OSV is a public API and
// the dashboard must not hammer it on every ingest.

const OSV = process.env.OSV_URL || 'https://api.osv.dev/v1/querybatch';
const TTL = 60 * 60 * 1000;
const cache = new Map();

const ECOSYSTEM = { npm: 'npm', npx: 'npm', yarn: 'npm', pnpm: 'npm', pip: 'PyPI', pip3: 'PyPI', uv: 'PyPI', poetry: 'PyPI', cargo: 'crates.io', gem: 'RubyGems', go: 'Go', apt: 'Debian', 'apt-get': 'Debian' };

// Parse "npm install left-pad@1.3.0 lodash" / "pip install requests==2.31" /
// "cargo add serde@1" into [{name, version, ecosystem}].
export function parseInstall(argv) {
  const parts = (argv || '').trim().split(/\s+/);
  const tool = (parts[0] || '').split('/').pop();
  const eco = ECOSYSTEM[tool];
  if (!eco) return [];
  const verbs = new Set(['install', 'i', 'add', 'run']);
  const start = parts.findIndex((p, i) => i > 0 && verbs.has(p));
  if (start < 0) return [];
  const out = [];
  for (const raw of parts.slice(start + 1)) {
    if (raw.startsWith('-')) continue;
    let name = raw, version;
    if (eco === 'PyPI') {
      const m = raw.match(/^([A-Za-z0-9_.\-\[\]]+?)(?:==|>=|<=|~=|>|<)?([\dA-Za-z.*+!-]*)$/);
      if (m) { name = m[1].replace(/\[.*\]$/, ''); version = raw.includes('==') ? m[2] : undefined; }
    } else if (eco === 'npm') {
      const at = raw.lastIndexOf('@');
      if (at > 0) { name = raw.slice(0, at); version = raw.slice(at + 1); }
    } else {
      const at = raw.indexOf('@');
      if (at > 0) { name = raw.slice(0, at); version = raw.slice(at + 1); }
    }
    if (name && !/^[.\/~]/.test(name)) out.push({ name, version: version && /^\d/.test(version) ? version : undefined, ecosystem: eco });
  }
  return out;
}

function sevOf(v) {
  const db = (v.database_specific && v.database_specific.severity) || '';
  if (db) return String(db).toLowerCase();
  const cvss = (v.severity || []).find((s) => /CVSS/i.test(s.type))?.score || '';
  // crude CVSS vector read: C:H or I:H or A:H → high
  if (/\/C:H|\/I:H|\/A:H/.test(cvss)) return 'high';
  if (cvss) return 'moderate';
  return 'unknown';
}

export async function lookup(pkgs) {
  const todo = [], results = new Map();
  for (const p of pkgs) {
    const k = `${p.ecosystem}:${p.name}:${p.version || '*'}`;
    const c = cache.get(k);
    if (c && Date.now() - c.at < TTL) results.set(k, c.vulns); else todo.push({ k, p });
  }
  if (todo.length) {
    try {
      const r = await fetch(OSV, {
        method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(8000),
        body: JSON.stringify({ queries: todo.map(({ p }) => ({ package: { name: p.name, ecosystem: p.ecosystem }, ...(p.version ? { version: p.version } : {}) })) }),
      });
      const body = r.ok ? await r.json() : { results: [] };
      // querybatch returns ids only; fetch details for the first few so the
      // graph can show severity and a summary.
      for (let i = 0; i < todo.length; i++) {
        const ids = (body.results?.[i]?.vulns || []).map((v) => v.id);
        const detailed = await details(ids);
        const vulns = ids.map((id) => detailed.find((d) => d.id === id) || { id, summary: '', severity: 'unknown' });
        cache.set(todo[i].k, { at: Date.now(), vulns }); results.set(todo[i].k, vulns);
      }
    } catch (e) {
      console.error('osv lookup failed:', e.message);
      todo.forEach(({ k }) => results.set(k, null)); // null = unknown, not "clean"
    }
  }
  return pkgs.map((p) => ({ ...p, vulns: results.get(`${p.ecosystem}:${p.name}:${p.version || '*'}`) }));
}

// querybatch returns only ids; fetch details for the ones we show.
export async function details(ids) {
  const out = [];
  for (const id of ids.slice(0, 10)) {
    try {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(8000) });
      if (r.ok) { const v = await r.json(); out.push({ id: v.id, summary: (v.summary || v.details || '').slice(0, 160), severity: sevOf(v) }); }
    } catch { /* keep going */ }
  }
  return out;
}
