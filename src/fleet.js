// fleet.js — fleet-level alert rollups: which endpoints have the most alerts,
// and which alert is most common across all laptops. Answers the questions a
// CISO asks first ("show me the worst endpoint", "what's the biggest repeating
// alert"), from the cached detection results (no extra rule queries).
import { gr } from './db.js';
import { detectDevice } from './detect.js';

export async function fleetSummary({ from = 0, to = Date.now() + 60_000 } = {}) {
  const ids = ((await gr().roQuery('MATCH (d:Device) RETURN d.id AS id')).data || []).map((x) => x.id);
  const byEndpoint = [];
  const byTitle = new Map();   // title -> { count, endpoints:Set, threat, severity, blocked }
  let total = 0;
  for (const id of ids) {
    const alerts = (await detectDevice(id, { from, to })).filter((a) => a.severity !== 'info');
    byEndpoint.push({ device: id, alerts: alerts.length, critical: alerts.filter((a) => a.severity === 'critical').length, high: alerts.filter((a) => a.severity === 'high').length });
    for (const a of alerts) {
      total++;
      const t = byTitle.get(a.title) || { title: a.title, count: 0, endpoints: new Set(), threat: a.threat, severity: a.severity, blocked: 0 };
      t.count++; t.endpoints.add(id); if (a.blocked === true) t.blocked++;
      if (({ critical: 0, high: 1, medium: 2 }[a.severity] ?? 3) < ({ critical: 0, high: 1, medium: 2 }[t.severity] ?? 3)) t.severity = a.severity;
      byTitle.set(a.title, t);
    }
  }
  byEndpoint.sort((a, b) => b.critical - a.critical || b.alerts - a.alerts);
  const topAlerts = [...byTitle.values()].map((t) => ({ title: t.title, threat: t.threat, severity: t.severity, count: t.count, endpoints: t.endpoints.size, blocked: t.blocked }))
    .sort((a, b) => b.count - a.count);
  return {
    total_open_alerts: total,
    endpoints_with_alerts: byEndpoint.filter((e) => e.alerts).length,
    top_endpoints: byEndpoint.filter((e) => e.alerts).slice(0, 8),
    most_common_alerts: topAlerts.slice(0, 8),
  };
}
