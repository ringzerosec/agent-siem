// aiusage.js — the shadow-AI inventory query, shared by the API and the MCP tools.
import { gr } from './db.js';

// Shadow AI inventory: every AI service seen (by protocol fingerprint or by the
// daemon's provider recognition), who calls it, and whether it is approved.
export async function aiUsage(device, from = 0) {
  const r = await gr().roQuery(
    `MATCH (d:Device)-[:RUNS]->(:Session)-[:HAS]->(p:Process)-[c:CALLED_AI]->(a:AiService)
     WHERE ($device IS NULL OR d.id = $device) AND c.ts >= $from
     WITH a, d, p, c
     RETURN a.host AS host, a.provider AS provider, a.family AS family, a.gateway AS gateway, a.self_hosted AS self_hosted, a.approved AS approved,
            collect(DISTINCT d.id) AS endpoints, collect(DISTINCT p.name) AS processes,
            collect(DISTINCT CASE WHEN p.known_agent = false THEN p.name END) AS unregistered,
            count(c) AS calls, sum(CASE WHEN c.allowed = false THEN 1 ELSE 0 END) AS blocked,
            sum(CASE WHEN c.streaming THEN 1 ELSE 0 END) AS streamed,
            collect(DISTINCT c.model)[0..5] AS models, collect(c.signals)[0] AS signals, max(c.ts) AS last
     ORDER BY a.approved, calls DESC`, { params: { device: device || null, from } });
  return (r.data || []).map((x) => ({ ...x, unregistered: x.unregistered.filter(Boolean), models: x.models.filter(Boolean) }));
}
