// autopilot.js — the proactive security loop.
//
// A new critical or high finding does not wait for someone to look at the wall:
//   1. the triage agent investigates it (src/triage.js; it may open tickets),
//   2. its verdict becomes a (:Decision): what happened, who owns the endpoint,
//      and the proposed next steps (escalate to the employee, block, contain…),
//   3. Pepper raises it out loud and the decision lands in the inbox,
//   4. a yes (spoken, or in the inbox) executes it; a no dismisses it.
// Nothing with consequences runs without that yes. Every decision and what was
// done is kept in the graph for audit.
//
//   AUTOPILOT=off      disable
//   SMTP_URL=smtp://user:pass@host:587   SMTP_FROM=security@company.com
//                      without SMTP, escalation emails are stored as drafts

import { randomUUID } from 'node:crypto';
import { g, gr } from './db.js';
import { startTriage, getJob } from './triage.js';
import { createMcpServer } from './mcp-tools.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const ON = process.env.AUTOPILOT !== 'off';
// Investigations cost money with the Claude agent: autopilot uses the playbook
// unless AUTOPILOT_AGENT=claude, runs one at a time, and caps runs per hour.
const AGENT_MODE = process.env.AUTOPILOT_AGENT === 'claude' ? 'agent' : 'playbook';
const MAX_PER_HOUR = Number(process.env.AUTOPILOT_MAX_PER_HOUR || 30);
const handled = new Set();
let queue = Promise.resolve(); const runs = [];
let notify = () => {};            // (decision) => void, set by the server (Pepper + change log)
export function onDecision(fn) { notify = fn; }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Who owns an endpoint: (:Person)-[:USES]->(:Device).
export async function ownerOf(device) {
  const r = await gr().roQuery('MATCH (p:Person)-[:USES]->(:Device {id: $device}) RETURN p LIMIT 1', { params: { device } });
  return r.data?.[0]?.p?.properties || null;
}
export async function setOwners(rows) {
  for (const o of rows) {
    await g().query(
      `MERGE (d:Device {id: $device})
       MERGE (p:Person {email: $email}) SET p.name = $name, p.manager = $manager, p.team = $team
       MERGE (p)-[:USES]->(d)`,
      { params: { device: String(o.device), email: String(o.email).toLowerCase(), name: o.name || '', manager: o.manager || '', team: o.team || '' } });
  }
}

function escalationEmail(owner, device, alert, verdict) {
  const first = (owner?.name || '').split(' ')[0] || 'there';
  const blocked = alert.blocked === true;
  const short = alert.title.split(':')[0].replace(/\s*\(.*\)$/, '');
  const subject = `${blocked ? 'Blocked on your laptop' : 'Action needed'}: ${short} (${device})`;
  const body = [
    `Hi ${first},`,
    '',
    `An AI agent on your laptop (${device}) ${blocked ? 'tried something risky, and Ring Zero Security blocked it' : 'did something risky that was not blocked'}:`,
    '',
    `  ${alert.summary}`,
    '',
    verdict?.summary ? `What our review found: ${verdict.summary}` : '',
    '',
    alert.rule?.includes('skill') ? 'This usually starts with a skill or plugin installed from an unknown source. Please remove it and only install skills from the approved list.'
      : alert.rule?.includes('mcp') ? 'This came from an MCP server that is not on the approved list. Please remove it from your agent configuration.'
        : alert.rule?.includes('shadow') || alert.rule?.includes('unregistered') ? 'This went to an AI service that is not approved for company data. Please use the approved providers, or ask us to review this one.'
          : 'If you did not ask your agent to do this, it may have followed instructions hidden in a file, web page or tool. Please reply so we can look at it together.',
    '',
    'No action is needed to stay protected. Reply to this email if anything looks wrong.',
    '',
    'Security team',
  ].filter((l, i, a) => !(l === '' && a[i - 1] === '')).join('\n');
  return { to: owner?.email || '', cc: owner?.manager || '', subject, body };
}

// What to propose, from the alert and the triage verdict.
function propose(alert, verdict, owner, device) {
  const out = [];
  if (owner?.email) out.push({ type: 'escalate_to_owner', label: `Email ${owner.name || owner.email}`, args: escalationEmail(owner, device, alert, verdict) });
  if (verdict?.verdict === 'true_positive_active' || alert.blocked === false) {
    const host = (alert.summary.match(/(?:connected to|called [^ ]+ at|contacted) ([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
    if (host && /secret|egress|exfil|campaign|shadow/i.test(alert.rule)) out.push({ type: 'block_host', label: `Block ${host} on ${device}`, args: { host, device, reason: alert.title } });
  }
  return out;
}

export function onFinding(device, alert) {
  if (!ON || handled.has(alert.id) || !['critical', 'high'].includes(alert.severity)) return;
  handled.add(alert.id);
  queue = queue.then(() => investigate(device, alert)).catch(() => {});
}
async function investigate(device, alert) {
  const hourAgo = Date.now() - 3600_000;
  while (runs.length && runs[0] < hourAgo) runs.shift();
  if (runs.length >= MAX_PER_HOUR) return;
  runs.push(Date.now());
  try {
    // Don't file a second decision for the same attack. Agent sessions rotate,
    // so the same finding gets a new id each time; dedup on (device, title)
    // while a decision for it is still pending, not just on the alert id.
    const exists = await gr().roQuery(
      `MATCH (d:Decision) WHERE (d.alert = $id) OR (d.device = $device AND d.title = $title AND d.status = 'pending')
       RETURN d.id LIMIT 1`, { params: { id: alert.id, device, title: alert.title } });
    if (exists.data?.length) return;
    // 1. investigate
    const job = startTriage({ device, alertId: alert.id, mode: AGENT_MODE });
    for (let i = 0; i < 120 && getJob(job.id)?.status === 'running'; i++) await sleep(1000);
    const done = getJob(job.id);
    const verdict = done?.verdict || null;
    // 2. decide what to propose
    const owner = await ownerOf(device);
    const proposals = propose(alert, verdict, owner, device);
    const id = 'D-' + randomUUID().slice(0, 6);
    const headline = `${owner?.name ? owner.name + ' (' + device + ')' : device}: ${alert.title}. ${alert.blocked === true ? 'Blocked.' : alert.blocked === false ? 'Not blocked.' : ''}`.trim();
    await g().query(
      `MERGE (d:Device {id: $device})
       CREATE (x:Decision {id: $id, alert: $alert, device: $device, severity: $severity, title: $title, summary: $summary,
         headline: $headline, verdict: $verdict, verdict_summary: $vsum, owner: $owner, owner_email: $email,
         proposals: $proposals, status: 'pending', ts: $ts, triage_mode: $mode})
       CREATE (d)-[:DECISION]->(x)`,
      { params: { device, id, alert: alert.id, severity: alert.severity, title: alert.title, summary: alert.summary, headline, verdict: verdict?.verdict || 'no verdict', vsum: verdict?.summary || '', owner: owner?.name || '', email: owner?.email || '', proposals: JSON.stringify(proposals), ts: Date.now(), mode: done?.mode || '' } });
    // 3. tell the humans
    notify({ id, device, headline, verdict: verdict?.verdict, verdict_summary: verdict?.summary, proposals: proposals.map((p) => p.label), owner });
  } catch (e) { console.error('autopilot', device, alert.id, e.message); }
}

export async function listDecisions(status) {
  const r = await gr().roQuery(`MATCH (x:Decision) WHERE $status IS NULL OR x.status = $status RETURN x ORDER BY x.ts DESC LIMIT 50`, { params: { status: status || null } });
  return (r.data || []).map((row) => { const p = row.x.properties; return { ...p, proposals: JSON.parse(p.proposals || '[]'), results: p.results ? JSON.parse(p.results) : undefined }; });
}

// Execute (all or some of) a decision's proposals: graph actions go through the
// MCP tools (so they are recorded and published like any other action).
export async function approveDecision(id, { only, actor = 'security-engineer' } = {}) {
  const [d] = (await listDecisions(null)).filter((x) => x.id === id);
  if (!d) throw new Error('no such decision');
  if (d.status !== 'pending') return { id, status: d.status, note: 'already handled' };
  const server = createMcpServer({ actor: `${actor} (approved ${id})` });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'agent-siem-autopilot', version: '0.1.0' });
  await client.connect(ct);
  const results = [];
  try {
    for (const p of d.proposals) {
      if (only && !only.includes(p.type)) continue;
      if (p.type === 'escalate_to_owner') results.push(await sendEscalation(d, p.args));
      else if (['block_host', 'open_ticket', 'contain_session'].includes(p.type)) {
        const args = { ...p.args, ...(d.alert ? { alert_id: d.alert } : {}) };
        const r = await client.callTool({ name: p.type, arguments: args });
        results.push({ type: p.type, ok: !r.isError, status: r.isError ? 'failed' : 'done', detail: r.content?.[0]?.text?.slice(0, 300) });
      }
    }
  } finally { await client.close(); await server.close(); }
  await g().query(`MATCH (x:Decision {id: $id}) SET x.status = 'approved', x.decided_at = $ts, x.decided_by = $actor, x.results = $results`,
    { params: { id, ts: Date.now(), actor, results: JSON.stringify(results) } });
  return { id, status: 'approved', results };
}
export async function dismissDecision(id, reason = '', actor = 'security-engineer') {
  await g().query(`MATCH (x:Decision {id: $id}) SET x.status = 'dismissed', x.decided_at = $ts, x.decided_by = $actor, x.reason = $reason`, { params: { id, ts: Date.now(), actor, reason } });
  return { id, status: 'dismissed' };
}

// Escalation email: sent through SMTP when configured, otherwise kept as a draft.
async function sendEscalation(d, mail) {
  const record = async (status, detail) => {
    await g().query(
      `MATCH (x:Decision {id: $id}) MATCH (dev:Device {id: $device})
       CREATE (e:Escalation {to: $to, cc: $cc, subject: $subject, body: $body, status: $status, detail: $detail, ts: $ts, decision: $id})
       CREATE (x)-[:ESCALATED]->(e) CREATE (dev)-[:ESCALATION]->(e)`,
      { params: { id: d.id, device: d.device, to: mail.to, cc: mail.cc || '', subject: mail.subject, body: mail.body, status, detail, ts: Date.now() } });
    return { type: 'escalate_to_owner', ok: true, status, to: mail.to, subject: mail.subject, detail };
  };
  if (!mail.to) return { type: 'escalate_to_owner', ok: false, detail: 'endpoint has no owner' };
  if (!process.env.SMTP_URL) return record('draft', 'no mail server configured (set SMTP_URL); saved as a draft');
  try {
    const nodemailer = (await import('nodemailer')).default;
    const tx = nodemailer.createTransport(process.env.SMTP_URL);
    const info = await tx.sendMail({ from: process.env.SMTP_FROM || 'security@localhost', to: mail.to, cc: mail.cc || undefined, subject: mail.subject, text: mail.body });
    return record('sent', info.messageId || 'sent');
  } catch (e) { return record('failed', e.message); }
}
