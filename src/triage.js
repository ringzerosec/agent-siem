// triage.js — an agent that investigates an alert through the graph and acts.
//
// The agent is an MCP client. It connects to the graph MCP server (in-process
// here; the same server is on POST /mcp for outside agents), lists the tools,
// and lets Claude choose which ones to call: walk the alert path, look at the
// process timeline, check whether the host or the secret shows up elsewhere in
// the fleet, rank what matters with PageRank, then block / contain / open a
// ticket, and submit a verdict. Every step (tool, arguments, result, the
// model's reasoning) is kept so the UI can show how it reached its answer.
//
//   ANTHROPIC_API_KEY=...   enables the Claude agent
//   TRIAGE_MODEL=claude-opus-5-5   (default; Fable 5.1's dual-use safeguards
//                                    decline credential-exfiltration evidence)
//   TRIAGE_FALLBACK_MODEL=claude-opus-5-5  used if the chosen model refuses
//
// Without a key it runs the same investigation as a fixed playbook over the
// same MCP tools, and says so in every result ("mode: playbook").

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer, TOOL_KIND } from './mcp-tools.js';

const MODEL = process.env.TRIAGE_MODEL || 'claude-opus-5-5';
const FALLBACK = process.env.TRIAGE_FALLBACK_MODEL || 'claude-opus-5-5';
const MAX_TURNS = Number(process.env.TRIAGE_MAX_TURNS || 14);

const SYSTEM = `You are the triage agent in Agent SIEM, a security console for AI agents running on employee endpoints. Every action an agent took (process spawned, file read or written, program executed, network connection, MCP tool call) is an edge in a FalkorDB provenance graph. Ring Zero Security enforces policy on each endpoint and may already have refused a step; "allowed": false on an edge means it was blocked.

Investigate the alert you are given using the tools, then act, then submit a verdict.
1. Start with get_alert to see the exact path.
2. Follow the evidence across hops: process_timeline for the process that acted, secret_followups for any secret on the path, host_fleet_exposure for any external host, blast_radius if you need to know what else was reachable, fleet_risk_rank to judge how important an asset is. Use run_readonly_cypher only for a question the other tools cannot answer.
3. Decide. If the exfiltration or command-and-control step was refused, the attempt is contained: do not block again, but open a ticket to rotate any secret that was read. If a step to an unapproved host was allowed, block that host (fleet-wide if more than one endpoint contacted it) and contain the session if it is recent. If the evidence shows benign behaviour, mark_false_positive with the reason. Never block an approved host.
4. Call submit_verdict exactly once, last. Cite node and edge ids in the evidence.

Be economical: 4 to 8 tool calls is typical. Before each tool call, say in one short sentence why you are calling it.`;

// One linked client/server pair per run, over the real MCP protocol.
async function connectMcp(actor) {
  const server = createMcpServer({ actor });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: 'agent-siem-triage', version: '0.1.0' });
  await client.connect(clientT);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

const parse = (res) => { try { return JSON.parse(res.content?.[0]?.text || '{}'); } catch { return { raw: res.content?.[0]?.text }; } };
const short = (obj, n = 600) => { const s = JSON.stringify(obj); return s.length > n ? s.slice(0, n) + '…' : s; };

// ---- jobs ------------------------------------------------------------------
const jobs = new Map();
let seq = 0;
export function getJob(id) { return jobs.get(id); }
export function listJobs(device) { return [...jobs.values()].filter((j) => !device || j.device === device).slice(-20).reverse(); }

export function startTriage({ device, alertId, mode }) {
  const id = `t${++seq}`;
  const useAgent = mode ? mode === 'agent' && !!process.env.ANTHROPIC_API_KEY : !!process.env.ANTHROPIC_API_KEY;
  const job = { id, device, alertId, mode: useAgent ? 'agent' : 'playbook', model: useAgent ? MODEL : null, status: 'running', steps: [], verdict: null, actions: [], started: Date.now() };
  jobs.set(id, job);
  if (jobs.size > 200) jobs.delete(jobs.keys().next().value);
  run(job).catch((e) => { job.status = 'error'; job.error = e.message; job.steps.push({ kind: 'error', text: e.message, ts: Date.now() }); })
    .finally(() => { job.finished = Date.now(); });
  return job;
}

async function run(job) {
  const mcp = await connectMcp(job.mode === 'agent' ? `triage-agent (${MODEL})` : 'triage-playbook');
  try {
    const call = async (name, args, why) => {
      const step = { kind: TOOL_KIND[name] || 'read', tool: name, args, why, ts: Date.now() };
      job.steps.push(step);
      const res = await mcp.client.callTool({ name, arguments: args });
      step.result = parse(res); step.error = !!res.isError; step.ms = Date.now() - step.ts;
      if (step.kind === 'action' && !step.error) job.actions.push({ tool: name, ...args, result: step.result });
      if (name === 'submit_verdict' && !step.error) job.verdict = args;
      return res;
    };
    if (job.mode === 'agent') await runAgent(job, mcp.client, call);
    else await runPlaybook(job, call);
    job.status = job.verdict ? 'done' : 'incomplete';
  } finally { await mcp.close(); }
}

// ---- Claude agent ----------------------------------------------------------
async function runAgent(job, client, call) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const anthropic = new Anthropic();
  const { tools } = await client.listTools();
  // The triage agent investigates; it never approves or dismisses decisions (that is a human's yes).
  const claudeTools = tools.filter((t) => !['approve_decision', 'dismiss_decision'].includes(t.name)).map((t) => ({ name: t.name, description: t.description, input_schema: t.inputSchema }));
  const messages = [{ role: 'user', content: `Triage alert ${job.alertId} on endpoint ${job.device}.` }];
  let model = MODEL;
  for (let turn = 0; turn < MAX_TURNS; turn++) {
    let resp = await anthropic.messages.create({ model, max_tokens: 2000, system: SYSTEM, tools: claudeTools, messages });
    // A model that declines (stop_reason "refusal", no content) hands the same
    // conversation to the fallback model instead of ending the run silently.
    if (resp.stop_reason === 'refusal' && model !== FALLBACK) {
      job.steps.push({ kind: 'thought', text: `${model} declined to continue; handing the investigation to ${FALLBACK}.`, ts: Date.now() });
      model = FALLBACK; job.model = `${MODEL} → ${FALLBACK}`;
      resp = await anthropic.messages.create({ model, max_tokens: 2000, system: SYSTEM, tools: claudeTools, messages });
    }
    if (resp.stop_reason === 'refusal') { job.steps.push({ kind: 'thought', text: `${model} declined to continue this investigation.`, ts: Date.now() }); break; }
    messages.push({ role: 'assistant', content: resp.content });
    job.trace = [...(job.trace || []), { turn, stop: resp.stop_reason, blocks: resp.content.map((b) => b.type) }];
    const results = [];
    let why = '';
    for (const block of resp.content) {
      if (block.type === 'text' && block.text.trim()) { why = block.text.trim(); job.steps.push({ kind: 'thought', text: why, ts: Date.now() }); }
      if (block.type === 'tool_use') {
        const res = await call(block.name, block.input, why);
        results.push({ type: 'tool_result', tool_use_id: block.id, content: res.content?.[0]?.text || '', is_error: !!res.isError });
        why = '';
      }
    }
    if (!results.length || job.verdict) break;
    messages.push({ role: 'user', content: results });
  }
}

// ---- playbook (no API key) -------------------------------------------------
// The same investigation, as fixed steps over the same MCP tools.
async function runPlaybook(job, call) {
  const { device, alertId } = job;
  const say = (text) => job.steps.push({ kind: 'thought', text, ts: Date.now() });
  say('Playbook mode (no ANTHROPIC_API_KEY): fixed investigation steps over the same MCP tools.');
  const a = parse(await call('get_alert', { device, alert_id: alertId }, 'Start from the exact path behind the alert.'));
  if (a.error) { say(a.error); return; }
  const procs = a.nodes.filter((n) => n.kind === 'Process');
  const secrets = a.nodes.filter((n) => n.kind === 'File' && n.secret);
  const hosts = a.nodes.filter((n) => n.kind === 'Host');
  const refused = a.edges.filter((e) => !e.allowed);
  const egress = a.edges.filter((e) => (e.type === 'CONNECTED' || e.type === 'SENT' || e.type === 'CALLED_AI'));
  const aiOut = a.edges.filter((e) => e.type === 'CALLED_AI').map((e) => a.nodes.find((n) => n.id === e.to)).filter((n) => n && n.approved === false);
  const allowedEgress = egress.filter((e) => e.allowed);
  const evidence = [];

  if (procs[0]) await call('process_timeline', { process_id: procs[0].id, limit: 40 }, `See what ${procs[0].name} did around the alert.`);
  for (const s of secrets.slice(0, 2)) {
    const f = parse(await call('secret_followups', { path: s.name }, `Check whether ${s.name} was read elsewhere or left the fleet.`));
    evidence.push(`secret ${s.name} (node ${s.id}) read by ${f.readers?.length || 0} process(es) fleet-wide`);
  }
  const fleetWide = new Set();
  for (const h of hosts.slice(0, 2)) {
    const x = parse(await call('host_fleet_exposure', { host: h.name }, `Is ${h.name} one endpoint or a campaign?`));
    evidence.push(`${h.name} (node ${h.id}): ${x.total_attempts} attempt(s) from ${x.endpoints} endpoint(s), ${x.allowed} allowed`);
    if (x.endpoints > 1) fleetWide.add(h.name);
  }
  await call('fleet_risk_rank', { limit: 5 }, 'Rank the assets involved against the rest of the fleet (PageRank).');
  for (const e of refused) evidence.push(`edge ${e.id} ${e.type} was refused by Ring Zero Security${e.reason ? ` (${e.reason})` : ''}`);

  let verdict;
  if (aiOut.length) {
    // Shadow AI: data went to an AI service nobody approved. Not blocked today (the daemon can't recognize it yet).
    say(`Data went to ${aiOut.map((n) => `${n.provider} (${n.name})`).join(', ')}, which is not an approved AI service.`);
    verdict = 'true_positive_active';
  } else if (!egress.length && !secrets.length) {
    verdict = 'needs_human';
    say('No egress or secret on this path; leave it for a human with the context above.');
  } else if (allowedEgress.length && !aiOut.length) {
    for (const e of allowedEgress) {
      const h = a.nodes.find((n) => n.id === e.to);
      if (h && !h.approved) await call('block_host', { host: h.name, device: fleetWide.has(h.name) ? '*' : device, reason: `${a.title} (alert ${alertId})`, alert_id: alertId }, `Connection to ${h.name} was allowed; block it.`);
    }
    if (a.sessions === 1) {
      const proc = procs[0];
      if (proc?.session) await call('contain_session', { device, session: proc.session, reason: a.summary, alert_id: alertId }, 'Contain the session that made the allowed connection.');
    }
    verdict = 'true_positive_active';
  } else {
    say('The outbound step was refused: the attempt is contained, no block needed.');
    verdict = 'true_positive_contained';
  }
  if (secrets.length) await call('open_ticket', { device, title: `Rotate ${secrets.map((s) => s.name.split('/').pop()).join(', ')} on ${device}`, body: `${a.summary}. ${verdict === 'true_positive_contained' ? 'The connection was refused, so rotation is a precaution.' : 'The connection went through; rotate now.'}`, severity: verdict === 'true_positive_active' ? 'critical' : 'high', alert_id: alertId }, 'A secret was read: a human should rotate it.');

  const summary = aiOut.length
    ? `${a.title} on ${device}: data went to ${aiOut.map((n) => n.provider).join(', ')} (${aiOut.map((n) => n.name).join(', ')}), not an approved AI service${secrets.length ? ', after a secret was read' : ''}. The owner should move to an approved provider or ask for a review.`
    : verdict === 'true_positive_contained'
    ? `${a.title} on ${device}. Ring Zero Security refused the outbound step, so nothing left the endpoint; a ticket was opened to rotate the secret as a precaution.`
    : verdict === 'true_positive_active'
      ? `${a.title} on ${device}, and the outbound step went through. The host was blocked${fleetWide.size ? ' fleet-wide' : ''} and the session contained.`
      : `${a.title} on ${device}. The path has no egress or secret, so it needs a human look.`;
  await call('submit_verdict', { device, alert_id: alertId, verdict, confidence: verdict === 'needs_human' ? 0.5 : 0.85, summary, evidence }, 'Record the verdict and the evidence on the alert.');
}
