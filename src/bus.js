// bus.js — NATS JetStream in front of the graph.
//
// Producers (the RZS adapter, the simulator, any HTTP client of POST
// /api/events) publish; a durable pull consumer drains the stream in batches
// and writes to FalkorDB. The HTTP request returns as soon as JetStream has
// stored the message, so a burst of events never waits on graph writes, and
// nothing is lost if the writer or FalkorDB restarts: unacked messages are
// redelivered.
//
//   NATS_URL=nats://localhost:4222   enable the bus (unset = write directly)
//   NATS_BATCH=200                   messages per fetch / graph write
//
// Subjects (one stream, RZS):
//   rzs.events.<device>   one agent event per message, Nats-Msg-Id = event id
//   rzs.mcp.<device>      one MCP inventory snapshot (array) per message
//   rzs.notes.<device>    one array of commentary lines per message
//   rzs.actions.<device>  response actions for the endpoint daemon (block, contain)
//
// Other consumers (CEF forwarders, archive, detection workers) can attach
// their own durable consumer to the same stream without touching this one.

import { connect, StringCodec, AckPolicy, DeliverPolicy, RetentionPolicy, headers as natsHeaders } from 'nats';

const URL = process.env.NATS_URL || '';
const BATCH = Number(process.env.NATS_BATCH || 200);
const STREAM = 'RZS';
const DURABLE = 'graph-writer';
const sc = StringCodec();

let nc, js;
export const enabled = () => Boolean(js);

const token = (s) => String(s || 'unknown').replace(/[^A-Za-z0-9_-]/g, '_');

export async function start() {
  if (!URL) return false;
  nc = await connect({ servers: URL, name: 'agent-siem' });
  const jsm = await nc.jetstreamManager();
  const cfg = {
    name: STREAM, subjects: ['rzs.>'], retention: RetentionPolicy.Limits,
    max_age: 7 * 24 * 3600 * 1e9,          // keep a week for replay
    duplicate_window: 10 * 60 * 1e9,       // drop a resent event id within 10 min
  };
  try { await jsm.streams.info(STREAM); await jsm.streams.update(STREAM, cfg); } catch { await jsm.streams.add(cfg); }
  try { await jsm.consumers.info(STREAM, DURABLE); } catch {
    await jsm.consumers.add(STREAM, { durable_name: DURABLE, ack_policy: AckPolicy.Explicit, deliver_policy: DeliverPolicy.All, ack_wait: 60e9, max_ack_pending: BATCH * 10 });
  }
  js = nc.jetstream();
  console.log(`bus: NATS JetStream ${URL} stream=${STREAM} consumer=${DURABLE} batch=${BATCH}`);
  return true;
}

// Publish events one message each, so JetStream can dedupe on event id.
export async function publishEvents(events) {
  await Promise.all(events.map((ev) => {
    const h = natsHeaders();
    if (ev.id) h.set('Nats-Msg-Id', `${ev.device}:${ev.id}`);
    return js.publish(`rzs.events.${token(ev.device)}`, sc.encode(JSON.stringify(ev)), { headers: h });
  }));
}
export async function publishArray(kind, items) {
  const byDevice = new Map();
  for (const it of items) { const d = token(it.device); if (!byDevice.has(d)) byDevice.set(d, []); byDevice.get(d).push(it); }
  for (const [d, arr] of byDevice) await js.publish(`rzs.${kind}.${d}`, sc.encode(JSON.stringify(arr)));
}

// Response actions decided in the SIEM (block a host, contain a session),
// for the endpoint daemon to subscribe to.
export async function publishAction(device, action) {
  await js.publish(`rzs.actions.${token(device)}`, sc.encode(JSON.stringify(action)));
}

// Drain the stream forever: fetch up to BATCH messages, group them by kind,
// write each group in one call, then ack. A failed write naks the batch so
// JetStream redelivers it after a short delay.
export async function consume({ onEvents, onMcp, onNotes, onSkills }) {
  const c = await js.consumers.get(STREAM, DURABLE);
  for (;;) {
    let msgs = [];
    try {
      const it = await c.fetch({ max_messages: BATCH, expires: 1000 });
      for await (const m of it) msgs.push(m);
    } catch (e) { console.error('bus fetch', e.message); await new Promise((r) => setTimeout(r, 1000)); continue; }
    if (!msgs.length) continue;
    const events = [], mcp = [], notes = [], skills = [];
    for (const m of msgs) {
      const body = JSON.parse(sc.decode(m.data));
      if (m.subject.startsWith('rzs.events.')) events.push(body);
      else if (m.subject.startsWith('rzs.mcp.')) mcp.push(...body);
      else if (m.subject.startsWith('rzs.notes.')) notes.push(...body);
      else if (m.subject.startsWith('rzs.skills.')) skills.push(...body);
    }
    try {
      if (events.length) await onEvents(events);
      if (mcp.length) await onMcp(mcp);
      if (notes.length) await onNotes(notes);
      if (skills.length && onSkills) await onSkills(skills);
      for (const m of msgs) m.ack();
    } catch (e) {
      console.error('bus write', e.message);
      for (const m of msgs) m.nak(2000);
    }
  }
}

export async function stats() {
  if (!nc) return null;
  const jsm = await nc.jetstreamManager();
  const s = await jsm.streams.info(STREAM); const c = await jsm.consumers.info(STREAM, DURABLE);
  return { messages: s.state.messages, bytes: s.state.bytes, pending: c.num_pending, ackPending: c.num_ack_pending, delivered: c.delivered.stream_seq };
}

export async function stop() { if (nc) await nc.drain(); }
