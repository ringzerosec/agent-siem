// db.js — one FalkorDB connection, one graph per deployment.
//
// Every session, process, file, host and MCP tool is a node; every action an
// agent took is an edge. The dashboard never computes anything in JS that the
// graph can answer in Cypher: detection, blast radius and timelines are all
// queries (see cypher/queries.cypher).

import { FalkorDB } from 'falkordb';

const HOST = process.env.FALKORDB_HOST || 'localhost';
const PORT = Number(process.env.FALKORDB_PORT || 6379);
const GRAPH = process.env.FALKORDB_GRAPH || 'agentwatch';

let db, dbRead, dbDetect;
let graph, graphRead, graphDetect;

// Three connections: graph writes, alert-rule queries and dashboard reads
// each get their own, so a slow rule never stalls ingest or a page load.
export async function connect() {
  if (graph) return graph;
  db = await FalkorDB.connect({ host: HOST, port: PORT });
  dbRead = await FalkorDB.connect({ host: HOST, port: PORT });
  dbDetect = await FalkorDB.connect({ host: HOST, port: PORT });
  graphDetect = dbDetect.selectGraph(GRAPH);
  graph = db.selectGraph(GRAPH);
  graphRead = dbRead.selectGraph(GRAPH);
  await ensureIndexes();
  return graph;
}

export function g() {
  if (!graph) throw new Error('db not connected');
  return graph;
}
export function gd() {
  if (!graphDetect) throw new Error('db not connected');
  return graphDetect;
}
export function gr() {
  if (!graphRead) throw new Error('db not connected');
  return graphRead;
}

// Indexes make the MERGE-heavy ingest and the per-session queries cheap.
async function ensureIndexes() {
  const stmts = [
    'CREATE INDEX FOR (s:Session) ON (s.id)',
    'CREATE INDEX FOR (p:Process) ON (p.key)',
    'CREATE INDEX FOR (f:File) ON (f.path)',
    'CREATE INDEX FOR (h:Host) ON (h.name)',
    'CREATE INDEX FOR (t:McpTool) ON (t.name)',
    'CREATE INDEX FOR (a:Agent) ON (a.name)',
    'CREATE INDEX FOR (d:Device) ON (d.id)',
    'CREATE INDEX FOR (m:McpServer) ON (m.name)',
  ];
  for (const s of stmts) {
    try { await graph.query(s); } catch (e) { if (!/already indexed/i.test(e.message)) throw e; }
  }
}

export async function wipe() {
  await graph.query('MATCH (n) DETACH DELETE n');
}

export async function close() {
  if (db) await db.close();
  if (dbRead) await dbRead.close();
  if (dbDetect) await dbDetect.close();
  db = dbRead = dbDetect = undefined; graph = graphRead = graphDetect = undefined;
}
