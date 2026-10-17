// Graph data model and the queries the dashboard depends on.
// Run against FalkorDB (GRAPH.QUERY agentwatch "...").

// ---------- Model ----------
// (:Device {id, owner, first_ts})
// (:Session {id, agent, started, device})
// (Device)-[:RUNS]->(Session)
// (:Agent {name})
// (:Process {key, pid, name, first_ts, session})
// (:File {path, sensitive, instruction, program?, privileged?, installer?})
// (:Host {name, approved})
// (:McpTool {name, server})
// (Session)-[:RAN_BY]->(Agent)
// (Session)-[:HAS]->(Process)
// (Process)-[:SPAWNED]->(Process)
// (Process)-[:READ|WROTE|EXECUTED {ts, event, allowed}]->(File)
// (Process)-[:CONNECTED {ts, event, allowed, port}]->(Host)
// (Process)-[:USED_TOOL {ts, event, allowed}]->(McpTool)

// ---------- The wall: every device with its sessions, processes and actions ----------
MATCH (d:Device)
OPTIONAL MATCH (d)-[:RUNS]->(s:Session)
OPTIONAL MATCH (s)-[:HAS]->(p:Process)
OPTIONAL MATCH (p)-[e]->()
RETURN d.id, d.owner, count(DISTINCT s), count(DISTINCT p), count(e), max(e.ts), collect(DISTINCT s.agent);

// ---------- One device's whole graph ----------
MATCH (d:Device {id: $id})-[:RUNS]->(s:Session)-[:HAS]->(p:Process)
OPTIONAL MATCH (p)-[e]->(m) WHERE NOT m:Session
RETURN s, p, e, m;

// ---------- Live session list with alert counts ----------
MATCH (s:Session)
OPTIONAL MATCH (s)-[:HAS]->(p:Process)
WITH s, count(p) AS procs
RETURN s.id, s.agent, s.started, procs ORDER BY s.started DESC;

// ---------- One session's whole graph ----------
MATCH (s:Session {id: $session})-[:HAS]->(p:Process)
OPTIONAL MATCH (p)-[e]->(m)
WHERE NOT m:Session
RETURN p, e, m;

// ---------- Rule: secret read, then egress to an unapproved host (multi-hop) ----------
MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
WHERE h.approved = false AND cn.ts >= rd.ts
RETURN f, h, r, c, nodes(path), relationships(path);

// ---------- Rule: secret read, encoded into a file, then that tree connected out ----------
MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
MATCH (r)-[wr:WROTE]->(out:File)
WHERE wr.ts >= rd.ts AND out.sensitive = false
MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
WHERE cn.ts >= wr.ts AND h.approved = false
RETURN f, out, h, r, c, nodes(path), relationships(path);

// ---------- Rule: privilege / scheduling tool executed ----------
MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[ex:EXECUTED]->(f:File {privileged: true})
RETURN p, f, ex;

// ---------- Rule: instruction file rewritten ----------
MATCH (s:Session {id: $session})-[:HAS]->(p:Process)-[wr:WROTE]->(f:File {instruction: true})
RETURN p, f, wr;

// ---------- Rule: wrote a file then executed it ----------
MATCH (s:Session {id: $session})-[:HAS]->(w:Process)-[wr:WROTE]->(f:File)
MATCH path = (w)-[:SPAWNED*0..3]->(x:Process)-[ex:EXECUTED]->(f)
WHERE ex.ts >= wr.ts
RETURN w, x, f, nodes(path), relationships(path);

// ---------- Blast radius of a node (2 hops, any direction) ----------
MATCH (n) WHERE ID(n) = $id
MATCH path = (n)-[*1..2]-(m)
WHERE NOT m:Session AND NOT m:Agent
RETURN nodes(path), relationships(path) LIMIT 500;

// ---------- Timeline of one process ----------
MATCH (p:Process {key: $key})-[e]->(m)
RETURN type(e) AS action, e.ts AS ts, e.allowed AS allowed, m ORDER BY e.ts;
