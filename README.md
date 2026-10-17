# Agent Watch

A live security wall for AI coding agents across a fleet. Every employee device
is a tile showing its own live provenance graph. Every action an agent takes on
that device (process spawned, file read or written, program executed, network
connection, MCP tool call) becomes an edge in a **provenance graph in
FalkorDB**. Alert rules are Cypher path queries. When a path matches, the tile
turns red; click it to open the device's full graph with the alert path painted
red, then click any node for its timeline and blast radius. Nodes are icons:
agent, process, file, secret, host, unapproved host, MCP tool.

Built for the WeMakeDevs × FalkorDB "Graph Hacks: Context for AI Agents"
hackathon, Track 01 (Agents That Act on Connected Data: security triage).

## Why a graph

The attacks that matter are multi-step. One event ("python opened `.env`") is
noise. Three events, minutes apart, across a process tree ("agent read `.env`,
wrote `docs/diagram.md`, a child `curl` connected to pastebin.com") is an
exfiltration. Finding that is a path query:

```cypher
MATCH (s:Session {id: $session})-[:HAS]->(r:Process)-[rd:READ]->(f:File {sensitive: true})
MATCH (r)-[wr:WROTE]->(out:File) WHERE wr.ts >= rd.ts
MATCH path = (r)-[:SPAWNED*0..4]->(c:Process)-[cn:CONNECTED]->(h:Host)
WHERE cn.ts >= wr.ts AND h.approved = false
RETURN f, out, h, nodes(path), relationships(path)
```

FalkorDB is not a cache here; it is the detection engine. Remove it and there
is no product. All queries are in [`cypher/queries.cypher`](cypher/queries.cypher).

## Graph data model

```
(:Device  {id, owner, first_ts})          one employee machine (or one benchmark VM)
(:Session {id, agent, started, device})
(Device)-[:RUNS]->(Session)
(:Agent   {name})
(:Process {key, pid, name, first_ts, session})
(:File    {path, sensitive, instruction, program?, privileged?, installer?})
(:Host    {name, approved})
(:McpTool {name, server})

(Session)-[:RAN_BY]->(Agent)
(Session)-[:HAS]->(Process)
(Process)-[:SPAWNED]->(Process)
(Process)-[:READ | WROTE | EXECUTED {ts, event, allowed}]->(File)
(Process)-[:CONNECTED {ts, event, allowed, port}]->(Host)
(Process)-[:USED_TOOL {ts, event, allowed}]->(McpTool)
```

`sensitive`, `instruction`, `privileged`, `installer` and `approved` are set at
ingest from path and host rules (`src/ingest.js`); everything else is a query.

## Alert rules (all Cypher, `src/detect.js`)

| Rule | Severity | Pattern |
|---|---|---|
| secret-to-egress | critical | sensitive file read → (same process tree, ≤4 spawns) → connect to unapproved host, later |
| secret-to-write-to-egress | critical | sensitive read → write to a non-sensitive file → tree connects out |
| privilege-tool | high | `sudo`, `su`, `pkexec`, `doas`, `run0`, `systemd-run`, `at`, `crontab` executed |
| instruction-file-write | high | agent rewrote `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `SKILL.md`… |
| write-then-exec | medium | a file the agent wrote was then executed by its tree |
| package-install | medium | `pip`, `npm`, `cargo`, `apt`… executed |

Rules only add alerts. Edges carry `allowed` so a refused action (dashed amber)
is distinguishable from one that went through.

## Run it

```bash
docker compose up --build
# dashboard: http://localhost:8080   FalkorDB browser: http://localhost:3000
```

The `simulator` service plays a fleet of 12 employee devices, each running one
or two agent sessions doing ordinary development work; about a quarter of the
sessions drift into the read-secret → write → connect-out chain. Watch their
tiles turn red. `SIM_DEVICES=40 SIM_RATE_MS=150` for a bigger wall.

Without compose:

```bash
docker run -d -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest
npm install
npm start            # http://localhost:8080
npm run sim          # in another terminal
```

## Feed it real events

`POST /api/events` takes a JSON array:

```json
{"id":"e1","ts":1760000000000,"device":"priya-laptop","owner":"priya","session":"priya-laptop-s1","agent":"claude-code",
 "kind":"read","pid":4242,"ppid":4000,"process":"python3","parent_process":"claude-code",
 "target":"/home/dev/app/.env","allowed":true}
```

`device` and `owner` identify the machine (a tile on the wall); `session` the
agent run on it. `kind` is one of `read`, `write`, `exec`, `connect` (`target` = `host:port`),
`tool` (`target` = `server/tool`), `spawn`. The shape mirrors the public event
record of the Ring Zero Security Linux daemon, so an export of its
`/api/v1/events` drops in unchanged. Set `APPROVED_HOSTS` (comma-separated) to
your allowlist.

## API

| Route | What |
|---|---|
| `POST /api/events` | ingest; triggers detection and a live update |
| `GET /api/devices` | every device with alert counts (the wall) |
| `GET /api/graph/device/:id` | nodes, edges and alerts for one device |
| `GET /api/sessions` | every session with alert counts |
| `GET /api/graph/:session` | nodes, edges and alerts for one session |
| `GET /api/node/:id?hops=2` | node properties, timeline, blast radius |
| `GET /api/alerts` | all alerts across sessions |
| `GET /api/stream` | server-sent events, one message per ingest |
| `POST /api/reset` | wipe the graph |

## Also a benchmark monitor

The same wall works for containment benchmarks: run N attacker agents in N
disposable VMs, point each VM's event export at `POST /api/events` with the VM
id as `device`, and the wall shows which VMs an attack path reached and which
were contained. Every red path is reproducible from the graph: the nodes and
edges on it are the evidence.

## Stack

Node 24, Express 5, `falkordb` 6.8 (the official Node client), vis-network for
the canvas. No build step. Apache-2.0.

## Built with

Claude Code wrote most of the code from a design discussion with the author; the
graph model, rules and architecture are the author's, and everything here has
been run and verified locally. Disclosed per the hackathon rules.
