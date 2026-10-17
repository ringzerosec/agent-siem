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
(:McpServer {name, device, agent, transport, url, held, approved})
(:Package {name, ecosystem, version, vuln_count, worst})
(:Vulnerability {id, severity, summary})          from OSV
(:Prompt  {ts, text, provider, model, tool_call, flagged})   redacted
(:Note    {seq, ts, level, kind, text})            the daemon's narrative
(:Tamper  {what})

(Device)-[:DECLARES]->(McpServer)-[:PROVIDES]->(McpTool)
(Process)-[:INSTALLED]->(Package)-[:HAS_VULN]->(Vulnerability)
(Process)-[:PROMPTED]->(Prompt)
(Process)-[:RESOLVED {ts}]->(Host)                  DNS
(Process)-[:SENT {ts, allowed, reason}]->(Host)
(Process)-[:TAMPERED]->(Tamper)
(Session)-[:NOTED]->(Note)
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

| Rule | Threat | Severity | Pattern |
|---|---|---|---|
| secret-to-egress | T2 | critical | sensitive file read → (same process tree, ≤4 spawns) → connect to unapproved host, later |
| secret-to-write-to-egress | T5 | critical | sensitive read → write to a non-sensitive file → tree connects out |
| tamper | T8 | critical | ptrace / signal / mount attempt on a contained process or the daemon |
| vulnerable-package | T3 | high | installed package has OSV advisories |
| mcp-unapproved-server | T3 | high | tool call to an MCP server not on the approved list, or held by the daemon |
| privilege-tool | T4 | high | `sudo`, `su`, `pkexec`, `doas`, `run0`, `systemd-run`, `at`, `crontab` executed |
| instruction-file-write | T1 | high | agent rewrote `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `SKILL.md`… |
| flagged-prompt | T1 | high | the daemon flagged a prompt (injection / offensive) |
| dns-tunnel-shape | T5 | high | DNS name with a label ≥30 chars or total ≥60 chars |
| bulk-read-then-egress | T5 | high | ≥25 distinct files read, then the tree connects to an unapproved host |
| write-then-exec | T8 | medium | a file the agent wrote was then executed by its tree |
| refused-egress | T5 | medium | proxy or policy refused an outbound connection or send |
| package-install | T3 | medium | `pip`, `npm`, `cargo`, `apt`… executed |

Rules only add alerts. Edges carry `allowed` so a refused action (dashed amber)
is distinguishable from one that went through.

## Real data: point it at installed Ring Zero Security daemons

Every machine with the Ring Zero Security daemon installed is a device on the
wall. The adapter polls each daemon's read-only API (sessions, their events,
the narrative commentary, the MCP inventory) and feeds the graph:

```bash
RZS="priya-laptop=http://10.0.0.12:7700,build-vm=http://10.0.0.5:7700" \
RZS_TOKEN="$(cat /var/lib/ringzero/api-token-readonly)" \
node src/adapter-rzs.js
```

Kernel events (file opens, execs, connects, DNS), proxy events (LLM requests,
DLP refusals) and tamper events map onto the graph; the daemon's session ids
become the sessions you see. Prompts and narrative lines pass through a secret
redactor before they are stored. The `simulator` is only for a demo without
daemons.

## Threat model

Every alert carries the category from the Ring Zero Security AI-agent threat
model, so the wall speaks the same language as the runbooks:

| Code | Threat | Rules |
|---|---|---|
| T1 | Prompt injection | instruction-file rewrite, flagged prompt |
| T2 | Credential exfiltration | secret read → egress (multi-hop) |
| T3 | Supply chain compromise | package with OSV advisories, unapproved or held MCP server |
| T4 | Privilege escalation | sudo / su / pkexec / doas / run0 / systemd-run / at / crontab |
| T5 | Data exfiltration | secret → write → egress, bulk read → egress, DNS-tunnel-shaped lookups, proxy refusals |
| T8 | C2 / persistence | write-then-execute, tamper attempts on the daemon |

T6 (intent vs behaviour), T7 (baseline anomaly) and T9 (framework CVEs) need
the daemon's intent and baseline engines and are not in this release.

## Packages: Google OSV

When an agent's tree runs `npm install`, `pip install`, `cargo add`, `uv`,
`gem` or `apt`, the package names and versions are parsed and checked against
[Google's OSV database](https://osv.dev) (`querybatch`, then per-advisory
details, cached an hour). Packages become `(:Package)` nodes with
`(:Vulnerability)` neighbours; a package with advisories raises a T3 alert and
shows red on the graph.

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
| `POST /api/mcp-servers` | MCP servers from a daemon's inventory |
| `POST /api/notes` | narrative lines for a session |
| `GET /api/feed/:device` | prompts + narrative for a device, in time order |
| `GET /api/threats` | the threat-model catalogue |
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
