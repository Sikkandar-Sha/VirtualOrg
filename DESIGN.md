# VirtualOrg — Design Brief

A synthetic enterprise for testing a risk-posture product. One world-state in one
database; every tool the product connects to is a lens over it, deliberately
imperfect in the way real tools are.

**Status:** design only, no code. **Target host:** Docker on ARM64, laptop-class.
**Scope:** read-only API consumption.

The kit under test consumes SIEM, incident management, GRC and audit systems over
their APIs, and produces residual risk per business service, control effectiveness
by framework, a board-level posture score with drivers, and top-N risks with
evidence trails. It writes nothing back. VirtualOrg gives it an enterprise to read,
and knows in advance what it *should* conclude.

**What this is not:** not a cyber range, not a collection of real security products,
not a log-generation pipeline. See #11 for what was cut and why.

---

## 1. One world, many lenses

An enterprise is not its tools. Every enterprise tool is a partial, lossy,
opinionated view of one underlying organisation.

The world is modelled once, completely and truthfully, in a single database. Every
tool is a **lens** with three properties:

- **Scope** — which slice of the world it can see
- **Loss profile** — how incomplete, stale and differently-named its view is
- **Shape** — its API surface, schema and auth

Adding a tool means writing a lens. Changing the entire tool list means rewriting
lenses — days each — and never touching the world. This is the decision that keeps
the tool list out of the architecture.

Loss is applied at the lens, never stored in the world. Two lenses onto the same
world with different loss profiles is what manufactures the correlation, conflict
and coverage-gap problems the kit exists to solve.

> A VirtualOrg whose lenses are faithful and complete is a database with extra
> steps. The loss profiles *are* the test.

---

## 2. Architecture

Five containers, one `docker compose up`, ~4 GB, boots in seconds, snapshot-restores
in under a second, native ARM64.

| Container | Responsibility |
|---|---|
| `world-db` | Postgres. *The* world — people, assets, apps, services, vendors, controls, evidence, findings, incidents, risks and their relationships, across three years of history. |
| `world-engine` | Owns state. Seeds and pre-ages the world, runs the logical clock, executes scenario files, applies the chaos dial, injects conflicts. Writes; never serves the kit. |
| `twin-gateway` | One process wearing N vendor faces, routed by hostname. Every response is a projection over `world-db` through a lens. Stateless, always well-behaved. |
| `wiremock` | Adversarial behaviour only — 429s, expired tokens, schema drift, truncated pages, timeouts, a source unreachable for three days. |
| `keycloak` | Real OAuth. Genuine token expiry, refresh, JWKS rotation. |
| `control-center` | Browsable specification of the enterprise (#8). Strictly read-only. |

### What runs where

**The kit stays out of the compose file by default.** Developers need a debugger
attached to it; a rebuild cycle between edits is small per iteration and enormous over
a quarter. VirtualOrg is containerised always, the kit only in CI.

```bash
docker compose up -d                   # dev: VirtualOrg only
docker compose --profile ci up -d      # CI: adds the kit in-network
docker compose --profile chaos up -d   # adds WireMock in front of a twin
```

Which means the kit's `base_url` differs by where it runs —
`http://localhost:8080/servicenow` from an IDE, `http://twin-gateway:8080/servicenow`
from inside the network. Two config files, no code change. This is the practical
reason #6 exists.

Route by **path prefix** (`/servicenow`, `/splunk`, `/grc`), not per-vendor hostnames.
Hostnames like `https://servicenow.virtual-org.test` demo better but need an
`/etc/hosts` entry on every machine and a local CA for TLS. Add them later as
cosmetics; don't pay for them on day one.

### Reset is a restore, not a regeneration

Generating three years of causally coherent history is the slowest thing in the loop.
Doing it on every reset will quietly become the bottleneck. Seed once, then snapshot:

```bash
./scripts/seed baseline      # schema + generate + snapshot
./scripts/reset baseline     # sub-second
./scripts/snapshot my-case   # freeze a variant
```

One dump per scenario baseline. That is what makes the pure-function property in #7
usable in practice — restore `W₁`, run the kit, assert `P₁`, move on.

**The twin / WireMock split:** twins are dynamic, database-backed and always behave
well. WireMock is static, scripted and behaves badly. Keep them separate — the moment
the twin gateway carries `if (chaos) throw 429` it becomes unmaintainable and you stop
trusting its happy path.

---

## 3. The world model

Broad but shallow: ~30–40 tables plus an event timeline.

### Domains

Not all built at once, but the schema reserves space for all — retrofitting a domain
later means backfilling three years of history for it.

| Domain | Day one |
|---|---|
| People & org — employees, contractors, roles, reporting lines, JML over time | Yes |
| Identity & access — accounts, groups, entitlements, privileged access, service accounts | Thin |
| Assets & infrastructure — endpoints, servers, cloud, lifecycle, software inventory | Yes |
| Applications & services — apps, business services, criticality, dependency graph, owners | Yes |
| Business processes — the process → service → app → asset chain | Thin |
| Third parties — vendors, contracts, SLAs, criticality, assessments | Later |
| Data — stores, classification, residency, retention | Later |
| Change — deployments, change requests, approvals, emergency changes | Later |
| Security posture — vulns, misconfigs, detections, alerts, incidents, exposures | Yes |
| Governance — frameworks, requirements, controls, tests, policies, exceptions, audits, findings, risks, treatments | Yes |
| Operations — tickets, outages, availability, SLAs | Thin |
| Impact — loss events, control costs, financial materiality | Later |

### The spine

```
Framework → Requirement → Control → Evidence → Asset/App → Service → Process → Impact
                             ↑          ↑                      ↑
                        (mitigated) (from lenses)         (threatens)
                             └──────── Risk ───────────────────┘
```

All four outputs are traversals of this one graph:

| Output | Traversal |
|---|---|
| Control effectiveness by framework | Bottom-up: evidence → control → requirement, grouped |
| Residual risk per business service | Top-down: service → dependencies → threats → controls → residual |
| Top-N risks with evidence trails | Risk → controls → evidence → source records |
| Board posture score with drivers | Roll-up of the above, plus attribution back down |

Build the spine and the outputs fall out. Build four features and you get four
disagreeing numbers within a quarter — fatal for a single-source-of-truth product.

Control and evidence are the load-bearing join. **Nothing in the source data links a
SIEM detection to a GRC control** — that attribution is the kit's job, and the thing
most likely to be wrong in a way nobody notices.

### Day-one slice

- 1 framework with real requirement text (ISO 27001 or NIST CSF, ~100 requirements)
- ~100 controls, mapped to requirements **with coverage strength**
- 5–8 business services with dependency graphs
- ~25 applications, ~300 assets, ~500 people
- ~40 risks in a register
- 3 years of control tests, audit findings, incidents and evidence

A few hundred thousand rows. Weeks, not quarters.

---

## 4. Data model decisions

Four decisions that are cheap now and expensive in a year.

### 4.1 Facts are claims, not truths

The kit only ever *receives* — it never observes. So nothing it handles is a fact.
It is a claim: **asserted by source S, at time T, with confidence C, superseding or
conflicting with prior claims.** The canonical entity is a reconciliation over
claims, not a record.

Four payoffs from one shape:

- **Entity resolution** — the core problem, given only other people's identifiers
- **Staleness** — a claim from a stale agent is old, not wrong, and the kit can say so
- **Conflict** — disagreement becomes a surfaceable finding, not a silent coin-flip
- **Future scanning** — first-party scanning becomes a new source type with higher
  confidence. Additive. Model facts as truth instead and that addition is a rewrite
  of reconciliation.

### 4.2 Control mappings carry coverage strength

Not a boolean many-to-many. Control `C-12` may *fully* satisfy CSF PR.AC-1 and only
*partially* satisfy ISO A.9.2.3 — so when C-12 fails, ISO moves 3% and SOC 2 moves 11%.
Without mapping strength you can compute those numbers but never explain them, which
puts you back in the lineage problem in front of an auditor.

### 4.3 The world boots pre-aged

Risk posture is a time series. A control tested eleven months ago is nearly stale; a
finding overdue by 200 days differs qualitatively from one overdue by five; audit
cycles are annual, risk reviews quarterly, effectiveness is a trend not a state.

An org born when the container started has no trend, no cycle, no aging, no velocity —
every posture feature untestable and undemoable. So seed **two to three years of
causally coherent history** at boot, spanning multiple audit cycles: controls that
drifted effective → ineffective → back, findings remediated late, a risk that
materialised into an incident and was then treated.

Trivial as rows in a database. Impossible any other way. Strongest single argument
for the projection model.

### 4.4 The chaos dial

A clean synthetic enterprise is the least useful test environment available, and it is
the default thing everyone builds.

| Level | World | Used for |
|---|---|---|
| 0 | Pristine — consistent identifiers, complete coverage, current data | Baseline regression |
| 1 | Realistic entropy — recycled IPs, three names per asset, 20% stale CMDB entries, departed owners, agent gaps | Primary regression |
| 2 | Pathological — duplicate IDs across vendors, unicode, timezone-naive timestamps, malformed payloads, ID collisions | Fuzzing |

The dial lives in the lens loss profiles, not the world. The world is always true.

---

## 5. Lens specification

A lens is a scope query, a loss profile, and a response template. Days each — which
is what makes the tool list disposable.

### Loss profile fields

| Field | Meaning | Example |
|---|---|---|
| `coverage` | Share of in-scope entities it knows about, and which | 87% of endpoints; no cloud workloads |
| `latency` | How stale the view is | Nightly sync — up to 24h behind |
| `identifier` | How it names things | IP (recycled), FQDN, asset tag, UUID |
| `vocabulary` | Severity scale, status enum, category taxonomy | 1–5 vs Critical/High/Med vs P1–P4 |
| `retention` | How far back it goes | 90 days rolling |
| `blind_spot` | What it structurally never sees | Assets procured outside IT |

### Vendor pack × customer profile

In this tool category the schema is not defined by the vendor — it is defined by the
customer. ServiceNow instances carry custom fields, renamed states and local choice
values; GRC platforms are configured object models, not fixed schemas. This is the
number one reason an integration that works at customer A breaks at customer B.

Each vendor pack ships with profiles:

- `out-of-the-box` — vanilla install, vendor defaults
- `lightly-customized` — a few custom fields, renamed statuses
- `heavily-customized` — custom objects, non-standard state machines, mandatory
  fields the vendor never shipped, a home-grown control taxonomy

**Passing all three means the connector is deployable. Passing only `out-of-the-box`
means it demos.** Cheap if the twin reads a profile config; impossible to retrofit
across thirty twins.

### Connector patterns to cover

Build for patterns, not brands.

- **Async query job** — submit, poll, fetch. Splunk-style search jobs, log-analytics
  queries. Job lifecycle, partial results, expiry, truncation, quota. Likeliest place
  to be subtly wrong, and absent from most connector checklists.
- **Generic table / record API** — one shape, N object types, customer-defined fields
- **REST with cursor pagination** and **REST with offset pagination**
- **OAuth client credentials with refresh** vs **static API key**
- **Incremental polling** — `since` / `updated_at` / checkpoints, including
  late-arriving and backdated records
- **Framework / taxonomy sync** — control libraries and crosswalks
- **Binary evidence retrieval** — audit attachments, separate auth, size limits

### ⚠ The standing hazard

With no real vendor product in the loop, all correctness confidence rests on twin
fidelity. Nothing in the environment can tell you you've misread a vendor's
pagination — connector and twin will be wrong together, forever, in green CI.

Mitigation is process, from commit one: every twin carries a **provenance manifest** —
where each response shape came from (vendor OpenAPI spec / published doc example /
captured sandbox response), the capture date, and the vendor API version it reflects.
Twins built from imagination are marked `unverified` and their passing tests do not
count as certification.

---

## 6. The connector contract

Section #5 specifies VirtualOrg's side of the boundary. This is the kit's side. VirtualOrg is
only usable if the kit can be aimed at it **without editing the kit** — otherwise the
test environment needs a patched build, and you are testing code that isn't what ships.

### One config object per connector instance

Per instance, not per connector *type* — a customer may run two ServiceNow instances,
or a production and a DR SIEM.

```yaml
# config/production/connectors.yaml
connectors:
  - id: snow-primary
    type: servicenow
    enabled: true
    mode: real                # real | sandbox | simulated

    endpoint:
      base_url: https://acme.service-now.com
      api_version: v2
      timeout_ms: 30000
      tls:
        verify: true
        ca_bundle: null       # customers proxy through their own CA

    auth:
      type: oauth_client_credentials
      token_url: https://acme.service-now.com/oauth_token.do
      client_id: ${SNOW_CLIENT_ID}
      client_secret: ${SNOW_CLIENT_SECRET}

    sync:
      poll_interval: 15m
      initial_lookback: 90d
      page_size: 200
      cursor_field: sys_updated_on

    limits:
      max_rps: 5
      retry: { attempts: 5, backoff: exponential, respect_retry_after: true }

    schema_profile: acme-customized
    scope:
      tables: [incident, sn_risk_risk, sn_compliance_control]
```

Secrets arrive by `${ENV_VAR}` interpolation only — never as literals in the file.

### Four things that must be config

Making `base_url` configurable is necessary and not sufficient.

| Field | Why it has to move |
|---|---|
| `endpoint.base_url` | The obvious one. Usually already config, because every customer's instance sits at a different address. |
| `auth.token_url` | **The one that actually bites.** Frequently hardcoded even when the API base isn't — which leaves token refresh and expiry, the fiddliest part of most connectors, untestable. |
| `endpoint.tls` | A connector that hard-refuses `http://` or self-signed certs can't reach a local twin — or a customer behind their own TLS-terminating proxy. |
| `schema_profile` | Customer-specific field names, renamed statuses and local choice values belong in a data file, not the parser. This is what makes #5's three customer profiles testable. |

```yaml
# profiles/acme-customized.yaml
servicenow.incident:
  id: number
  opened: opened_at
  severity: u_business_severity        # custom field
  status:
    field: state
    values: { "1": new, "2": in_progress, "6": resolved, "9": u_deferred }
```

### The environment switch is three files, not a feature

Same binary, different config directory, selected with `--config`.

```yaml
# config/virtualorg/connectors.yaml
connectors:
  - id: snow-primary
    type: servicenow
    mode: simulated
    endpoint:
      base_url: http://twin-gateway:8080/servicenow
      tls: { verify: false }
    auth:
      type: oauth_client_credentials
      token_url: http://keycloak:8080/realms/virtualorg/protocol/openid-connect/token
      client_id: ${VO_CLIENT_ID}
      client_secret: ${VO_CLIENT_SECRET}
    schema_profile: heavily-customized
```

Three directories — `config/production`, `config/sandbox`, `config/virtualorg` — and
`mode: simulated | sandbox | real` stops being something you build.

### The test that keeps it true

Config discipline decays silently, so it gets enforced rather than agreed. A runtime
interceptor rather than a source grep, because it also catches URLs assembled at runtime.

```python
def test_no_connector_reaches_an_unconfigured_host():
    cfg = load("config/virtualorg/connectors.yaml")
    allowed = hosts_declared_in(cfg)

    with block_http_except(allowed) as guard:
        for c in build_all_connectors(cfg):
            c.authenticate()
            c.fetch_page()

    assert guard.blocked == [], f"escaped to: {guard.blocked}"
```

It fails the day someone adds a hardcoded endpoint, and it keeps failing. Cheap
insurance on the one property everything else in this brief depends on.

### Mode flows through to the output

A posture computed from simulated sources is **labelled** simulated, all the way to the
report. Costs nothing, and prevents the failure that eventually happens to everyone: a
screenshot of simulated numbers in front of someone who thinks they are real.

> **This is a product requirement, not a test accommodation.** Self-hosted instances sit
> on customer domains — Splunk Enterprise is not Splunk Cloud, self-hosted Jira is not
> `atlassian.net`. Sovereign and regional clouds have different hostnames entirely. Some
> customers route everything through their own gateway. VirtualOrg just surfaces the
> requirement early, while the refactor is still cheap.

---

## 7. Assertion catalogue

Because the kit writes nothing back, the system is a pure function:
world-state → vendor responses → posture. Snapshot world `W₁`, record posture `P₁`;
any change in posture without a change in world is a regression.

### Four families

| Family | Question | Manufactured by |
|---|---|---|
| **Attribution** | Is this event genuine evidence for this control? Precision and recall, with deliberate near-miss traps. | Ground-truth evidence links |
| **Conflict** | Sources disagree. Resolve with a defensible rule, or surface it? Either is valid — silently picking a winner is not. | `conflict:` block in scenario |
| **Degradation** | A source is stale or down. Does posture announce it, or serve last week's numbers as current? | WireMock in front of a twin |
| **Absence** | Controls with no evidence source, risks with no controls, services with no owner. For an SSOT, silence must be distinguishable from health. | Coverage gaps in loss profile |

### Conflict scenarios worth building first

- GRC rates a control effective; audit has a 140-day-overdue finding on it; the SIEM
  detection backing it hasn't fired in three months because it broke
- Audit closed a finding; the underlying condition is still visible in the SIEM
- An incident closed "no customer impact" that touched a tier-1 service
- The control owner of record left the company in March
- A risk marked "reviewed — current" whose last review timestamp is 14 months old

### Different outputs, different assertion styles

| Output | What matters | Assertion style |
|---|---|---|
| Control effectiveness by framework | Auditable — someone will check it against the GRC platform | Exact match |
| Top-N risks | Ordering, not values | Rank order + set membership |
| Residual risk per service | Defensible direction, not precision | Invariants, monotonicity |
| Board posture score | Movement, not level | Deltas: change X → direction Y within band Z |

Asserting absolute values on the board score is a trap — expected numbers get
rewritten every time a weight is tuned and the tests stop meaning anything.

### Lineage is the real assertion

"With drivers" and "with evidence trails" are the same requirement: **lineage that
survives aggregation.** A score of 68 must decompose into what made it 68 rather than
74, and each of those must decompose again to a specific detection or overdue finding —
through every layer of roll-up, weighting and normalisation.

So ground truth is not just *expected posture*, it is **expected lineage**. You can
produce the right number for the wrong reasons, and that is worse than a wrong number:
it survives scrutiny until a CRO drills into a driver, finds it doesn't hold up, and
stops trusting the tool.

**Testing the number is easy. Testing the explanation is the job.**

---

## 8. Control Center

Developers cannot write connectors against an enterprise they cannot see. Without
this, every engineer reverse-engineers the world by poking at Postgres and VirtualOrg
becomes tribal knowledge.

It is not an operator console. It is a **live specification** — every pixel generated
from `world-db` and the twins, nothing hand-maintained. A written README about the
virtual org will be wrong within a month and will then actively mislead. A UI reading
from the same world-state everything else projects from is documentation that
structurally cannot lie.

### Surfaces, in build order

1. **One entity, every lens.** Highest-value screen — build first.

   ```
   Asset AST-0088
   CMDB     lt4471.corp.local · owner Sarah Chen · last seen 14h ago   [stale]
   EDR      LT-4471 · agent healthy · 2 min ago
   Scanner  10.42.8.19 · last scanned 9 days ago
   HR       Sarah Chen — left the company 14 Mar 2026               [conflict]
   GRC      — not present in any control scope                           [gap]
   ─────────────────────────────────────────────────────────────────────────
   TRUTH    One machine. Three identifiers. One departed owner.
            Zero control coverage.
   ```

2. **The spine, visually.** Pick a service → dependency graph down to assets, controls
   covering it, risks attached. Pick a control → every piece of evidence from every lens.
3. **The lenses.** Per tool: base URL, auth, test credentials, pagination style,
   available customer profiles, loss profile in plain language, plus a **live try-it
   console** that executes against the real twin.
4. **The org.** Browsable inventory with counts, filters, drill-down.
5. **Ground truth vs actual.** Expected posture, top-N and lineage beside what the kit
   concluded.
6. **Scenario controls.** Run, reset, advance clock, chaos dial, kill a lens. Least
   important; nearly free once the rest exists.

### Two rules that keep it from eating the project

**Read-only over `world-db` and twin responses. Zero business logic.** If a number
appears in the UI it must be a query, never a computation. The moment the control
center calculates anything there are two implementations of "what is true about this
enterprise" and they will diverge — you'd have built the exact bug the product exists
to detect, inside the harness for detecting it.

**Build it after the world and the twins, generated from them.** Then it is mostly
free. Build it first and it becomes a beautiful interface over an enterprise that does
not exist yet, and it will absorb unlimited effort.

> It is also the demo: here is the enterprise → here is what the kit concluded → here
> is the evidence trail → and here are the 40 machines nobody was watching, which a GRC
> platform will never tell you about. Spend real design effort on surfaces 1 and 2,
> almost none on the rest.

---

## 9. Phasing

**Phase 0 — Model and catalogue.** Canonical entity model, claims schema, the spine,
ground-truth schema, assertion catalogue, written down. This is the actual product;
everything after is scaffolding. *Nothing runs yet.*

**Phase 1 — World and two lenses.** `world-db`, `world-engine`, day-one slice pre-aged
three years, `twin-gateway` with two vendors on two different connector patterns,
Keycloak, chaos dial at 0 and 1. The kit connects and produces a posture.
*Runs on the ARM laptop, ~4 GB.*

**Phase 2 — Adversarial layer and breadth.** WireMock failure modes, conflict and
degradation scenarios, customer profiles per vendor, remaining connector patterns,
chaos level 2. *All four assertion families live.*

**Phase 3 — Control Center.** Surfaces 1–3 first, generated from what exists. 4–6 as
they earn it. *Developer onboarding and demo surface.*

**Phase 4 — Certification against real vendors.** Small suite against vendor developer
tenants or one real instance — auth, permissions, pagination, rate limits, schema
comparison against recorded fixtures. Asserted loosely, run weekly, never per-commit.
Plus canary probes for schema drift. *This is where the mock-drift hazard is paid down.*

---

## 10. Open questions

**Does the kit already meet the #6 contract?** The contract is specified; whether the
current codebase satisfies it is not yet known. Run the grep for absolute URLs outside
tests, and check the auth path specifically — an API base that is configurable while the
token endpoint is a constant is the common case, and it fails the same way. Everything
else in this brief assumes the kit can be aimed at a twin without a patched build.
**Verify before writing anything else.**

**Is control attribution configured or inferred?** If a human maps SIEM detections to
controls during onboarding, the attribution family tests configuration handling. If the
kit infers it, that inference is the core IP and needs a far larger labelled corpus in
ground truth.

**Which vendors must be certified in the next six months?** Not the aspirational
fifty. Determines which connector patterns get built first and which sandboxes to go get.

**How many frameworks at launch?** One makes mapping strength a nicety. Two or more
make it mandatory, and make crosswalk imperfection a first-class test case.

**Does the risk engine consume a canonical model the team controls?** If yes,
VirtualOrg targets that boundary and stays small. If connectors write vendor-shaped
data straight into scoring logic, that is a larger architectural problem in the product
and the test environment is the wrong thing to build first.

---

## 11. Out of scope, and why

All of this appeared in earlier plans. Reasons recorded so decisions don't get quietly
reversed.

The chain that justified it ran: *the kit connects to a SIEM → so we need a real SIEM →
a real SIEM is only realistic with real logs → real logs need real endpoints, network
and attacks.* The chain hangs on the first link, and the first link is false. The kit
calls an endpoint and receives JSON; it cannot determine whether that JSON came from a
real product or a database query.

Running the real product tests exactly one thing: whether our understanding of that
vendor's API is correct. That is real — it is why #5's provenance discipline and Phase 4
exist — but it is *one* thing, and testing it needs any data, not realistic data. Three
alerts verify pagination, auth and schema. A cyber range is not required to produce
three alerts.

| Cut | Why proposed | Why it's gone |
|---|---|---|
| Real SIEM (Wazuh / Elastic) | Something to connect to | Twin serves identical JSON. Also no official ARM64 Wazuh images. |
| Sysmon, Zeek, Suricata | Produce logs for the SIEM | Nothing ingests logs — kit is API-only |
| Windows VMs, AD lab | Produce Windows telemetry | No consumer |
| CALDERA, Atomic Red Team, GOAD | Produce attack telemetry | No consumer. Unsafe on a Tailscale-connected work machine. |
| EvidenceForge | Synthetic security logs | No consumer — and it is a batch file generator, not a live service |
| OpenTelemetry Demo, Online Boutique | Ambient app telemetry | No consumer |
| Greenbone / OpenVAS | Real vulnerability findings | Findings are records; the world holds them |
| DefectDojo, CISO Assistant | Real APIs to pull from | Twins. ARM64-problematic; AGPL in one case. |
| Kafka / Redpanda, MinIO, syslog sink | Stream and file ingestion | No stream or file connectors yet. Re-add as lenses if that changes. |
| Docker network segmentation, VyOS, IDS | Realistic network | The network is a graph in the world model. Revisit only if the kit does live exposure analysis. |
| 64 GB x86 server | Run all of the above | Nothing left that needs it |

### What is genuinely given up

- **API fidelity assurance.** The real loss. Paid down by provenance manifests, Phase 4
  certification and schema-drift canaries — not by hope.
- **Demo credibility with a technical prospect.** "Connected to a real Wazuh" lands
  harder than "connected to our simulator." Partly offset by Control Center surfaces 1–2,
  which show something a real stack cannot.
- **Emergent weirdness.** Real products surprise you; a simulator contains only the
  weirdness someone thought of. The chaos dial helps and does not fully substitute.

Not given up, contrary to intuition: correlation testing gets better (ground truth is
exact), scale gets better (logical entities are free), dirty data gets better (it is
controlled), determinism and iteration speed are not close.

### The one thing that comes back later

Active and passive scanning is on the roadmap but not planned. The claims model in #4
is the seam: a first-party scanner is a new source type with higher confidence, added
without touching reconciliation. Keep that seam intact and the decision stays cheap.
