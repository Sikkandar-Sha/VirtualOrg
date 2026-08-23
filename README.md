<h1>VirtualOrg</h1>

**A synthetic enterprise for testing risk-posture products, with the answer key
included.**

[![licence](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENSE)
[![checks](https://img.shields.io/badge/self--checks-80%20passing-brightgreen)](scripts/verify.py)
[![boot](https://img.shields.io/badge/cold%20boot-~7s-brightgreen)](#run-it)
[![lenses](https://img.shields.io/badge/vendor%20lenses-7-informational)](#the-seven-lenses)

## The problem

You are building something that reads a SIEM, an ITSM, a GRC platform and a scanner
over their APIs, and produces residual risk per service, control effectiveness, and a
board-level posture score. To know whether it works, you need an enterprise to point it
at. Every option is bad:

- **A real customer.** You cannot, and even if you could, nobody knows what the right
  answer was, so you cannot tell a good posture from a plausible one.
- **A demo dataset.** Clean, consistent, complete. It never exercises correlation,
  conflict or coverage gaps, which are the only hard parts.
- **Real vendor products in a lab.** Months of work, no ARM64 images for several, and
  at the end you still have no ground truth about what should have been concluded.

## The idea

Your product calls an endpoint and receives JSON. **It cannot tell whether that JSON
came from a real product or a database query.** So model the enterprise once,
completely and truthfully, and make every tool a deliberately lossy *lens* over it.

```
                    ┌── ServiceNow   97% · by fqdn      · 1d behind
                    ├── Splunk       83% · by ip        · 5m behind · 90d window
  world-db ─────────┼── Onspring     91% · by asset tag · 7d behind      ──▶ your kit
  complete · true   ├── Okta         94% · by login     · 15m behind
  40 tables         ├── Tenable      88% · by hostname  · 1d behind · 365d window
  38,000 rows       ├── Workday     100% · by staff no. · employees only
  3 years           └── CrowdStrike  79% · by agent id  · 5m behind · 30d window

  All loss is applied at the lens, at read time. The world is never wrong.
```

Seven lenses. Five different names for the same machine, two more for the same person,
and no lens that sees all of it. That is not an accident. **It is what manufactures the
correlation, conflict and coverage-gap problems your product exists to solve.**

> A VirtualOrg whose lenses are faithful and complete is a database with extra steps.
> The loss profiles *are* the test.

## What you get

**1,217 ground-truth assertions.** `world.expectation` says what your product should
conclude, and what it should refuse to conclude. Four families: attribution, conflict,
degradation, absence.

**An answer key for attribution.** Nothing in any vendor API links a SIEM detection to a
GRC control. That inference is your product's core job, and the thing most likely to be
wrong in a way nobody notices. `world.evidence.control_id` holds the true link for
**5,023** events, and `is_trap` marks **773** topically-adjacent decoys. Score precision
and recall against it.

**Determinism.** Same seed and same `--as-of` produce a byte-identical world, so a
posture change without a world change is a regression. No live clock anywhere.

**A sub-second reset.** Snapshot the world, run your product, assert, restore. That is
what makes world-state `W₁` → posture `P₁` golden-file testing usable in practice.

**Seven connector patterns**, three customer schema profiles per vendor, a chaos dial,
real OAuth, and an adversarial proxy that returns 429s and expired tokens on demand.

## Where it helps

| If you are… | VirtualOrg gives you |
|---|---|
| **Writing connectors** | Seven live API patterns: async job, cursor, offset, Link header, page number, incremental `since` and query-then-hydrate, plus binary evidence retrieval behind a second credential |
| **Testing entity resolution** | One machine under five identifiers, recycled IPs so the IP is not a key, and one join that *does* work so you can tell the difference |
| **Guarding against regressions** | A deterministic world and a restorable baseline, so any posture delta is a real finding |
| **Scoring inference quality** | 5,023 true evidence links and 773 deliberate traps |
| **Proving deployability** | Three customer schema profiles per vendor. Passing all three means the connector ships. Passing only `out-of-the-box` means it demos |
| **Demoing** | *"Here are the 52 machines with no endpoint agent, and the 7 control exceptions that expired months ago. A GRC platform will never tell you that."* |

## Run it

```bash
git clone https://github.com/Sikkandar-Sha/VirtualOrg.git && cd VirtualOrg
cp .env.example .env
docker compose up -d          # boots in about seven seconds
./scripts/status              # is everything running?
open http://localhost:3000    # the Control Center
```

The design rationale lives in [DESIGN.md](DESIGN.md). This file is how to run it.

`world-engine` applies the schema, generates ~500 people / 300 assets / 100 controls
across **40 tables** and **three years of history**, then exits. `twin-gateway` waits for it and comes up
on `:8080`.

Run your kit from your IDE with a debugger attached, pointed at
`config/virtualorg/connectors.yaml`. The kit is deliberately not a compose service.
See DESIGN.md §2 for why.

```bash
docker compose --profile ci up -d      # CI: also runs the kit in-network
docker compose --profile chaos up -d   # adds WireMock in front of a twin (see wiremock/README.md)
```

## The seven lenses

| Path | Vendor shape | Connector pattern | Loss profile |
|---|---|---|---|
| `/servicenow/api/now/table/{table}` | generic table API | offset pagination, customer-defined fields | 97% coverage, nightly sync, identifies by **FQDN** |

`{table}` is one of `incident`, `cmdb_ci_computer`, `cmdb_ci_appl`, `cmdb_ci_service`,
`cmdb_rel_ci`. The relationship table makes the spine walkable: service → application →
asset, with children named exactly as the CI tables name them.
| `/splunk/services/search/jobs` | async search job | submit → poll → fetch | 83% coverage, 5 min latency, 90d retention, identifies by **IP** |
| `/grc/api/v1/{object}` | governance objects | cursor pagination | full coverage, weekly sync, identifies by **asset tag** |
| `/iam/api/v1/users` | identity provider | **Link-header** pagination | 94% coverage, 15 min sync, identifies people by **login** |
| `/scanner/api/v3/findings` | vulnerability scanner | **incremental `since`** polling | 88% coverage, 24h sync, 365d retention, identifies by **hostname** |
| `/hr/api/v1/workers` | HCM system of record | **page / per_page** | employees only, contractors are structurally absent, identifies by **employee id** |
| `/edr/devices/...` | endpoint detection | **query then hydrate** | 79% coverage, 5 min sync, 30d retention, identifies by **agent id** |

`{object}` is one of `controls`, `assets`, `findings`, `risks`, `control-mappings`.

Five identifier styles for the same machine (fqdn, ip, asset tag, hostname, agent id)
and two more for people: an IdP login and an HR employee number. No two lenses name the same thing the same way, and no lens sees all of it. That is
the point. It is what manufactures the correlation, conflict and coverage-gap problems
the kit exists to solve.

```bash
curl -s -H "Authorization: Bearer vo-dev-token" localhost:8080/_lens/splunk
```

## The domains

DESIGN.md §3 names twelve domains and a day-one column. Everything it marks **Yes** or
**Thin** is built:

| Domain | §3 | Built |
|---|---|---|
| People & org | Yes | people, departments, JML over three years, HR lens |
| Identity & access | Thin | accounts, groups, membership with revocation, privileged flag |
| Assets & infrastructure | Yes | assets, lifecycle, **software inventory with EOL dates** |
| Applications & services | Yes | apps, services, dependency graph, owners |
| Business processes | Thin | **processes with RTO**, process → service edges |
| Security posture | Yes | vulns, **misconfigurations**, detections, alerts, incidents |
| Governance | Yes | frameworks ×2, requirements, controls, tests, **policies**, **exceptions**, audits, findings, risks, **treatments** |
| Operations | Thin | incidents with severity and stated impact |
| Third parties · Data · Change · Impact | Later | deferred by the design |

## Connector patterns covered

Build for patterns, not brands (DESIGN.md §5). All seven are live:

| Pattern | Lens | The part that catches people |
|---|---|---|
| Generic table API, offset pagination | ServiceNow | customer-defined field names |
| Async query job | Splunk | never DONE on the first poll; 204 before ready |
| Cursor pagination | GRC | opaque cursors you must echo, never construct |
| Link-header pagination | Okta | follow `rel="next"`; building the URL yourself drifts |
| Incremental polling | Tenable | late-arriving records with a backdated `first_found` |
| Page number | Workday | `total_pages` in the envelope |
| Query then hydrate | CrowdStrike | ids and detail page differently; unknown ids vanish silently |

Plus **framework / taxonomy sync** (two frameworks and an imperfect crosswalk) and
**binary evidence retrieval** (a second credential, a real `Content-Type`, a hard size
limit). Both live on the GRC lens.

## Two frameworks, one imperfect crosswalk

ISO/IEC 27001 and NIST CSF 2.0, with controls mapped into both at differing coverage
strength, and a crosswalk where **56 of 70 equivalences are partial**.

```bash
curl -s -H "$H" localhost:8080/grc/api/v1/frameworks
curl -s -H "$H" 'localhost:8080/grc/api/v1/crosswalks?limit=5'
```

That is what makes mapping strength mandatory rather than a nicety (DESIGN.md §10): the
same control failure moves ISO and CSF by different amounts, and you can say why.

## Binary evidence

```bash
curl -s -H "$H" localhost:8080/grc/api/v1/findings/AF-054/attachments
curl -s -H "$H" 'localhost:8080/grc/api/v1/attachments/ATT-0123/content?token=...' -o out.png
```

Metadata carries size, media type, a SHA-256 and a `download_token`. The bytes need
that second credential, so a bearer token alone gets a `403`, and anything over 5 MB is
refused with a `413` rather than truncated. Content is generated deterministically, so
the same attachment is byte-identical on every run.

## Customer profiles

The same twin serves three schema shapes, because in this market the schema is defined
by the customer, not the vendor (DESIGN.md §5).

```bash
H='Authorization: Bearer vo-dev-token'
curl -s -H "$H" -H 'X-VO-Profile: out-of-the-box'      localhost:8080/servicenow/api/now/table/cmdb_ci_computer
curl -s -H "$H" -H 'X-VO-Profile: heavily-customized'  localhost:8080/servicenow/api/now/table/cmdb_ci_computer
```

`name` / `u_device_name`, `assigned_to` / `u_custodian`, `severity: "1"` / `"Sev-Critical"`.
**Passing all three profiles means the connector is deployable. Passing only
`out-of-the-box` means it demos.**

## Ground truth

`world.expectation` is the assertion catalogue, materialised. Every row is something
the kit should conclude, or should refuse to conclude.

```sql
SELECT family, claim, count(*) FROM world.expectation GROUP BY 1,2 ORDER BY 1;
```

```
absence     asset runs software that is past its end-of-life date                      200
absence     asset is live but carries no endpoint protection agent                      52
absence     asset is scanned for vulnerabilities but monitored by no SIEM               29
absence     control has no evidence source of any kind                                   8
absence     leaver is a contractor, so no HR record confirms the termination             7
absence     application is not attached to any business service                          3
absence     policy is approved but no control implements it                              3
absence     asset is live and in ITSM but invisible to every security lens               1
attribution evidence is topically adjacent to the control but is not evidence for it   773
conflict    person has left but an account remains enabled                              31
conflict    person has left but retains membership of a privileged group                21
conflict    control tested effective while an overdue audit finding stands against it   21
conflict    risk treatment is overdue while the risk remains above appetite             17
conflict    incident recorded as no customer impact on a tier-1 service                 16
conflict    control owner of record has left the company                                12
conflict    control exception is recorded as active but its expiry date has passed       7
conflict    risk presented as current but review period has lapsed                       4
degradation endpoint agent is installed but has not reported in over a week             12
```

Counts are for `--seed 48392 --as-of 2026-08-21 --scale 1.0`. Same seed, same numbers.

All four assertion families are now live from the world itself. Degradation used to be
WireMock-only.

`world.evidence.control_id` is the **true** control attribution for every event, and
`is_trap` marks the topically-adjacent decoys. Score the kit's attribution as precision
and recall against that column.

## Reset loop

Generating three years of history takes a couple of seconds; restoring it takes a
fraction of one. Do it once, restore thereafter.

```bash
./scripts/seed baseline      # schema + generate + snapshot
./scripts/reset baseline     # ~0.3s
./scripts/snapshot my-case   # freeze a variant
```

That is what makes world-state `W₁` → posture `P₁` golden-file testing usable.

## Determinism

Same seed + same `--as-of` ⇒ byte-identical world. Never use a live clock.

```bash
python3 world/generate.py --seed 48392 --as-of 2026-08-21 --scale 1.0
```

`--scale 0.2` for a fast laptop world, `--scale 3.0` for volume.

## Verify the environment

`scripts/verify.py` checks that the conditions ground truth claims exist are actually
observable **through the vendor APIs**. It tests VirtualOrg, not your kit. Run it after
any change to the generator or the lenses.

```bash
python3 scripts/verify.py
```

It runs every ServiceNow-dependent check against all three customer profiles, resolving
field names from `twins/profiles/servicenow.yaml` rather than hardcoding them, which is
the same bar it holds the kit to.

## Control Center

The browsable specification of the enterprise (DESIGN.md §8). Every pixel is generated
from world-db and the twins, so it cannot drift from what the kit actually reads.

```bash
open http://localhost:3000        # or $VO_CC_PORT
```

| Surface | Path | What it is for |
|---|---|---|
| 0 | `/` | Is everything running? Live probes, not container state |
| 1 | `/asset/{id}` | **One entity, every lens.** The highest-value screen |
| 2 | `/spine/service/{id}`, `/spine/control/{id}` | The spine, walked from either end |
| 3 | `/lenses/{id}` | Loss profile in plain language, plus a try-it console against the real twin |
| 4 | `/org` | Browsable inventory, filters, drill-down |
| 5 | `/groundtruth` | The assertion catalogue |
| 6 | `/scenario` | Baselines and chaos state, read-only (see below) |
| 7 | `/manual` | **The manual.** How it works, how to connect, every entity and endpoint |

It is **read-only over world-db and the twins, and computes nothing**. If a number
appears there it is a query, never a calculation: two implementations of "what is true
about this enterprise" would be the exact bug the product exists to detect, built
inside the harness meant to detect it. Surface 6 shows commands rather than running
them, for the same reason.

### The manual (surface 7)

Eight chapters at `/manual`, aimed at someone about to write a connector:

| Chapter | Answers |
|---|---|
| Overview | What VirtualOrg is, what runs where, why the world is pre-aged |
| The world model | Every table, every column, live row counts, the spine |
| What you can reach | **Which entities a connector can see through the APIs, and which it cannot** |
| Where the graph breaks | Cross-table integrity: what exists but is not wired into the spine |
| Connecting a kit | Base URLs, auth, the config file, the three call patterns, live request/response per lens, the profile field maps |
| API reference | Every endpoint, read from the twin's own route table |
| Correlation | One real machine as each lens names it, plus the traps |
| Scoring | The four families, attribution precision/recall, assertion style per output |

Every fact in it is generated: column names from `information_schema`, counts from the
tables, the endpoint list from the twin's route table, example payloads from real calls to
the running twin. Only prose is authored, and the model chapter reports any table it does
not describe, so the manual cannot quietly fall behind the schema.

Port 3000 is taken on some machines. Set `VO_CC_PORT` in `.env` to move the host side.

## Is everything running?

```bash
./scripts/status                  # terminal
open http://localhost:3000        # same answer, browsable
```

Both probe each dependency the way a consumer would. Splunk is exercised as a full
submit → poll → DONE cycle, because a twin can return 200 on `/healthz` and still fail
the pattern a connector uses.

## The chaos dial

The dial lives in the lens loss profiles, never in the world (DESIGN.md §4.4).

```bash
python3 world/generate.py --seed 48392 --as-of 2026-08-21 --chaos 2
VO_CHAOS=2 docker compose up -d --force-recreate world-engine
```

| Level | World | Used for |
|---|---|---|
| 0 | Pristine. One identifier scheme, complete coverage, nothing stale | Baseline regression |
| 1 | Realistic. Recycled IPs, five naming schemes, gaps, stale rows *(default)* | Primary regression |
| 2 | Pathological. Level 1 plus ID collisions, Cyrillic homoglyphs, trailing whitespace, case drift | Fuzzing |

Level 2 mangles a percentage of `lens_visibility.external_id` values, so identifiers
stop being trustworthy keys. The count lands in `world_meta.mangled_identifiers`.
It is for fuzzing, not scoring: the mangled rows are not written as expectations.

## Auth

Static bearer tokens by default. `VO_AUTH_MODE=jwks` validates real RS256 tokens
against Keycloak's published keys, checking signature, issuer, audience and expiry.
Nothing is stubbed. The audience is the client id rather than `account`, which Keycloak
puts in every token it issues for a realm, so the check identifies the caller rather
than just the realm.

```bash
VO_AUTH_MODE=jwks docker compose up -d --force-recreate twin-gateway
TOK=$(curl -s -X POST localhost:8081/realms/virtualorg/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=vo-kit -d client_secret=vo-kit-secret \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOK" localhost:8080/grc/api/v1/controls?limit=1
```

`scripts/verify.py` detects the running mode and checks it either way.

**The issuer is pinned deliberately.** Keycloak derives `iss` from the request host,
so a token fetched on `localhost:8081` would never satisfy a twin expecting
`keycloak:8080`. `KC_HOSTNAME` fixes the issuer; `VO_JWKS_URL` still points at the
internal address, because where you fetch keys from and what the token claims are
two different things. Self-hosted customers hit exactly this.

## Fidelity, and the standing hazard

With no vendor product in the loop, all correctness confidence rests on twin fidelity.
Nothing here can tell you the connector has misread a vendor's pagination: connector
and twin will be wrong together, forever, in green CI (DESIGN.md §5).

Every twin therefore carries a provenance manifest in `twins/provenance.yaml`,
served live and surfaced on the Control Center status board:

```bash
curl -s localhost:8080/_provenance | python3 -m json.tool
```

**All seven lenses are `unverified`.** Every response shape was written from our
understanding of documented behaviour, and no vendor artefact was captured. `status` is
derived, never asserted: it requires a trustworthy basis for every endpoint *and* a
capture date. Passing tests here show the kit agrees with this environment, not that
either agrees with the vendor. Paying that down is Phase 4.

## Not yet built

- **Phase 4 certification** against real vendor tenants, plus schema-drift canaries.
  This is the only thing that moves a lens off `unverified`, and it needs vendor
  developer tenants rather than more code.
- The domains DESIGN.md §3 marks *Later*: third parties, data classification, change
  management, and financial impact. Deferred by the design, not outstanding.
- Surface 5's "vs actual" column stays empty until a kit is pointed at this world and
  its output is loaded. The Control Center computes nothing itself, by rule.

## Known gaps

- The ServiceNow lens returns `name` and `fqdn` as the same value for computers. The
  hostname form is exposed by the scanner lens, so the identifier clash in DESIGN.md §8
  is now real, but ServiceNow itself still duplicates one value into two fields.
- The IdP shows only accounts federated to it. AD-only accounts, including some
  orphaned ones, are invisible by design. A kit should say so rather than report clean.
- `world.account` is reachable only through the IdP, and only for federated accounts.
- Orphaned access now needs a real join: the IdP shows an account `ACTIVE` with *no*
  termination date, because the deprovisioning workflow never ran. HR is the only
  source that knows the person left, and HR cannot see contractors at all.

## Re-baselining

The service→application graph was rebuilt (see `world/generate.py`), which shifts the
random stream and changes every downstream count. Golden files recorded before that change
need re-baselining. Determinism is unaffected: the same seed and `--as-of` still produce
the same world.

## Branches

Two, and only two.

| Branch | Purpose |
|---|---|
| `dev` | Where work happens. Everything lands here first. |
| `main` | Finalised, released state. Only ever fast-forwarded from `dev`. |

```bash
git checkout dev && git push                 # day to day
git checkout main && git merge --ff-only dev && git push   # when it is ready
```

CI runs on both: it boots the whole environment, runs the 80 self-checks, loads every
Control Center surface, exercises the chaos proxy and real OAuth, and regenerates the
world twice to prove determinism.

## Network boundary

Every published port binds `127.0.0.1`. Docker's short port form binds `0.0.0.0`, and
`POSTGRES_USER` is the Postgres image's bootstrap superuser, so a port on the LAN would
hand anyone on that network `COPY ... TO PROGRAM`. Under `--profile chaos`, WireMock's
`/__admin` API is unauthenticated by design and would be an open proxy. Both are
contained by the binding, and `scripts/verify.py` asserts it by asking
`docker compose config` what the daemon will actually do.

Set `VO_BIND=0.0.0.0` if you deliberately want LAN access, knowing what you are sharing.

## Licence

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Vendor names are trademarks of
their owners; VirtualOrg is not affiliated with or endorsed by any of them, and every
twin is marked `unverified` so no passing test is mistaken for vendor certification.

## ARM64

All images should resolve natively on Apple Silicon and Windows-on-ARM. Confirm before
relying on it, because there is no amd64 emulation on Docker Desktop for Windows/ARM:

```bash
for i in postgres:16-alpine quay.io/keycloak/keycloak:26.0 wiremock/wiremock:3.10.0; do
  echo "$i: $(docker manifest inspect $i | grep -c 'arm64')"
done
```
