# Security

## VirtualOrg ships with credentials on purpose

This repository contains working credentials, and that is deliberate. VirtualOrg is a
local test harness whose whole job is to be started in one command and thrown away:

| Credential | Where | What it is |
|---|---|---|
| `vo-dev-token` | `.env.example`, `docker-compose.yml` | The static bearer token the twins accept |
| `admin` / `admin` | `docker-compose.yml` | The Keycloak bootstrap admin |
| `vo-kit-secret` | `keycloak/virtualorg-realm.json` | The OAuth client secret for the `vo-kit` service account |
| `vo` / `vo` | `docker-compose.yml` | The Postgres role |

None of these guard anything real. The database holds a generated fiction: invented
people, invented machines, invented findings. There is no customer data anywhere in
this project, and there never should be.

**Do not expose a VirtualOrg instance to a network you do not control.**

Every published port binds `127.0.0.1` explicitly. That matters more than it looks:
Docker's short port form (`"5433:5432"`) binds `0.0.0.0`, and `POSTGRES_USER: vo` is the
Postgres image's *bootstrap superuser*, so anyone who could reach `:5433` could run
`COPY ... TO PROGRAM` and execute commands in the container. Under `--profile chaos`,
WireMock's `/__admin` API is unauthenticated by design, so reaching `:8090` would let
anyone install a stub proxying to an arbitrary host.

Both are contained by the loopback binding. If you deliberately want LAN access, set
`VO_BIND=0.0.0.0`, and understand that you are handing a superuser shell and an open
proxy to everyone on that network.

The bind mounts are read-only. Nothing inside a container writes to `./seeds` or
`./wiremock`; the snapshot and restore scripts run `pg_dump` and `pg_restore` on the
host. Read-only stops a compromised container, or an unauthenticated WireMock admin
call, from writing into your checked-out repository.

Anyone who can reach the ports can read the whole world and, with the token above, every
twin. There is no authorisation model beyond a shared token, because modelling one would
not have tested anything about the kit under test.

If you want to change them, everything is in `.env`. That file is gitignored.

## What is not a shared default

Two things are deliberately keyed independently of the token above, so that changing
nothing still leaves them unguessable:

- **Attachment download tokens** are an HMAC over the attachment id, keyed by
  `VO_EVIDENCE_SECRET`. Leave that unset and the process generates a random key at
  startup, so tokens are valid only for that run. The attachment metadata call issues a
  current one on every request, so nothing needs to persist them.
- **The OAuth audience** is the client id (`vo-kit`), not `account`. Keycloak stamps
  `account` into every token it issues for a realm, so checking it would prove the realm
  and nothing more. The realm ships an audience mapper so tokens name the client.

The Control Center renders no credential on any page, not even the shipped default.
Its examples reference `$VO_TOKEN`, so they stay copy-pasteable without publishing a
token on a surface that has no authentication. CI asserts it across every surface and
every manual chapter.

Every data endpoint requires a credential, including the `/_lens/{id}` and
`/_provenance` metadata routes. Three paths stay open: `/healthz`, which probes and CI
need before they have anything to authenticate with and which returns only liveness and
the world's identifying metadata, and FastAPI's own `/docs` and `/openapi.json`, which
describe the interface and expose no data.

## What VirtualOrg is not

It is not a security product, not a scanner, and not a source of security advice. The
vulnerabilities, misconfigurations and control failures it reports are fabricated to
give a risk-posture product something to reason about. Nothing it says about CVEs
reflects the real state of any real software.

## Reporting a vulnerability

If you find a genuine security problem in VirtualOrg itself, such as a path that lets a
reader escape the container, or a dependency with a known advisory, please open a
[security advisory](https://github.com/Sikkandar-Sha/VirtualOrg/security/advisories/new)
rather than a public issue.

For anything that is merely a bug, open a normal issue. Given what this project is, most
findings will be bugs rather than vulnerabilities.
