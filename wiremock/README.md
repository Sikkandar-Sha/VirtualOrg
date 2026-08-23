# Adversarial layer

Twins never misbehave. This does. (DESIGN.md #2)

WireMock sits in front of `twin-gateway` and serves the **degradation** assertion
family (#7). A catch-all mapping proxies everything to the twin, so the happy path is
identical to hitting `:8080` directly; the failure mappings intercept specific paths.

```bash
docker compose --profile chaos up -d
# point the kit at :8090 instead of :8080
curl -s -H 'Authorization: Bearer vo-dev-token' localhost:8090/healthz
```

## Failure modes

Every failure is a **WireMock scenario that fires once, then recovers**, so the chaos
profile stays usable and each mode tests a retry path rather than permanently breaking
an endpoint.

| Mapping | Fires on | Behaviour | Question it asks the kit |
|---|---|---|---|
| `10/11-rate-limit` | Splunk job poll | `429` + `Retry-After: 3`, then proxies | Does it honour Retry-After, or hammer and fail the sync? |
| `20/21-expired-token` | GRC risks | `401 invalid_token` + `WWW-Authenticate`, then proxies | Does it refresh and retry, or surface a broken source? |
| `30/32-truncated-page` | first GRC controls page | 2 items but `total: 100`, plus a poison `next_cursor`, then proxies | Does it notice the page is short, or report 2 controls as the whole library? |
| `31-dead-cursor` | the poison cursor only | `500 cursor expired` | Does a mid-pagination failure surface, or silently truncate the set? |
| `40/41-source-unreachable` | ServiceNow CMDB | connection reset, then proxies | Does posture announce a stale source, or serve last week's numbers as current? |

`31-dead-cursor` is the one mapping with no recovery state: the real twin never issues
that cursor, so it is only reachable by a kit that followed the poisoned one.

Each failure mode owns **one endpoint**, deliberately. Two mappings at the same priority
matching the same path make which one fires ambiguous, and a harness whose failure
injection is non-deterministic cannot be used to score anything.

## Reset

Scenarios are stateful. Put every failure back into its firing state:

```bash
curl -X POST localhost:8090/__admin/scenarios/reset
curl -s localhost:8090/__admin/scenarios | python3 -m json.tool   # inspect state
```
