# Contributing

## The one rule

**The world is always true. All loss happens at the lens.**

If you find yourself storing something incomplete, stale or misspelled in `world/`, stop.
That belongs in a lens loss profile or in `lens_visibility`. The moment the world itself
starts lying, ground truth stops meaning anything and the whole project is just a
database with extra steps.

## House style

No em dashes. They read as machine-written, and this project is meant to read as
though a person wrote it. Use a full stop, a colon, a semicolon, or a comma pair,
whichever the join actually calls for. CI fails on an em dash in any tracked file
except `DESIGN.md`, which keeps its author's voice.

Section references use `#5`, not the section symbol.

## Branches

| Branch | Purpose |
|---|---|
| `dev` | Where work happens. Everything lands here first. |
| `main` | Released state. Only ever fast-forwarded from `dev`. |

```bash
git checkout dev && git push
git checkout main && git merge --ff-only dev && git push
```

## Before you open a pull request

```bash
pip install -r requirements-host.txt   # once; verify.py needs httpx and PyYAML
docker compose up -d
python3 scripts/verify.py         # must be green
```

`scripts/verify.py` tests VirtualOrg, not any kit. It proves the conditions the ground
truth claims exist are genuinely observable through the vendor APIs. If you change the
generator or a lens and it stays green, you have probably not added a check yet.

CI runs the same thing on every push, plus every Control Center surface, the chaos
proxy, real OAuth, and a determinism check.

## Adding a lens

A lens is a scope query, a loss profile and a response shape. Roughly a day's work:

1. Add a row to the `base_lenses` list in `world/generate.py`, with honest coverage,
   latency, retention, identifier style and blind spot. The `lenses` name is derived from
   it, and the chaos dial rewrites it at level 0.
2. Give it visibility rows in the same loop. A missing row means that lens is
   structurally blind to that entity, which is a feature.
3. Add the vendor face to `twins/app.py`. Twins are **always well behaved**: no injected
   failures, no throttling, no drift. Adversarial behaviour belongs in `wiremock/`.
4. Write a provenance entry in `twins/provenance.yaml`. Be honest about `basis`. If you
   modelled it from documentation rather than a captured response, say `model` and name
   the divergences you know about.
5. Add checks to `scripts/verify.py`.
6. Add it to the reach map in `control_center/manual.py`.

## Changing the generator

Any change to the order of random draws rewrites the entire world downstream. That is
fine, but it invalidates golden files, so say so in the pull request. If your addition
can use its own `random.Random(seed ^ ...)` stream, prefer that: it leaves everything
that already exists byte-identical.

## Things that are deliberately not here

Real vendor products, log pipelines, attack tooling. See DESIGN.md #11 for why each was
cut. Please read it before proposing one of them back.
