"""
VirtualOrg Control Center — a live specification of the synthetic enterprise.

DESIGN.md §8: read-only over world-db and twin responses, zero business logic.
Every number on every page is a query in queries.py. Nothing here aggregates,
scores or infers — that is the job of the kit under test, and building a second
implementation of "what is true about this enterprise" inside the harness would
be the exact bug the product exists to detect.

Surface 6 (scenario controls) is deliberately read-only: it shows the commands and
the current state, and never executes them. The harness does not mutate the world
it describes.
"""
import datetime as dt
import glob
import os
import textwrap
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import manual as M, probes, queries as Q

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
app = FastAPI(title="VirtualOrg Control Center", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
T = Jinja2Templates(directory=os.path.join(HERE, "templates"))

SURFACES = [
    ("/", "Status", "0"),
    ("/asset", "One entity, every lens", "1"),
    ("/spine", "The spine", "2"),
    ("/lenses", "The lenses", "3"),
    ("/org", "The org", "4"),
    ("/groundtruth", "Ground truth", "5"),
    ("/scenario", "Scenario", "6"),
    ("/manual", "Manual", "7"),
]


def world_now():
    meta = Q.world_meta()
    d = dt.date.fromisoformat(meta["as_of"])
    return dt.datetime.combine(d, dt.time(9, 0), tzinfo=dt.timezone.utc), meta


# The Control Center is unauthenticated by design, so it prints no credential at
# all, not even the shipped default. Examples reference the shell variable instead,
# which keeps them copy-pasteable without putting a token on the page.
TOKEN_PLACEHOLDER = "$VO_TOKEN"

# Prose that states a count has to read the count. "Three views, one world" was
# written when there were three lenses and quietly became wrong at four.
NUMBER_WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six",
                7: "Seven", 8: "Eight", 9: "Nine", 10: "Ten", 11: "Eleven", 12: "Twelve"}


def spell(n):
    return NUMBER_WORDS.get(n, str(n))


def asset_version():
    """mtime of the stylesheet, so the browser never serves a stale one."""
    try:
        return str(int(os.path.getmtime(os.path.join(HERE, "static", "app.css"))))
    except OSError:
        return "0"


def page(request, template, **ctx):
    _, meta = world_now()
    return T.TemplateResponse(request, template,
                              {"surfaces": SURFACES, "meta": meta, "path": request.url.path,
                               "v": asset_version(), **ctx})


def hours_stale(last_seen, now):
    """Whole hours. A tenth of an hour is precision the source never had."""
    if not last_seen:
        return None
    return int(round((now - last_seen).total_seconds() / 3600))


# ------------------------------------------------------------- surface 0: status
@app.get("/")
def status(request: Request):
    now, meta = world_now()
    return page(request, "status.html", prov=probes.provenance(),
                probes=probes.all_probes(), lens_probes=probes.lens_reachability(),
                lenses=Q.lenses(), counts=Q.table_counts(),
                families=Q.expectation_families(), corpus=Q.attribution_corpus(),
                world_now=now)


# ---------------------------------------------- surface 1: one entity, every lens
@app.get("/asset")
def asset_index(request: Request, q: Optional[str] = None, invisible_to: Optional[str] = None):
    rows = Q.assets(limit=60, q=q, invisible_to=invisible_to)
    return page(request, "asset_index.html", rows=rows, q=q or "",
                invisible_to=invisible_to or "", lenses=Q.lenses(),
                total=Q.asset_total(q=q, invisible_to=invisible_to))


@app.get("/asset/{asset_id}")
def asset_detail(request: Request, asset_id: str):
    a = Q.asset(asset_id)
    if not a:
        return RedirectResponse("/asset")
    now, _ = world_now()
    bands = []
    for r in Q.asset_lens_rows(asset_id):
        bands.append({**r, "stale_h": hours_stale(r["last_seen"], now),
                      "blind": r["external_id"] is None})
    return page(request, "asset.html", a=a, bands=bands, now=now,
                alerts=Q.asset_alert_count(asset_id), vulns=Q.asset_open_vulns(asset_id),
                apps=Q.asset_applications(asset_id), expectations=Q.asset_expectations(asset_id))


# --------------------------------------------------------- surface 2: the spine
@app.get("/spine")
def spine_index(request: Request):
    return page(request, "spine_index.html", services=Q.services(),
                processes=Q.processes(),
                controls=Q.controls(limit=100), gaps=Q.spine_gaps())


@app.get("/spine/service/{service_id}")
def spine_service(request: Request, service_id: str):
    s = Q.service(service_id)
    if not s:
        return RedirectResponse("/spine")
    return page(request, "service.html", s=s, processes=Q.service_processes(service_id),
                apps=Q.service_applications(service_id),
                assets=Q.service_assets(service_id), risks=Q.service_risks(service_id),
                incidents=Q.service_incidents(service_id))


@app.get("/spine/control/{control_id}")
def spine_control(request: Request, control_id: str):
    c = Q.control(control_id)
    if not c:
        return RedirectResponse("/spine")
    return page(request, "control.html", c=c,
                evidence=Q.control_evidence(c["id"]),
                summary=Q.control_evidence_summary(c["id"]),
                tests=Q.control_tests(c["id"]), findings=Q.control_findings(c["id"]),
                reqs=Q.control_requirements(c["id"]), risks=Q.control_risks(c["id"]),
                policies=Q.control_policies(c["id"]), exceptions=Q.control_exceptions(c["id"]),
                now=world_now()[0].date(),
                expectations=Q.control_expectations(c["id"]))


# -------------------------------------------------------- surface 3: the lenses
@app.get("/lenses")
def lens_index(request: Request):
    lenses = Q.lenses()
    return page(request, "lens_index.html", lenses=lenses, n_lenses=spell(len(lenses)),
                counts=Q.lens_entity_counts())


TRY_IT = {
    "servicenow": [("GET", "/servicenow/api/now/table/cmdb_ci_computer", {"sysparm_limit": "5"}),
                   ("GET", "/servicenow/api/now/table/incident", {"sysparm_limit": "5"})],
    "splunk": [("POST", "/splunk/services/search/jobs", {"search": "search index=main"})],
    "iam": [("GET", "/iam/api/v1/users", {"limit": "5"}),
            ("GET", "/iam/api/v1/users", {"limit": "5", "filter": 'status eq "ACTIVE"'})],
    "scanner": [("GET", "/scanner/api/v3/findings", {"limit": "5"}),
                ("GET", "/scanner/api/v3/findings", {"limit": "5", "state": "OPEN"}),
                ("GET", "/scanner/api/v3/assets", {"limit": "5"})],
    "hr": [("GET", "/hr/api/v1/workers", {"per_page": "5"}),
           ("GET", "/hr/api/v1/workers", {"per_page": "5", "active": "false"})],
    "edr": [("GET", "/edr/devices/queries/devices/v1", {"limit": "5"})],
    "grc": [("GET", "/grc/api/v1/controls", {"limit": "5"}),
            ("GET", "/grc/api/v1/assets", {"limit": "5"}),
            ("GET", "/grc/api/v1/findings", {"limit": "5", "status": "overdue"}),
            ("GET", "/grc/api/v1/risks", {"limit": "5"}),
            ("GET", "/grc/api/v1/control-mappings", {"limit": "5"}),
            ("GET", "/grc/api/v1/frameworks", {}),
            ("GET", "/grc/api/v1/requirements", {"limit": "5", "framework": "NIST CSF"}),
            ("GET", "/grc/api/v1/crosswalks", {"limit": "5"})],
}
PROFILES = ["out-of-the-box", "lightly-customized", "heavily-customized"]


@app.get("/lenses/{lens_id}")
def lens_detail(request: Request, lens_id: str, call: Optional[str] = None,
                profile: Optional[str] = None):
    l = Q.lens(lens_id)
    if not l:
        return RedirectResponse("/lenses")
    now, _ = world_now()
    result = None
    calls = TRY_IT.get(lens_id, [])
    if call is not None:
        try:
            method, path, params = calls[int(call)]
        except (ValueError, IndexError):
            method, path, params = calls[0]
        result = probes.twin_call(method, path,
                                  params=params if method == "GET" else None,
                                  data=params if method == "POST" else None,
                                  profile=profile if lens_id == "servicenow" else None)
    return page(request, "lens.html", l=l, calls=calls, result=result,
                prov=probes.provenance().get("lenses", {}).get(lens_id),
                selected=call, profile=profile or PROFILES[0], profiles=PROFILES,
                horizon=now - dt.timedelta(minutes=l["latency_minutes"]),
                floor=now - dt.timedelta(days=l["retention_days"]), now=now,
                counts=[c for c in Q.lens_entity_counts() if c["lens_id"] == lens_id])


# ------------------------------------------------------------ surface 4: the org
@app.get("/org")
def org(request: Request, tab: str = "overview", q: Optional[str] = None,
        kind: Optional[str] = None, leavers: int = 0, offset: int = 0):
    ctx = {"tab": tab, "q": q or "", "kind": kind or "", "leavers": leavers, "offset": offset}
    if tab == "people":
        ctx["rows"] = Q.people(limit=80, offset=offset, q=q, leavers_only=bool(leavers))
    elif tab == "assets":
        ctx["rows"] = Q.assets(limit=80, offset=offset, q=q, kind=kind)
        ctx["total"] = Q.asset_total(q=q, kind=kind)
    elif tab == "controls":
        ctx["rows"] = Q.controls(limit=80, offset=offset, q=q)
    elif tab == "services":
        ctx["rows"] = Q.services()
    else:
        ctx["counts"] = Q.org_counts()
        ctx["depts"] = Q.departments()
    return page(request, "org.html", **ctx)


@app.get("/org/person/{person_id}")
def person_detail(request: Request, person_id: str):
    p = Q.person(person_id)
    if not p:
        return RedirectResponse("/org?tab=people")
    return page(request, "person.html", p=p, accounts=Q.person_accounts(person_id),
                owns=Q.person_owns(person_id), expectations=Q.person_expectations(person_id))


# --------------------------------------------------------- surface 5: ground truth
@app.get("/groundtruth")
def groundtruth(request: Request, family: Optional[str] = None, offset: int = 0):
    return page(request, "groundtruth.html", families=Q.expectation_families(),
                rows=Q.expectations(family=family, offset=offset),
                total=Q.expectation_total(family=family), family=family or "",
                offset=offset, corpus=Q.attribution_corpus())


# ------------------------------------------------------------ surface 6: scenario
@app.get("/scenario")
def scenario(request: Request):
    seeds = []
    for f in sorted(glob.glob(os.path.join(ROOT, "seeds", "*.dump"))):
        seeds.append({"name": os.path.basename(f)[:-5],
                      "size_mb": round(os.path.getsize(f) / 1_048_576, 1),
                      "modified": dt.datetime.fromtimestamp(os.path.getmtime(f))})
    return page(request, "scenario.html", seeds=seeds, probes=probes.all_probes(),
                lenses=Q.lenses())


# ------------------------------------------------------------- surface 7: manual
CHAPTERS = [
    ("overview", "Overview"),
    ("model", "The world model"),
    ("reach", "What you can reach"),
    ("gaps", "Where the graph breaks"),
    ("connect", "Connecting a kit"),
    ("api", "API reference"),
    ("correlate", "Correlation"),
    ("scoring", "Scoring"),
]

# Live examples, per lens. Each is executed against the running twin when its
# chapter is viewed, so the manual shows what the kit actually receives today.
SNOW_BLURB = {
    "cmdb_ci_computer": "Computers — offset pagination, named by FQDN",
    "incident": "Incidents",
    "cmdb_ci_appl": "Applications — named by CI name, not the APP- id",
    "cmdb_ci_service": "Business services — name, tier and owner",
    "cmdb_rel_ci": "Relationships — this is what makes the spine walkable",
}


def _snow_examples():
    """Built from the profile YAML, so a table added there appears here on its own."""
    import yaml
    path = os.path.join(ROOT, "twins", "profiles", "servicenow.yaml")
    tables = sorted(yaml.safe_load(open(path))["out-of-the-box"])
    out = [("servicenow", SNOW_BLURB.get(t, t), "GET",
            f"/servicenow/api/now/table/{t}", {"sysparm_limit": "2"}, "out-of-the-box")
           for t in tables]
    # one side-by-side so the profile difference is visible, not just described
    out.append(("servicenow", "The same computers call, heavily-customized profile — "
                "every field renamed", "GET",
                "/servicenow/api/now/table/cmdb_ci_computer",
                {"sysparm_limit": "2"}, "heavily-customized"))
    return out


EXAMPLES = _snow_examples() + [
    ("iam", "Users — Link-header pagination; read the next URL, never build it",
     "GET", "/iam/api/v1/users", {"limit": "3"}, None),
    ("scanner", "Findings — incremental polling; feed next_since back on the next call",
     "GET", "/scanner/api/v3/findings", {"limit": "3"}, None),
    ("scanner", "Scanned assets — named by hostname, the fourth identifier style",
     "GET", "/scanner/api/v3/assets", {"limit": "3"}, None),
    ("hr", "Workers — page / per_page; HR is blind to contractors",
     "GET", "/hr/api/v1/workers", {"per_page": "2"}, None),
    ("edr", "Step 1 of 2 — ids only, no device detail",
     "GET", "/edr/devices/queries/devices/v1", {"limit": "3"}, None),
    ("splunk", "Step 1 of 3 — submit the search job",
     "POST", "/splunk/services/search/jobs", {"search": "search index=main"}, None),
    ("grc", "Controls — cursor pagination", "GET", "/grc/api/v1/controls", {"limit": "2"}, None),
    ("grc", "Assets — the third identifier style", "GET", "/grc/api/v1/assets", {"limit": "2"}, None),
    ("grc", "Overdue findings", "GET", "/grc/api/v1/findings",
     {"limit": "2", "status": "overdue"}, None),
    ("grc", "Risks — note review_status is asserted, not verified",
     "GET", "/grc/api/v1/risks", {"limit": "2"}, None),
    ("grc", "Control mappings — coverage is a fraction, not a boolean",
     "GET", "/grc/api/v1/control-mappings", {"limit": "2"}, None),
    ("grc", "Frameworks — two of them, so mapping strength is mandatory",
     "GET", "/grc/api/v1/frameworks", {}, None),
    ("grc", "Crosswalks — equivalence between frameworks, mostly partial",
     "GET", "/grc/api/v1/crosswalks", {"limit": "2"}, None),
]

LENS_PATTERN = {"servicenow": ("/servicenow/api/now/table", "offset"),
                "splunk": ("/splunk/services/search/jobs", "async job"),
                "grc": ("/grc/api/v1", "cursor"),
                "iam": ("/iam/api/v1", "Link header"),
                "scanner": ("/scanner/api/v3", "incremental since"),
                "hr": ("/hr/api/v1", "page / per_page"),
                "edr": ("/edr/devices", "query then hydrate")}


def _curl(method, path, params, profile):
    base = "http://localhost:8080"
    h = f' -H "Authorization: Bearer {TOKEN_PLACEHOLDER}"'
    if profile:
        h += f" \\\n     -H 'X-VO-Profile: {profile}'"
    if method == "POST":
        body = " ".join(f"-d '{k}={v}'" for k, v in (params or {}).items())
        return f"curl -s{h} \\\n     {body} \\\n     {base}{path}"
    qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
    return f"curl -s{h} \\\n     '{base}{path}{'?' + qs if qs else ''}'"


@app.get("/manual")
def manual(request: Request, ch: str = "overview"):
    keys = [k for k, _ in CHAPTERS]
    if ch not in keys:
        ch = "overview"
    ctx = {"chapter": ch, "chapters": CHAPTERS,
           "cc_port": os.environ.get("VO_CC_PORT", "3000")}

    if ch == "overview":
        lo = M.lens_objects()
        rows = []
        for l in sorted(Q.lenses(), key=lambda x: list(LENS_PATTERN).index(x["id"])
                        if x["id"] in LENS_PATTERN else 99):
            mins = l["latency_minutes"]
            sync = (f"{mins} min" if mins < 60 else
                    f"{mins // 60}h" if mins < 1440 else f"{mins // 1440}d")
            objs = ", ".join(lo.get(l["id"], []))
            rows.append({"vendor": l["vendor"], "cat": l["category"],
                         "cov": int(round(l["coverage"] * 100)),
                         "ident": l["identifier_style"], "sync": sync,
                         "retention": l["retention_days"],
                         # wrapped here, on word boundaries: SVG has no text flow, and
                         # splitting on a character count breaks identifiers in half
                         "object_lines": textwrap.wrap(objs, width=40)[:3]})
        ctx.update(inventory=M.world_inventory(), lens_rows=rows)
    elif ch == "model":
        groups, undocumented, live = M.domains_with_schema()
        ctx.update(groups=groups, undocumented=undocumented, live=live)
    elif ch == "reach":
        ctx["matrix"] = M.reach_matrix()
    elif ch == "gaps":
        ctx.update(gaps=Q.spine_gaps(), orphans=Q.orphan_applications())
    elif ch == "connect":
        # ordered to match the call-pattern diagram above them, not by lens id
        order = list(LENS_PATTERN)
        lenses = []
        for l in sorted(Q.lenses(), key=lambda x: order.index(x["id"])
                        if x["id"] in order else 99):
            base, pattern = LENS_PATTERN.get(l["id"], ("", ""))
            lenses.append({**l, "base": base, "pattern": pattern})
        examples = []
        for lens_id, title, method, path, params, profile in EXAMPLES:
            examples.append({
                "lens": lens_id, "title": title,
                "curl": _curl(method, path, params, profile),
                "result": M.live_example(path, params=params if method == "GET" else None,
                                         data=params if method == "POST" else None,
                                         method=method, profile=profile, cap=2200)})
        ctx.update(lenses=lenses, examples=examples,
                   fieldmaps=M.profile_fieldmaps(), config_yaml=M.config_file(),
                   token=TOKEN_PLACEHOLDER)
    elif ch == "api":
        ctx["endpoints"] = M.endpoints()
        ctx["prov"] = probes.provenance()
    elif ch == "correlate":
        ctx["worked"] = M.worked_correlation()
    elif ch == "scoring":
        ctx.update(families=Q.expectation_families(), corpus=Q.attribution_corpus())

    return page(request, "manual.html", **ctx)


@app.get("/healthz")
def healthz():
    p = probes.all_probes()
    down = [x["name"] for x in p if x["state"] in ("down", "degraded") and not x["optional"]]
    return {"status": "ok" if not down else "degraded", "down": down,
            "probes": p, "world": Q.world_meta()}
