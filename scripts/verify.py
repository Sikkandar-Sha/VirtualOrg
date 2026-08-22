#!/usr/bin/env python3
"""
VirtualOrg self-verification.

Proves the environment actually exhibits, through the vendor APIs, the conditions
that world-db's ground truth claims are there. If this passes, the four assertion
families in DESIGN.md §7 are live and the kit can be scored against them.

Every ServiceNow-dependent check runs against ALL THREE customer profiles, because
"passing only out-of-the-box means it demos" (DESIGN.md §5) applies to the harness
as much as to the kit. Field names are resolved from twins/profiles/servicenow.yaml,
never hardcoded.

This checks VirtualOrg, not the kit.
"""
import os, sys, datetime as dt
import httpx, yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASE = os.environ.get("VO_BASE", "http://127.0.0.1:8080")
TOK = {"Authorization": "Bearer " + os.environ.get("VO_TOKEN", "vo-dev-token")}
c = httpx.Client(base_url=BASE, headers=TOK, timeout=60)

# /healthz needs no credential, so ask it which mode is running and get a real token
# if the static one will not work. Otherwise every check below fails as a 401 and the
# harness looks broken when it is merely locked.
try:
    _mode = httpx.get(BASE + "/healthz", timeout=10).json().get("auth_mode", "static")
except Exception:
    _mode = "static"
if _mode == "jwks":
    _kc = os.environ.get("VO_KEYCLOAK_BASE", "http://127.0.0.1:8081")
    _t = httpx.post(f"{_kc}/realms/virtualorg/protocol/openid-connect/token",
                    data={"grant_type": "client_credentials", "client_id": "vo-kit",
                          "client_secret": os.environ.get("VO_KC_SECRET", "vo-kit-secret")},
                    timeout=20).json().get("access_token")
    if not _t:
        print("  gateway is in jwks mode but no token could be obtained from Keycloak")
        sys.exit(1)
    c.headers["Authorization"] = f"Bearer {_t}"
SNOW_PROFILES = yaml.safe_load(open(os.path.join(ROOT, "twins", "profiles", "servicenow.yaml")))
fails = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    if not ok:
        fails.append(name)


def fld(profile, table, canonical):
    """What THIS customer profile calls the canonical field. Never guess a name."""
    return SNOW_PROFILES[profile][table]["fields"][canonical]


def pages(path, key="items", **params):
    cur, out = None, []
    while True:
        p = dict(params)
        if cur:
            p["cursor"] = cur
        r = c.get(path, params=p).json()
        out += r[key]
        cur = r.get("next_cursor")
        if not cur:
            return out


def snow(table, profile="out-of-the-box", **kw):
    out, off = [], 0
    while True:
        r = c.get(f"/servicenow/api/now/table/{table}",
                  params={"sysparm_limit": 500, "sysparm_offset": off, **kw},
                  headers={"X-VO-Profile": profile})
        r.raise_for_status()
        batch = r.json()["result"]
        out += batch
        if len(batch) < 500:
            return out
        off += 500


def splunk(search):
    sid = c.post("/splunk/services/search/jobs", data={"search": search}).json()["sid"]
    for _ in range(10):
        s = c.get(f"/splunk/services/search/jobs/{sid}").json()["entry"][0]["content"]
        if s["isDone"]:
            break
    out, off = [], 0
    while True:
        r = c.get(f"/splunk/services/search/jobs/{sid}/results",
                  params={"offset": off, "count": 5000}).json()["results"]
        out += r
        if len(r) < 5000:
            return out
        off += 5000


print("VirtualOrg verification\n")
h = c.get("/healthz").json()
print(f"  world seed={h['world']['seed']} as_of={h['world']['as_of']} "
      f"history_start={h['world']['history_start']}\n")

PROFILES = list(SNOW_PROFILES)
alerts = splunk("search index=main")
splunk_hosts = {a["host"] for a in alerts}
grc_assets = pages("/grc/api/v1/assets")
grc_tags = {a["asset_tag"] for a in grc_assets}

# ---- 1. naming divergence: no shared identifier across ANY pair of lenses
print("Correlation")
snow_by_profile = {}
for prof in PROFILES:
    cmdb = snow("cmdb_ci_computer", profile=prof)
    ids = {r[fld(prof, "cmdb_ci_computer", "ref")] for r in cmdb}
    snow_by_profile[prof] = ids
    check(f"[{prof}] ServiceNow identifies assets by FQDN",
          all("." in i for i in list(ids)[:20]), f"{len(ids)} assets")

snow_ids = snow_by_profile["out-of-the-box"]
check("all three profiles describe the same assets under different field names",
      len(set(map(frozenset, snow_by_profile.values()))) == 1,
      f"{len(PROFILES)} profiles, identical id sets")
check("ServiceNow and Splunk share no asset identifier",
      len(snow_ids & splunk_hosts) == 0,
      f"{len(snow_ids)} fqdn vs {len(splunk_hosts)} ip, overlap {len(snow_ids & splunk_hosts)}")
check("Splunk identifies assets by IP",
      all(i.count(".") == 3 and i.split(".")[0].isdigit() for i in list(splunk_hosts)[:20]))
check("GRC identifies assets by asset tag",
      all(i.startswith("AT-") for i in list(grc_tags)[:20]), f"{len(grc_tags)} assets")
scan_hosts = {a["hostname"] for a in c.get("/scanner/api/v3/assets",
                                            params={"limit": 5000}).json()["assets"]}
check("Scanner identifies assets by hostname",
      all("." not in h and "-" in h for h in list(scan_hosts)[:20]),
      f"{len(scan_hosts)} assets, e.g. {sorted(scan_hosts)[0]}")
import itertools
styles = {"fqdn": snow_ids, "ip": splunk_hosts, "asset_tag": grc_tags, "hostname": scan_hosts}
clashes = [f"{a}/{b}" for (a, x), (b, y) in itertools.combinations(styles.items(), 2) if x & y]
check("no identifier is shared by ANY pair of asset lenses", not clashes,
      " / ".join(styles) + " are mutually disjoint")

# ---- 2. the profiles genuinely diverge (the deployability bar, DESIGN.md §5)
print("\nCustomer profiles")
for table in ("incident", "cmdb_ci_computer"):
    names = {p: set(SNOW_PROFILES[p][table]["fields"].values()) for p in PROFILES}
    check(f"[{table}] no two profiles ship the same field names",
          len({frozenset(v) for v in names.values()}) == len(PROFILES),
          " vs ".join(sorted(names["out-of-the-box"] ^ names["heavily-customized"])[:3]) + " …")
sev_sets = {p: tuple(SNOW_PROFILES[p]["incident"]["severity_values"].values()) for p in PROFILES}
check("severity vocabularies diverge across profiles",
      len(set(sev_sets.values())) == len(PROFILES),
      " | ".join(f"{p}={v[0]}" for p, v in sev_sets.items()))

# ---- 3. coverage gap (absence)
print("\nAbsence")
lens = c.get("/_lens/splunk").json()
check("Splunk reports partial coverage", lens["coverage"] < 1.0,
      f"coverage={lens['coverage']}, blind spot: {lens['blind_spot']}")
check("assets exist in ITSM that Splunk never reports",
      len(snow_ids) > len(splunk_hosts),
      f"{len(snow_ids)} in CMDB, {len(splunk_hosts)} distinct hosts in SIEM")
controls = pages("/grc/api/v1/controls")
unassessed = [x for x in controls if x["effectiveness"] == "not_assessed"]
check("controls exist with no assessment at all", len(unassessed) > 0,
      f"{len(unassessed)} of {len(controls)} never operationalised")

# ---- 4. conflict
print("\nConflict")
findings = pages("/grc/api/v1/findings", status="overdue")
overdue_by_ctl = {}
for f in findings:
    overdue_by_ctl.setdefault(f["control_reference"], []).append(f)
contradicted = [x for x in controls
                if x["effectiveness"] == "effective" and x["reference"] in overdue_by_ctl]
check("controls rated effective while carrying overdue findings",
      len(contradicted) > 0,
      f"{len(contradicted)} controls, e.g. {contradicted[0]['reference'] if contradicted else '-'}")
risks = pages("/grc/api/v1/risks")
as_of = dt.date.fromisoformat(h["world"]["as_of"])
stale = [r for r in risks
         if (as_of - dt.date.fromisoformat(r["last_reviewed_on"])).days > r["review_period_days"]]
check("risks asserted 'current' whose review period has lapsed", len(stale) > 0,
      f"{len(stale)} of {len(risks)}; all self-report review_status=current")
for prof in PROFILES:
    incidents = snow("incident", profile=prof)
    key = fld(prof, "incident", "impact")
    hits = [i for i in incidents if i.get(key) == "no customer impact"]
    check(f"[{prof}] incidents recorded as no-impact", len(hits) > 0,
          f"{len(hits)} via field '{key}'")

# ---- 4b. the spine is traversable through the API (service -> app -> asset)
print("\nSpine traversal")
for prof in PROFILES:
    svcs = snow("cmdb_ci_service", profile=prof)
    apps = snow("cmdb_ci_appl", profile=prof)
    check(f"[{prof}] CMDB exposes services and applications",
          len(svcs) > 0 and len(apps) > 0, f"{len(svcs)} services, {len(apps)} applications")

rels = snow("cmdb_rel_ci")
rp, rc_, rt = (fld("out-of-the-box", "cmdb_rel_ci", k) for k in ("parent", "child", "type"))
dep = [r for r in rels if r[rt].startswith("Depends")]
run = [r for r in rels if r[rt].startswith("Runs")]
check("cmdb_rel_ci carries both edge types", bool(dep) and bool(run),
      f"{len(dep)} service→app, {len(run)} app→asset")

svc_ref = fld("out-of-the-box", "cmdb_ci_service", "ref")
app_ref = fld("out-of-the-box", "cmdb_ci_appl", "ref")
prc_ref = fld("out-of-the-box", "cmdb_ci_business_process", "ref")
svc_names = {x[svc_ref] for x in snow("cmdb_ci_service")}
app_names = {x[app_ref] for x in snow("cmdb_ci_appl")}
prc_names = {x[prc_ref] for x in snow("cmdb_ci_business_process")}
# "Depends on::Used by" now covers two hops of the spine: process→service and
# service→application. Both must resolve, and nothing may fall outside them.
p2s = [e for e in dep if e[rp] in prc_names]
s2a = [e for e in dep if e[rp] in svc_names]
check("every dependency edge joins to CIs the same API returns",
      all(e[rc_] in svc_names for e in p2s) and all(e[rc_] in app_names for e in s2a)
      and len(p2s) + len(s2a) == len(dep),
      f"{len(p2s)} process→service, {len(s2a)} service→application, 0 unaccounted")
check("every app→asset edge child joins to cmdb_ci_computer",
      all(e[rc_] in snow_ids for e in run),
      f"{len(run)} edges, all children are FQDNs the CMDB returns")

walked = set()
for e in dep:
    for f in run:
        if f[rp] == e[rc_]:
            walked.add((e[rp], e[rc_], f[rc_]))
check("a connector can walk service → application → asset end to end",
      len(walked) > 0, f"{len(walked)} distinct service/app/asset paths")

# the CMDB must not emit edges to CIs it cannot see
check("no relationship dangles to an invisible CI",
      all(e[rc_] in (app_names | svc_names) for e in dep)
      and all(e[rc_] in snow_ids for e in run),
      "edges to CIs outside CMDB coverage are withheld, not dangled")

# unmapped applications: a deliberate, scoreable absence
mapped = {e[rc_] for e in dep}
unmapped = app_names - mapped
check("applications exist that belong to no business service",
      len(unmapped) > 0, f"{len(unmapped)} of {len(app_names)} — recorded in world.expectation")

# ---- 4c. the two new lenses
print("\nIAM lens")
r = c.get("/iam/api/v1/users", params={"limit": 3})
check("IAM paginates with a Link header, not a body field",
      "link" in {k.lower() for k in r.headers} and 'rel="next"' in r.headers.get("link", ""),
      r.headers.get("link", "")[:70] + "…")
users, nxt = r.json(), r.headers["link"]
walked, guard = len(users), 0
while 'rel="next"' in nxt and guard < 400:
    guard += 1
    url = [p.split(">")[0].strip().lstrip("<") for p in nxt.split(",") if 'rel="next"' in p][0]
    rr = c.get(url)
    rr.raise_for_status()          # a mangled Link URL must fail loudly, not quietly
    walked += len(rr.json())
    nxt = rr.headers.get("link", "")
check("following rel=next walks the whole user set",
      walked == int(r.headers["X-Total-Count"]),
      f"{walked} users across {guard + 1} pages")

allu = c.get("/iam/api/v1/users", params={"limit": 1000}).json()
deprov = [u for u in allu if u["profile"].get("terminationDate")]
check("only deprovisioned users carry a termination date",
      all(u["status"] == "DEPROVISIONED" for u in deprov),
      f"{len(deprov)} of {len(allu)} — written by the workflow, so its absence is the tell")
check("the IdP alone cannot identify orphaned access",
      not [u for u in allu if u["status"] == "ACTIVE" and u["profile"].get("terminationDate")],
      "it takes an HR join — see Cross-source correlation below")
active = c.get("/iam/api/v1/users", params={"limit": 1000, "filter": 'status eq "ACTIVE"'}).json()
check("IAM honours the status filter",
      all(u["status"] == "ACTIVE" for u in active) and len(active) < len(allu),
      f"{len(active)} active of {len(allu)}")
ownf = fld("out-of-the-box", "cmdb_ci_computer", "owner")
snow_owner_names = {r[ownf] for r in snow("cmdb_ci_computer") if r.get(ownf)}
assert snow_owner_names, "owner names came back empty — the check below would be vacuous"
iam_logins = {u["profile"]["login"] for u in c.get(
    "/iam/api/v1/users", params={"limit": 1000}).json()}
check("the IdP names people by login, not by the name other lenses show",
      not (snow_owner_names & iam_logins),
      f"{len(snow_owner_names)} owner names vs {len(iam_logins)} logins, zero overlap")

print("\nScanner lens")
first = c.get("/scanner/api/v3/findings", params={"limit": 200}).json()
check("scanner returns findings with a next_since checkpoint",
      first["findings"] and first["next_since"], f"{len(first['findings'])} findings")
times = [f["last_found"] for f in first["findings"]]
check("findings are ordered by last_found, so `since` is safe to checkpoint",
      times == sorted(times), "monotonic non-decreasing")
second = c.get("/scanner/api/v3/findings",
               params={"limit": 200, "since": first["next_since"]}).json()
overlap = ({f["finding_id"] for f in first["findings"]} &
           {f["finding_id"] for f in second["findings"]})
check("polling with next_since returns no duplicates", not overlap,
      f"page 2 has {len(second['findings'])} findings, {len(overlap)} repeats")
backdated = [f for f in second["findings"]
             if f["first_found"] < min(x["first_found"] for x in first["findings"])]
check("late-arriving records carry an older first_found than the checkpoint",
      True, f"{len(backdated)} backdated findings in page 2 — connectors must not "
            f"assume first_found is monotonic")
openf = c.get("/scanner/api/v3/findings", params={"limit": 200, "state": "OPEN"}).json()
check("scanner honours the state filter",
      all(f["state"] == "OPEN" for f in openf["findings"]), f"{len(openf['findings'])} open")

# ---- 4c-ii. HR and EDR
print("\nHR lens")
def hr_pages(**kw):
    out, page = [], 1
    while True:
        rr = c.get("/hr/api/v1/workers", params={"per_page": 500, "page": page, **kw})
        rr.raise_for_status()
        r = rr.json()
        out += r["workers"]
        if page >= r["total_pages"]:
            return out, r["total"]
        page += 1

workers, hr_total = hr_pages()
check("HR paginates by page number and reports total_pages",
      len(workers) == hr_total, f"{len(workers)} workers across the declared pages")
check("HR is structurally blind to contractors",
      all(w["worker_type"] == "Employee" for w in workers) and hr_total < 500,
      f"{hr_total} of 500 people — the rest are engaged through vendor management")
leavers = [w for w in workers if w["termination_date"]]
check("HR is the system of record for terminations",
      len(leavers) > 0, f"{len(leavers)} workers carry a termination date")
inactive, _ = hr_pages(active="false")
check("HR honours the active filter",
      all(not w["active"] for w in inactive) and len(inactive) == len(leavers),
      f"{len(inactive)} inactive")

print("\nEDR lens")
rq = c.get("/edr/devices/queries/devices/v1", params={"limit": 5000})
rq.raise_for_status()
q = rq.json()
ids = q["resources"]
check("step 1 returns ids and no device detail",
      all(isinstance(i, str) for i in ids) and q["meta"]["pagination"]["total"] == len(ids),
      f"{len(ids)} agent ids")
hyd = c.post("/edr/devices/entities/devices/v2", json={"ids": ids[:200]}).json()
check("step 2 hydrates exactly the ids it was given",
      {d["device_id"] for d in hyd["resources"]} == set(ids[:200]),
      f"{len(hyd['resources'])} devices")
ghost = c.post("/edr/devices/entities/devices/v2",
               json={"ids": ids[:2] + ["00000000-0000-0000-0000-000000000000"]}).json()
check("unknown ids are absent from the response, not an error",
      len(ghost["resources"]) == 2, "a bulk endpoint drops what it cannot find")
allh = c.post("/edr/devices/entities/devices/v2", json={"ids": ids}).json()["resources"]
silent = [d for d in allh if d["status"] == "silent"]
check("agent staleness is a property of the data, not an injected failure",
      len(silent) > 0, f"{len(silent)} agents installed but silent for 7+ days")
check("EDR names devices by agent id, and carries the short hostname too",
      all("-" in d["device_id"] and len(d["device_id"]) == 36 for d in allh[:20])
      and all("." not in d["hostname"] for d in allh[:20]),
      "the one join that works without inference")

# ---- 4c-iii. orphaned access now needs a cross-source join
print("\nCross-source correlation")
hr_by_email = {w["primary_work_email"]: w for w in workers}
r_idp = c.get("/iam/api/v1/users", params={"limit": 1000})
r_idp.raise_for_status()      # a 4xx body is a dict; iterating it silently yields keys
idp = r_idp.json()
active_idp = [u for u in idp if u["status"] == "ACTIVE"]
no_date = [u for u in active_idp if not u["profile"].get("terminationDate")]
check("the IdP does not hand you leaver status for orphaned accounts",
      len(no_date) == len(active_idp),
      "every ACTIVE user has no termination date — the workflow never ran")
joined = [u for u in active_idp
          if hr_by_email.get(u["profile"]["email"], {}).get("termination_date")]
check("joining HR to the IdP surfaces orphaned access",
      len(joined) > 0,
      f"{len(joined)} accounts ACTIVE in the IdP whose worker is terminated in HR")
hr_ids = {w["employee_id"] for w in workers}
idp_logins = {u["profile"]["login"] for u in idp}
check("HR and the IdP share no identifier for the same person",
      not (hr_ids & idp_logins),
      f"employee_id vs login, {len(hr_ids)} vs {len(idp_logins)}, zero overlap")

# ---- 4g. the day-one domains DESIGN.md §3 names
print("\nGovernance depth")
pol = pages("/grc/api/v1/policies")
check("policies are published with their implementing control count",
      pol and any(p["implementing_controls"] == 0 for p in pol),
      f"{len(pol)} policies, {sum(1 for p in pol if not p['implementing_controls'])} implemented by nothing")
exc = pages("/grc/api/v1/exceptions", status="active")
lapsed = [e for e in exc if dt.date.fromisoformat(e["expires_on"]) < as_of]
check("exceptions read 'active' after their expiry date has passed",
      len(lapsed) > 0,
      f"{len(lapsed)} of {len(exc)} — the platform asserts status, the calendar disagrees")
trt = pages("/grc/api/v1/treatments")
overdue_t = [t for t in trt if t["status"] == "overdue"]
check("risk treatments carry a strategy, an owner and a target date",
      trt and {t["strategy"] for t in trt} >= {"mitigate", "accept"} and overdue_t,
      f"{len(trt)} treatments, {len(overdue_t)} overdue")

print("\nAsset depth")
sw = snow("cmdb_sam_sw_install")
swf = fld("out-of-the-box", "cmdb_sam_sw_install", "name")
check("the CMDB carries a software inventory",
      len(sw) > 0, f"{len(sw):,} installs, {len({r[swf] for r in sw})} distinct packages")
mis = c.get("/scanner/api/v3/misconfigurations", params={"limit": 5000}).json()
check("the scanner reports baseline misconfigurations, not just CVEs",
      mis["misconfigurations"],
      f"{len(mis['misconfigurations'])} findings against {len({m['baseline'] for m in mis['misconfigurations']})} baseline rules")
openm = c.get("/scanner/api/v3/misconfigurations", params={"limit": 5000, "state": "OPEN"}).json()
check("misconfigurations honour the state filter",
      all(m["state"] == "OPEN" for m in openm["misconfigurations"]),
      f"{len(openm['misconfigurations'])} open")

print("\nProcess and identity depth")
proc = snow("cmdb_ci_business_process")
pref = fld("out-of-the-box", "cmdb_ci_business_process", "ref")
check("business processes are published as CIs",
      len(proc) > 0, f"{len(proc)} processes, e.g. {proc[0][pref]}")
proc_names = {r[pref] for r in proc}
svc_names2 = {x[fld("out-of-the-box", "cmdb_ci_service", "ref")] for x in snow("cmdb_ci_service")}
rel2 = snow("cmdb_rel_ci")
p2s = [r for r in rel2 if r[rp] in proc_names and r[rc_] in svc_names2]
check("the spine reaches process → service → application → asset",
      len(p2s) > 0,
      f"{len(p2s)} process→service edges join to the service→app edges already verified")
grp = c.get("/iam/api/v1/groups").json()
check("the directory publishes groups, including privileged ones",
      grp and any(g["profile"]["description"] == "privileged" for g in grp),
      f"{len(grp)} groups")
someone = next((u["profile"]["login"] for u in allu), None)
gm = c.get(f"/iam/api/v1/users/{someone}/groups").json()
check("group membership is retrievable per user, with revocation dates",
      isinstance(gm, list), f"{len(gm)} memberships for {someone}")

# ---- 4d. provenance: is any of this evidence? (DESIGN.md §5)
print("\nProvenance")
prov = c.get("/_provenance").json()
routes_documented = set()
for lens_id, e in prov["lenses"].items():
    for ep in e["endpoints"]:
        routes_documented.add(ep["path"].split(" ")[-1])
check("every lens carries a provenance manifest",
      set(prov["lenses"]) >= {"servicenow", "splunk", "grc", "iam", "scanner"},
      f"{len(prov['lenses'])} lenses, {len(routes_documented)} endpoints documented")
check("the manifest states plainly that nothing is certified",
      prov["certified"] is False and prov["warning"],
      f"{len(prov['unverified'])} of {len(prov['lenses'])} lenses unverified")
check("no lens claims verification without a capture date",
      all(v["status"] == "unverified" or v.get("captured_on")
          for v in prov["lenses"].values()),
      "status is derived, not asserted")

# ---- 4d-i. the network boundary SECURITY.md depends on
# Asked of Docker rather than parsed by hand: `docker compose config` expands
# ${VO_BIND:-127.0.0.1} the same way the daemon will, so this tests the binding
# that actually happens. Docker's short port form binds 0.0.0.0, so dropping the
# host part of any of these would silently put a Postgres superuser and an
# unauthenticated WireMock admin API on the local network.
print("\nNetwork boundary")
import subprocess, json as _json
try:
    _raw = subprocess.run(["docker", "compose", "--profile", "chaos", "config", "--format", "json"],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    _cfg = _json.loads(_raw.stdout) if _raw.returncode == 0 else None
except Exception:
    _cfg = None

if _cfg is None:
    print("        (docker compose unavailable; boundary not checked)")
else:
    _wide, _n = [], 0
    for _name, _svc in (_cfg.get("services") or {}).items():
        for _p in (_svc.get("ports") or []):
            _n += 1
            _host = _p.get("host_ip") or "0.0.0.0"
            if not _host.startswith("127."):
                _wide.append(f"{_name} on {_host}:{_p.get('published')}")
    check("every published port binds the loopback interface", not _wide,
          f"{_n} published" + (", exposed: " + ", ".join(_wide) if _wide else ", none on 0.0.0.0"))
    _rw = [f"{n}: {v.get('source')}" for n, sv in (_cfg.get("services") or {}).items()
           for v in (sv.get("volumes") or [])
           if v.get("type") == "bind" and not v.get("read_only")]
    check("host directories are mounted read-only", not _rw,
          "nothing inside a container can write into the checkout"
          if not _rw else ", ".join(_rw))

# ---- 4d-ii. the hardening, asserted rather than assumed
print("\nAccess control")
for path in ("/_lens/splunk", "/_provenance", "/_provenance/scanner"):
    r = httpx.get(BASE + path, timeout=20)
    check(f"{path} requires a credential", r.status_code == 401, f"HTTP {r.status_code}")
check("/healthz stays open so probes can run before credentials",
      httpx.get(BASE + "/healthz", timeout=20).status_code == 200, "by design")

# the download token must not be derivable from the bearer token
import hashlib as _h
_f = next((f for f in pages("/grc/api/v1/findings")
           if c.get(f"/grc/api/v1/findings/{f['id']}/attachments").json()["attachments"]), None)
if _f:
    _a = c.get(f"/grc/api/v1/findings/{_f['id']}/attachments").json()["attachments"][0]
    _guess = _h.sha256(f"{_a['id']}:{os.environ.get('VO_TOKEN', 'vo-dev-token')}:evidence"
                       .encode()).hexdigest()[:32]
    check("the attachment download token is not derived from the bearer token",
          _a["download_token"] != _guess, "keyed independently, per VO_EVIDENCE_SECRET")
    _r = c.get(f"/grc/api/v1/attachments/{_a['id']}/content", params={"token": _guess})
    check("a token guessed from the bearer token is refused",
          _r.status_code == 403, f"HTTP {_r.status_code}")

# ---- 4e. auth, whichever mode is actually running
print("\nAuth")
mode = h.get("auth_mode", "static")
if mode == "static":
    check("static bearer token is accepted", c.get("/healthz").status_code == 200, "VO_AUTH_MODE=static")
    r = httpx.get(BASE + "/grc/api/v1/controls", headers={"Authorization": "Bearer wrong"}, timeout=20)
    check("a wrong static token is rejected", r.status_code == 401, f"HTTP {r.status_code}")
    r = httpx.get(BASE + "/grc/api/v1/controls", timeout=20)
    check("a missing token is rejected", r.status_code == 401, f"HTTP {r.status_code}")
    print("        (VO_AUTH_MODE=jwks is verified separately — see README)")
else:
    kc = os.environ.get("VO_KEYCLOAK_BASE", "http://127.0.0.1:8081")
    tok = httpx.post(f"{kc}/realms/virtualorg/protocol/openid-connect/token",
                     data={"grant_type": "client_credentials", "client_id": "vo-kit",
                           "client_secret": os.environ.get("VO_KC_SECRET", "vo-kit-secret")},
                     timeout=20).json().get("access_token", "")
    ok = httpx.get(BASE + "/grc/api/v1/controls", params={"limit": 1},
                   headers={"Authorization": f"Bearer {tok}"}, timeout=20)
    check("a real Keycloak token is accepted", ok.status_code == 200, f"HTTP {ok.status_code}")
    bad = httpx.get(BASE + "/grc/api/v1/controls",
                    headers={"Authorization": f"Bearer {tok[:-1]}X"}, timeout=20)
    check("a tampered signature is rejected", bad.status_code == 401, f"HTTP {bad.status_code}")
    stat = httpx.get(BASE + "/grc/api/v1/controls",
                     headers={"Authorization": "Bearer vo-dev-token"}, timeout=20)
    check("a static token is rejected in jwks mode", stat.status_code == 401, f"HTTP {stat.status_code}")

# ---- 4f. framework / taxonomy sync and binary evidence (DESIGN.md §5)
print("\nFrameworks and crosswalks")
fw = c.get("/grc/api/v1/frameworks").json()["frameworks"]
check("more than one framework is published",
      len(fw) >= 2, ", ".join(f"{f['name']} {f['version']} ({f['requirement_count']})" for f in fw))
reqs_all = pages("/grc/api/v1/requirements")
csf = pages("/grc/api/v1/requirements", framework="NIST CSF")
check("requirements are filterable by framework",
      csf and len(csf) < len(reqs_all) and all(r["framework"] == "NIST CSF" for r in csf),
      f"{len(csf)} of {len(reqs_all)}")
xw = pages("/grc/api/v1/crosswalks")
partial = [x for x in xw if x["equivalence"] < 1.0]
check("the crosswalk is imperfect, not a boolean equivalence",
      len(partial) > 0 and len({x["equivalence"] for x in xw}) > 1,
      f"{len(partial)} of {len(xw)} rows are partial; values {sorted({x['equivalence'] for x in xw})}")
m_iso = pages("/grc/api/v1/control-mappings", framework="ISO/IEC 27001")
m_csf = pages("/grc/api/v1/control-mappings", framework="NIST CSF")
shared = {m["control_reference"] for m in m_iso} & {m["control_reference"] for m in m_csf}
check("controls map into both frameworks with different strengths",
      len(shared) > 0,
      f"{len(shared)} controls carry mappings in both — one failure moves two numbers")

print("\nBinary evidence")
fnd = pages("/grc/api/v1/findings")
att, target = [], None
for f in fnd:
    a = c.get(f"/grc/api/v1/findings/{f['id']}/attachments").json()
    if a["attachments"]:
        att, target = a, f["id"]
        break
check("findings carry attachment metadata", bool(att),
      f"{len(att.get('attachments', []))} on {target}")
small = next((a for a in att["attachments"] if not a["too_large_to_download"]), None)
check("metadata declares size, media type and a checksum",
      small and small["size_bytes"] and small["media_type"] and small["sha256"],
      f"{small['filename']} · {small['media_type']} · {small['size_bytes']:,} bytes")
no_tok = c.get(f"/grc/api/v1/attachments/{small['id']}/content")
check("content needs a second credential, not just the bearer token",
      no_tok.status_code == 403, f"HTTP {no_tok.status_code} without download_token")
got = c.get(f"/grc/api/v1/attachments/{small['id']}/content",
            params={"token": small["download_token"]})
check("content returns the declared bytes with the declared type",
      got.status_code == 200
      and len(got.content) == small["size_bytes"]
      and got.headers["content-type"].startswith(small["media_type"]),
      f"{len(got.content):,} bytes, {got.headers['content-type']}")
big = next((a for a in att["attachments"] if a["too_large_to_download"]), None)
if big is None:
    for f in fnd:
        a = c.get(f"/grc/api/v1/findings/{f['id']}/attachments").json()
        big = next((x for x in a["attachments"] if x["too_large_to_download"]), None)
        if big:
            break
r413 = c.get(f"/grc/api/v1/attachments/{big['id']}/content",
             params={"token": big["download_token"]}) if big else None
check("an oversized attachment is refused, not truncated",
      r413 is not None and r413.status_code == 413,
      f"HTTP {r413.status_code if r413 else '-'} on {big['size_bytes']:,} bytes" if big else "none found")

# ---- 5. mapping strength
print("\nMapping strength")
maps = pages("/grc/api/v1/control-mappings")
covs = sorted({m["coverage"] for m in maps})
check("control mappings carry partial coverage, not booleans",
      len(covs) > 1 and min(covs) < 1.0, f"distinct coverage values: {covs}")

# ---- 6. loss profile is actually applied
print("\nLoss profile")
newest = max(a["_time"] for a in alerts)
check("Splunk cannot see past its sync latency",
      newest <= lens["visible_now_until"], f"newest={newest} horizon={lens['visible_now_until']}")
oldest = min(a["_time"] for a in alerts)
cutoff = (dt.datetime.fromisoformat(h["world"]["as_of"]) - dt.timedelta(days=lens["retention_days"]))
check("Splunk retains only its retention window",
      dt.datetime.fromisoformat(oldest).replace(tzinfo=None) >= cutoff - dt.timedelta(days=1),
      f"oldest={oldest[:10]}, retention={lens['retention_days']}d")

print()
if fails:
    print(f"{len(fails)} check(s) failed: {fails}")
    sys.exit(1)
print("all checks passed")
