"""
VirtualOrg twin-gateway — one process, N vendor faces, routed by path prefix.

Every response is a projection over world-db through a lens (twins/lenses.py).
Twins are ALWAYS well-behaved: no injected failures, no throttling, no drift.
Adversarial behaviour belongs in WireMock, in front of this. (DESIGN.md §2)
"""
import base64
import hashlib
import os
import uuid
import datetime as dt
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse, Response

from . import db, lenses

HERE = os.path.dirname(__file__)
PROFILES = {
    "servicenow": yaml.safe_load(open(os.path.join(HERE, "profiles", "servicenow.yaml"))),
}
PROVENANCE = yaml.safe_load(open(os.path.join(HERE, "provenance.yaml")))

TRUSTWORTHY = {"openapi-spec", "captured-sandbox"}


def provenance_status(entry):
    """`verified` demands a trustworthy basis for every endpoint AND a capture date.
    Anything short of that is unverified, and its passing tests certify nothing."""
    bases = {e.get("basis") for e in entry.get("endpoints", [])} | {entry.get("basis")}
    if bases <= TRUSTWORTHY and entry.get("captured_on"):
        return "verified"
    return "unverified"
AUTH_MODE = os.environ.get("VO_AUTH_MODE", "static")
STATIC_TOKENS = set(filter(None, os.environ.get("VO_TOKENS", "vo-dev-token").split(",")))
JWKS_URL = os.environ.get("VO_JWKS_URL", "")
JWT_ISSUER = os.environ.get("VO_JWT_ISSUER", "")
JWT_AUDIENCE = os.environ.get("VO_JWT_AUDIENCE", "account")

app = FastAPI(title="VirtualOrg twin-gateway", docs_url="/docs")


# ----------------------------------------------------------------- auth
def require_token(authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if AUTH_MODE == "static":
        if token not in STATIC_TOKENS:
            raise HTTPException(401, "invalid token")
        return
    _verify_jwt(token)


_JWKS_CLIENT = None


def _jwks_client():
    """One PyJWKClient, which caches keys and refetches on an unknown kid — so a
    JWKS rotation is picked up without a restart, and the kit's refresh path is
    exercised for real rather than waved through."""
    global _JWKS_CLIENT
    if _JWKS_CLIENT is None:
        import jwt
        if not JWKS_URL:
            raise HTTPException(500, "VO_AUTH_MODE=jwks but VO_JWKS_URL is unset")
        _JWKS_CLIENT = jwt.PyJWKClient(JWKS_URL, cache_keys=True, lifespan=300)
    return _JWKS_CLIENT


def _verify_jwt(token: str):
    """Real signature verification against Keycloak's published keys.

    Nothing here is stubbed. An expired token fails, a wrong signature fails, a
    token from another realm fails — which is the only way the kit's own token
    refresh handling can be shown to work. (DESIGN.md §5)
    """
    import jwt
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
        jwt.decode(token, signing_key.key, algorithms=["RS256"],
                   issuer=JWT_ISSUER or None,
                   audience=JWT_AUDIENCE or None,
                   options={"verify_aud": bool(JWT_AUDIENCE),
                            "verify_iss": bool(JWT_ISSUER)})
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token expired")
    except jwt.InvalidAudienceError:
        raise HTTPException(401, f"token audience is not '{JWT_AUDIENCE}'")
    except jwt.InvalidIssuerError:
        raise HTTPException(401, f"token issuer is not '{JWT_ISSUER}'")
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {type(e).__name__}")
    except HTTPException:
        raise
    except Exception as e:
        # JWKS endpoint unreachable is a 503, not a 401: the caller's token may be
        # perfectly good and telling them it is invalid would send them in circles.
        raise HTTPException(503, f"cannot reach JWKS endpoint: {type(e).__name__}")


def profile_for(vendor: str, requested: Optional[str]) -> str:
    p = requested or os.environ.get(f"VO_PROFILE_{vendor.upper()}", "out-of-the-box")
    if p not in PROFILES[vendor]:
        raise HTTPException(400, f"unknown profile '{p}' for {vendor}")
    return p


def shape(row: dict, fieldmap: dict) -> dict:
    """Rename canonical keys to whatever this customer profile calls them."""
    return {fieldmap[k]: v for k, v in row.items() if k in fieldmap}


def iso(v):
    return v.isoformat() if isinstance(v, (dt.datetime, dt.date)) else v


# ----------------------------------------------------------------- meta
@app.get("/healthz")
def healthz():
    meta = {r["key"]: r["value"] for r in db.q("SELECT key, value FROM world_meta")}
    return {"status": "ok", "world": meta, "auth_mode": AUTH_MODE,
            "lenses": [r["id"] for r in db.q("SELECT id FROM lens ORDER BY id")]}


@app.get("/_lens/{lens_id}")
def lens_info(lens_id: str):
    """Not a vendor endpoint. Feeds Control Center surface 3."""
    try:
        return {"lens": lens_id, **lenses.coverage_note(lens_id),
                "world_now": lenses.world_now().isoformat(),
                "visible_now_until": lenses.horizon(lens_id).isoformat()}
    except KeyError:
        raise HTTPException(404, "no such lens")


@app.get("/_provenance")
def provenance_all():
    """Not a vendor endpoint. Where each response shape came from, and whether that
    is evidence. DESIGN.md §5: twins built from imagination are marked unverified."""
    out = {}
    for lens_id, e in PROVENANCE.items():
        out[lens_id] = {**e, "status": provenance_status(e)}
    unverified = [k for k, v in out.items() if v["status"] == "unverified"]
    return {"lenses": out, "unverified": unverified,
            "certified": not unverified,
            "warning": ("No twin here is verified against a vendor artefact. Passing "
                        "tests demonstrate the kit agrees with this environment, not "
                        "that either agrees with the vendor.") if unverified else None}


@app.get("/_provenance/{lens_id}")
def provenance_one(lens_id: str):
    e = PROVENANCE.get(lens_id)
    if not e:
        raise HTTPException(404, "no such lens")
    return {**e, "status": provenance_status(e)}


# ================================================================= ServiceNow
# Pattern: generic table API, offset pagination, customer-defined field names.
SNOW = "/servicenow/api/now/table"


@app.get(SNOW + "/{table}")
def snow_table(table: str,
               sysparm_limit: int = Query(100, le=1000),
               sysparm_offset: int = 0,
               sysparm_query: Optional[str] = None,
               x_vo_profile: Optional[str] = Header(None),
               authorization: Optional[str] = Header(None)):
    require_token(authorization)
    prof = profile_for("servicenow", x_vo_profile)
    spec = PROFILES["servicenow"][prof].get(table)
    if not spec:
        raise HTTPException(404, f"no such table: {table}")
    fm = spec["fields"]
    hz, fl = lenses.horizon("servicenow"), lenses.floor("servicenow")

    if table == "incident":
        sev_map = {int(k): v for k, v in spec["severity_values"].items()}
        rows = db.q("""SELECT ref, title, category, severity, opened_at, closed_at,
                              service_id, stated_impact
                         FROM incident
                        WHERE opened_at <= %s AND opened_at >= %s
                        ORDER BY opened_at DESC, ref
                        LIMIT %s OFFSET %s""", (hz, fl, sysparm_limit, sysparm_offset))
        total = db.one("""SELECT count(*) n FROM incident
                           WHERE opened_at <= %s AND opened_at >= %s""", (hz, fl))["n"]
        out = [shape({"ref": r["ref"], "title": r["title"], "category": r["category"],
                      "severity": sev_map[r["severity"]], "opened": iso(r["opened_at"]),
                      "closed": iso(r["closed_at"]), "service": r["service_id"],
                      "impact": r["stated_impact"]}, fm) for r in rows]

    elif table == "cmdb_ci_computer":
        vis = lenses.visible_ids("servicenow", "asset")
        rows = db.q("""SELECT a.id, a.hostname, a.fqdn, a.ip, a.os_family, a.os_version,
                              a.criticality, p.full_name AS owner
                         FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
                        WHERE a.decommissioned_on IS NULL
                        ORDER BY a.id""")
        rows = [r for r in rows if r["id"] in vis]            # <- coverage loss
        total = len(rows)
        page = rows[sysparm_offset:sysparm_offset + sysparm_limit]
        out = [shape({"ref": vis[r["id"]]["external_id"],     # <- naming loss
                      "fqdn": r["fqdn"], "ip": str(r["ip"]),
                      "os": r["os_family"], "os_version": r["os_version"],
                      "owner": r["owner"], "criticality": r["criticality"],
                      "updated": iso(vis[r["id"]]["last_seen"])}, fm) for r in page]
    elif table == "cmdb_ci_appl":
        vis = lenses.visible_ids("servicenow", "application")
        rows = db.q("""SELECT a.id, a.name, a.criticality, p.full_name AS owner
                         FROM application a LEFT JOIN person p ON p.id = a.owner_person_id
                        ORDER BY a.id""")
        rows = [r for r in rows if r["id"] in vis]        # <- coverage loss
        total = len(rows)
        page = rows[sysparm_offset:sysparm_offset + sysparm_limit]
        out = [shape({"ref": vis[r["id"]]["external_id"],  # <- the CMDB names CIs by name
                      "criticality": r["criticality"], "owner": r["owner"],
                      "updated": iso(vis[r["id"]]["last_seen"])}, fm) for r in page]

    elif table == "cmdb_ci_service":
        vis = lenses.visible_ids("servicenow", "business_service")
        rows = db.q("""SELECT s.id, s.name, s.criticality, p.full_name AS owner
                         FROM business_service s LEFT JOIN person p ON p.id = s.owner_person_id
                        ORDER BY s.id""")
        rows = [r for r in rows if r["id"] in vis]
        total = len(rows)
        page = rows[sysparm_offset:sysparm_offset + sysparm_limit]
        out = [shape({"ref": vis[r["id"]]["external_id"],
                      "tier": r["criticality"], "owner": r["owner"],
                      "updated": iso(vis[r["id"]]["last_seen"])}, fm) for r in page]

    elif table == "cmdb_ci_business_process":
        vis = lenses.visible_ids("servicenow", "business_process")
        rows = db.q("""SELECT b.id, b.name, b.criticality, b.rto_hours,
                              p.full_name AS owner
                         FROM business_process b
                         LEFT JOIN person p ON p.id = b.owner_person_id
                        ORDER BY b.id""")
        rows = [r for r in rows if r["id"] in vis]
        total = len(rows)
        page = rows[sysparm_offset:sysparm_offset + sysparm_limit]
        out = [shape({"ref": vis[r["id"]]["external_id"], "criticality": r["criticality"],
                      "rto": str(r["rto_hours"]), "owner": r["owner"],
                      "updated": iso(vis[r["id"]]["last_seen"])}, fm) for r in page]

    elif table == "cmdb_sam_sw_install":
        vis = lenses.visible_ids("servicenow", "asset")
        rows = db.q("""SELECT i.asset_id, s.name, s.publisher, s.version, s.eol_on,
                              i.installed_on
                         FROM software_install i JOIN software s ON s.id = i.software_id
                         JOIN asset a ON a.id = i.asset_id
                        WHERE a.decommissioned_on IS NULL
                        ORDER BY i.asset_id, s.name""")
        rows = [r for r in rows if r["asset_id"] in vis]
        total = len(rows)
        page = rows[sysparm_offset:sysparm_offset + sysparm_limit]
        out = [shape({"ref": vis[r["asset_id"]]["external_id"], "name": r["name"],
                      "publisher": r["publisher"], "version": r["version"],
                      "installed": iso(r["installed_on"])}, fm) for r in page]

    elif table == "cmdb_rel_ci":
        # The relationship table is what makes service -> app -> asset traversable.
        # Both ends are named exactly as the CI tables name them, so a connector can
        # join on the strings it already has: services and apps by name, computers by
        # FQDN. A relationship is only returned when BOTH ends are visible to this
        # lens — an edge to a CI the CMDB cannot see would be a dangling reference.
        svc = lenses.visible_ids("servicenow", "business_service")
        app_ = lenses.visible_ids("servicenow", "application")
        ast = lenses.visible_ids("servicenow", "asset")
        rels = []
        for d in db.q("""SELECT service_id, application_id FROM service_dependency
                          ORDER BY service_id, application_id"""):
            if d["service_id"] in svc and d["application_id"] in app_:
                rels.append({"parent": svc[d["service_id"]]["external_id"],
                             "child": app_[d["application_id"]]["external_id"],
                             "type": "Depends on::Used by"})
        # decommissioned assets are withheld by cmdb_ci_computer, so an edge to one
        # would dangle against the very table a connector joins to
        prc = lenses.visible_ids("servicenow", "business_process")
        for d in db.q("""SELECT process_id, service_id FROM process_service
                          ORDER BY process_id, service_id"""):
            if d["process_id"] in prc and d["service_id"] in svc:
                rels.append({"parent": prc[d["process_id"]]["external_id"],
                             "child": svc[d["service_id"]]["external_id"],
                             "type": "Depends on::Used by"})
        for x in db.q("""SELECT x.application_id, x.asset_id
                           FROM application_asset x JOIN asset a ON a.id = x.asset_id
                          WHERE a.decommissioned_on IS NULL
                          ORDER BY x.application_id, x.asset_id"""):
            if x["application_id"] in app_ and x["asset_id"] in ast:
                rels.append({"parent": app_[x["application_id"]]["external_id"],
                             "child": ast[x["asset_id"]]["external_id"],
                             "type": "Runs on::Runs"})
        total = len(rels)
        out = [shape(r, fm) for r in rels[sysparm_offset:sysparm_offset + sysparm_limit]]

    else:
        raise HTTPException(404, f"no such table: {table}")

    return JSONResponse({"result": out},
                        headers={"X-Total-Count": str(total), "X-VO-Profile": prof})


# ===================================================================== Splunk
# Pattern: asynchronous search job. Submit -> poll -> fetch. (DESIGN.md §6)
_JOBS: dict = {}
SPL = "/splunk/services/search/jobs"


@app.post(SPL)
async def splunk_create_job(request: Request, authorization: Optional[str] = Header(None)):
    require_token(authorization)
    form = await request.form()
    search = (form.get("search") or "").strip()
    if not search:
        raise HTTPException(400, "search is required")
    sid = uuid.uuid4().hex[:16]
    _JOBS[sid] = {"search": search, "polls": 0, "created": dt.datetime.now(dt.timezone.utc)}
    return JSONResponse({"sid": sid}, status_code=201)


@app.get(SPL + "/{sid}")
def splunk_job_status(sid: str, authorization: Optional[str] = Header(None)):
    require_token(authorization)
    job = _JOBS.get(sid)
    if not job:
        raise HTTPException(404, "unknown sid")           # expired job -> connector must resubmit
    job["polls"] += 1
    done = job["polls"] >= 2                              # never ready on the first poll
    return {"entry": [{"name": sid, "content": {
        "dispatchState": "DONE" if done else "RUNNING",
        "isDone": done, "doneProgress": 1.0 if done else 0.45,
        "resultCount": _count(job) if done else 0}}]}


def _rule_filter(search: str):
    if "rule=" in search:
        return search.split("rule=", 1)[1].split()[0].strip('"')
    return None


def _count(job):
    hz, fl = lenses.horizon("splunk"), lenses.floor("splunk")
    rule = _rule_filter(job["search"])
    sql = """SELECT count(*) n FROM alert a
              WHERE a.occurred_at <= %s AND a.occurred_at >= %s
                AND a.asset_id IN (SELECT entity_id FROM lens_visibility
                                    WHERE lens_id='splunk' AND entity_kind='asset')"""
    params = [hz, fl]
    if rule:
        sql += " AND a.rule_id = %s"
        params.append(rule)
    return db.one(sql, tuple(params))["n"]


@app.get(SPL + "/{sid}/results")
def splunk_job_results(sid: str, offset: int = 0, count: int = Query(100, le=5000),
                       authorization: Optional[str] = Header(None)):
    require_token(authorization)
    job = _JOBS.get(sid)
    if not job:
        raise HTTPException(404, "unknown sid")
    if job["polls"] < 2:
        raise HTTPException(204, "job not finished")
    hz, fl = lenses.horizon("splunk"), lenses.floor("splunk")
    rule = _rule_filter(job["search"])
    sql = """SELECT a.id, a.severity, a.occurred_at, r.name AS rule_name, a.rule_id,
                    v.external_id AS host, p.email AS user_email
               FROM alert a
               JOIN detection_rule r ON r.id = a.rule_id
               JOIN lens_visibility v ON v.entity_id = a.asset_id
                    AND v.lens_id = 'splunk' AND v.entity_kind = 'asset'
               LEFT JOIN person p ON p.id = a.person_id
              WHERE a.occurred_at <= %s AND a.occurred_at >= %s"""
    params = [hz, fl]
    if rule:
        sql += " AND a.rule_id = %s"
        params.append(rule)
    sql += " ORDER BY a.occurred_at DESC, a.id LIMIT %s OFFSET %s"
    params += [count, offset]
    rows = db.q(sql, tuple(params))
    results = [{"_time": iso(r["occurred_at"]), "signature": r["rule_name"],
                "rule_id": r["rule_id"], "severity": r["severity"],
                "host": r["host"],                        # <- Splunk names assets by IP
                "user": r["user_email"], "event_id": r["id"]} for r in rows]
    return {"init_offset": offset, "post_process_count": 0,
            "preview": False, "results": results}


# ========================================================================= HR
# Pattern: page / per_page with a total_pages envelope. The system of record for
# employees — and, by design, blind to everyone engaged through an agency.
HR = "/hr/api/v1"


@app.get(HR + "/workers")
def hr_workers(page: int = 1, per_page: int = Query(100, le=1000),
               active: Optional[bool] = None,
               authorization: Optional[str] = Header(None)):
    require_token(authorization)
    vis = lenses.visible_ids("hr", "person")
    rows = db.q("""SELECT p.id, p.full_name, p.email, p.title, p.employment,
                          p.started_on, p.ended_on, d.cost_center, d.name AS department
                     FROM person p JOIN department d ON d.id = p.department_id
                    ORDER BY p.id""")
    rows = [r for r in rows if r["id"] in vis]
    if active is not None:
        rows = [r for r in rows if (r["ended_on"] is None) == active]
    total = len(rows)
    pages = max(1, -(-total // per_page))
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    out = []
    for r in rows[start:start + per_page]:
        first, _, last = r["full_name"].partition(" ")
        out.append({
            "employee_id": vis[r["id"]]["external_id"],   # <- HR names people by staff number
            "legal_name": {"first": first, "last": last},
            "primary_work_email": r["email"],
            "worker_type": "Employee",
            "job_title": r["title"],
            "cost_center": r["cost_center"],
            "organization": r["department"],
            "hire_date": iso(r["started_on"]),
            "termination_date": iso(r["ended_on"]),      # HR always knows
            "active": r["ended_on"] is None,
        })
    return {"workers": out, "page": page, "per_page": per_page,
            "total_pages": pages, "total": total}


# ======================================================================== EDR
# Pattern: query for ids, then hydrate them in a second call. Common, and the place
# a connector most often forgets that the id list and the detail call page
# differently. (DESIGN.md §5)
EDR = "/edr/devices"


def _edr_rows():
    vis = lenses.visible_ids("edr", "asset")
    rows = db.q("""SELECT a.id, a.hostname, a.os_family, a.os_version, a.kind
                     FROM asset a WHERE a.decommissioned_on IS NULL ORDER BY a.id""")
    return [(r, vis[r["id"]]) for r in rows if r["id"] in vis]


@app.get(EDR + "/queries/devices/v1")
def edr_query(limit: int = Query(100, le=5000), offset: int = 0,
              authorization: Optional[str] = Header(None)):
    """Step 1 of 2 — ids only. No device detail is returned here, by design."""
    require_token(authorization)
    rows = _edr_rows()
    ids = [v["external_id"] for _, v in rows]
    page = ids[offset:offset + limit]
    return {"resources": page,
            "meta": {"pagination": {"offset": offset, "limit": limit,
                                    "total": len(ids)}}}


@app.post(EDR + "/entities/devices/v2")
async def edr_hydrate(request: Request, authorization: Optional[str] = Header(None)):
    """Step 2 of 2 — hydrate ids from step 1. Unknown ids are silently absent from
    the response rather than raising, exactly as a real bulk endpoint behaves."""
    require_token(authorization)
    body = await request.json()
    want = set(body.get("ids") or [])
    if not want:
        raise HTTPException(400, "ids is required")
    now = lenses.world_now()
    out = []
    for r, v in _edr_rows():
        if v["external_id"] not in want:
            continue
        silent_days = (now - v["last_seen"]).days
        out.append({
            "device_id": v["external_id"],               # <- the EDR names by agent id
            "hostname": r["hostname"],                   # <- and also carries the short name
            "platform_name": r["os_family"],
            "os_version": r["os_version"],
            "agent_version": "7.16.18604.0",
            "first_seen": iso(now - dt.timedelta(days=400)),
            "last_seen": iso(v["last_seen"]),
            "status": "silent" if silent_days >= 7 else "normal",
        })
    return {"resources": out,
            "meta": {"pagination": {"total": len(out)}},
            "errors": []}


# ======================================================================== IAM
# Pattern: Link-header pagination (Okta-shaped). The next page is a URL the server
# hands you in a header — construct one yourself and you will drift. (DESIGN.md §5)
IAM = "/iam/api/v1"


def _severity_role(privileged):
    return ["SUPER_ADMIN"] if privileged else ["USER"]


def _iam_rows():
    """Only accounts federated to the IdP. AD-only accounts are the blind spot."""
    vis = lenses.visible_ids("iam", "person")
    rows = db.q("""SELECT p.id, p.full_name, p.email, p.started_on, p.ended_on,
                          a.username, a.created_on, a.disabled_on, a.privileged
                     FROM person p
                     JOIN account a ON a.person_id = p.id AND a.system = 'okta'
                    ORDER BY p.id""")
    return [(r, vis[r["id"]]) for r in rows if r["id"] in vis]


def _iam_user(r, v):
    first, _, last = r["full_name"].partition(" ")
    return {
        "id": v["external_id"],                       # <- the IdP names people by login
        "status": "DEPROVISIONED" if r["disabled_on"] else "ACTIVE",
        "created": iso(r["created_on"]),
        "lastUpdated": iso(v["last_seen"]),
        "profile": {
            "login": v["external_id"], "email": r["email"],
            "firstName": first, "lastName": last,
            # Written by the deprovisioning workflow, not by HR directly. When that
            # workflow never ran, the account stays ACTIVE *and* carries no
            # termination date — so the leaver signal has to come from HR, and
            # finding orphaned access becomes a genuine cross-source join.
            "terminationDate": iso(r["ended_on"]) if r["disabled_on"] else None,
            "userType": "privileged" if r["privileged"] else "standard",
        },
    }


@app.get(IAM + "/users")
def iam_users(limit: int = Query(200, le=1000), after: Optional[str] = None,
              filter: Optional[str] = None, request: Request = None,
              authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = _iam_rows()
    users = [_iam_user(r, v) for r, v in rows]
    if filter:                                        # Okta-style: status eq "ACTIVE"
        want = filter.split("eq", 1)[-1].strip().strip('"') if "eq" in filter else None
        if want:
            users = [u for u in users if u["status"] == want]
    start = _decode(after)
    page = users[start:start + limit]
    headers = {"X-Total-Count": str(len(users))}
    links = [f'<{IAM}/users?limit={limit}&after={_encode(start)}>; rel="self"']
    if start + limit < len(users):
        links.append(f'<{IAM}/users?limit={limit}&after={_encode(start + limit)}>; rel="next"')
    headers["Link"] = ", ".join(links)
    return JSONResponse(page, headers=headers)


@app.get(IAM + "/groups")
def iam_groups(authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT g.id, g.name, g.system, g.privileged,
                          count(m.account_id) FILTER (WHERE m.revoked_on IS NULL) AS members
                     FROM access_group g
                     LEFT JOIN group_membership m ON m.group_id = g.id
                    WHERE g.system = 'okta'
                    GROUP BY g.id, g.name, g.system, g.privileged ORDER BY g.name""")
    return [{"id": r["id"], "profile": {"name": r["name"],
             "description": "privileged" if r["privileged"] else "standard"},
             "type": "OKTA_GROUP", "_embedded": {"stats": {"usersCount": r["members"]}}}
            for r in rows]


@app.get(IAM + "/users/{login}/groups")
def iam_user_groups(login: str, authorization: Optional[str] = Header(None)):
    """Membership as the directory holds it — including memberships never revoked
    after the person left, which the directory has no opinion about."""
    require_token(authorization)
    rows = db.q("""SELECT g.id, g.name, g.privileged, m.granted_on, m.revoked_on
                     FROM group_membership m
                     JOIN access_group g ON g.id = m.group_id
                     JOIN account a ON a.id = m.account_id
                    WHERE a.system = 'okta' AND a.username = %s
                    ORDER BY g.name""", (login,))
    return [{"id": r["id"], "profile": {"name": r["name"],
             "description": "privileged" if r["privileged"] else "standard"},
             "granted": iso(r["granted_on"]), "revoked": iso(r["revoked_on"]),
             "active": r["revoked_on"] is None} for r in rows]


@app.get(IAM + "/users/{login}")
def iam_user(login: str, authorization: Optional[str] = Header(None)):
    require_token(authorization)
    for r, v in _iam_rows():
        if v["external_id"] == login:
            u = _iam_user(r, v)
            u["roles"] = _severity_role(r["privileged"])
            return u
    raise HTTPException(404, "user not found")


# ==================================================================== SCANNER
# Pattern: incremental polling by `since`. Records arrive late and backdated — a
# finding fixed last month re-enters the feed with an old first_found. (DESIGN.md §5)
SCAN = "/scanner/api/v3"


def _sev(cvss):
    c = float(cvss)
    return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"


@app.get(SCAN + "/findings")
def scanner_findings(since: Optional[str] = None, limit: int = Query(500, le=5000),
                     state: Optional[str] = None,
                     authorization: Optional[str] = Header(None)):
    require_token(authorization)
    hz, fl = lenses.horizon("scanner"), lenses.floor("scanner")
    rows = db.q("""SELECT v.id, v.cve, v.cvss, v.discovered_on, v.remediated_on,
                          lv.external_id AS host, lv.last_seen
                     FROM vulnerability v
                     JOIN asset a ON a.id = v.asset_id
                     JOIN lens_visibility lv ON lv.entity_id = v.asset_id
                          AND lv.lens_id = 'scanner' AND lv.entity_kind = 'asset'
                    WHERE a.decommissioned_on IS NULL""")
    out = []
    for r in rows:
        # A finding is last confirmed either when it was fixed, or at the last scan
        # of the host that still carried it.
        last = (dt.datetime.combine(r["remediated_on"], dt.time(9, 0), tzinfo=dt.timezone.utc)
                if r["remediated_on"] else r["last_seen"])
        if last > hz or last < fl:
            continue                                  # sync horizon and retention
        st = "FIXED" if r["remediated_on"] else "OPEN"
        if state and st != state.upper():
            continue
        out.append({"finding_id": r["id"], "cve": r["cve"], "cvss": float(r["cvss"]),
                    "severity": _sev(r["cvss"]), "state": st,
                    "asset": {"hostname": r["host"]},  # <- the scanner names by hostname
                    "first_found": iso(r["discovered_on"]), "last_found": iso(last)})
    out.sort(key=lambda x: (x["last_found"], x["finding_id"]))
    if since:
        try:
            cut = dt.datetime.fromisoformat(since)
        except ValueError:
            raise HTTPException(400, "since must be ISO-8601")
        if cut.tzinfo is None:
            cut = cut.replace(tzinfo=dt.timezone.utc)
        out = [f for f in out if dt.datetime.fromisoformat(f["last_found"]) > cut]
    page = out[:limit]
    return {"findings": page, "has_more": len(out) > limit,
            "next_since": page[-1]["last_found"] if page else since}


@app.get(SCAN + "/misconfigurations")
def scanner_misconfigs(since: Optional[str] = None, limit: int = Query(500, le=5000),
                       state: Optional[str] = None,
                       authorization: Optional[str] = Header(None)):
    """Baseline drift, on the same incremental contract as findings."""
    require_token(authorization)
    hz, fl = lenses.horizon("scanner"), lenses.floor("scanner")
    rows = db.q("""SELECT m.id, m.baseline_ref, m.title, m.severity, m.detected_on,
                          m.remediated_on, lv.external_id AS host, lv.last_seen
                     FROM misconfiguration m
                     JOIN asset a ON a.id = m.asset_id
                     JOIN lens_visibility lv ON lv.entity_id = m.asset_id
                          AND lv.lens_id = 'scanner' AND lv.entity_kind = 'asset'
                    WHERE a.decommissioned_on IS NULL""")
    out = []
    for r in rows:
        last = (dt.datetime.combine(r["remediated_on"], dt.time(9, 0), tzinfo=dt.timezone.utc)
                if r["remediated_on"] else r["last_seen"])
        if last > hz or last < fl:
            continue
        st = "RESOLVED" if r["remediated_on"] else "OPEN"
        if state and st != state.upper():
            continue
        out.append({"misconfiguration_id": r["id"], "baseline": r["baseline_ref"],
                    "title": r["title"], "severity": r["severity"], "state": st,
                    "asset": {"hostname": r["host"]},
                    "first_detected": iso(r["detected_on"]), "last_seen": iso(last)})
    out.sort(key=lambda x: (x["last_seen"], x["misconfiguration_id"]))
    if since:
        try:
            cut = dt.datetime.fromisoformat(since)
        except ValueError:
            raise HTTPException(400, "since must be ISO-8601")
        if cut.tzinfo is None:
            cut = cut.replace(tzinfo=dt.timezone.utc)
        out = [f for f in out if dt.datetime.fromisoformat(f["last_seen"]) > cut]
    page = out[:limit]
    return {"misconfigurations": page, "has_more": len(out) > limit,
            "next_since": page[-1]["last_seen"] if page else since}


@app.get(SCAN + "/assets")
def scanner_assets(limit: int = Query(500, le=5000), offset: int = 0,
                   authorization: Optional[str] = Header(None)):
    require_token(authorization)
    vis = lenses.visible_ids("scanner", "asset")
    rows = db.q("""SELECT a.id, a.os_family, a.os_version, a.kind
                     FROM asset a WHERE a.decommissioned_on IS NULL ORDER BY a.id""")
    rows = [r for r in rows if r["id"] in vis]
    page = rows[offset:offset + limit]
    return {"assets": [{"hostname": vis[r["id"]]["external_id"],
                        "operating_system": f'{r["os_family"]} {r["os_version"]}',
                        "kind": r["kind"],
                        "last_scanned": iso(vis[r["id"]]["last_seen"])} for r in page],
            "total": len(rows)}


# ======================================================================== GRC
# Pattern: cursor pagination over governance objects.
GRC = "/grc/api/v1"


def _encode(o: int) -> str:
    return base64.urlsafe_b64encode(str(o).encode()).decode().rstrip("=")


def _decode(c: Optional[str]) -> int:
    if not c:
        return 0
    pad = "=" * (-len(c) % 4)
    try:
        return int(base64.urlsafe_b64decode(c + pad).decode())
    except Exception:
        raise HTTPException(400, "malformed cursor")


def _page(rows, cursor, limit, key="items"):
    start = _decode(cursor)
    page = rows[start:start + limit]
    nxt = _encode(start + limit) if start + limit < len(rows) else None
    return {key: page, "next_cursor": nxt, "total": len(rows)}


@app.get(GRC + "/controls")
def grc_controls(cursor: Optional[str] = None, limit: int = Query(50, le=500),
                 authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT c.ref, c.title, c.test_frequency, c.automated,
                          p.full_name AS owner_name, p.ended_on AS owner_left_on,
                          t.tested_on AS last_tested_on, t.result AS last_result
                     FROM control c
                     LEFT JOIN person p ON p.id = c.owner_person_id
                     LEFT JOIN LATERAL (
                          SELECT tested_on, result FROM control_test
                           WHERE control_id = c.id ORDER BY tested_on DESC LIMIT 1) t ON true
                    ORDER BY c.ref""")
    items = [{"reference": r["ref"], "title": r["title"],
              "test_frequency": r["test_frequency"], "automated": r["automated"],
              "owner": r["owner_name"],
              # the GRC platform does not know the owner has left. That is the point.
              "last_tested_on": iso(r["last_tested_on"]),
              "effectiveness": r["last_result"] or "not_assessed"} for r in rows]
    return _page(items, cursor, limit)


@app.get(GRC + "/findings")
def grc_findings(status: Optional[str] = None, cursor: Optional[str] = None,
                 limit: int = Query(50, le=500), authorization: Optional[str] = Header(None)):
    require_token(authorization)
    sql = """SELECT f.id, f.title, f.severity, f.raised_on, f.due_on, f.closed_on,
                    f.status, c.ref AS control_ref
               FROM finding f JOIN control c ON c.id = f.control_id"""
    params = []
    if status:
        sql += " WHERE f.status = %s"
        params.append(status)
    sql += " ORDER BY f.raised_on DESC, f.id"
    rows = db.q(sql, tuple(params))
    items = [{"id": r["id"], "title": r["title"], "severity": r["severity"],
              "control_reference": r["control_ref"], "raised_on": iso(r["raised_on"]),
              "due_on": iso(r["due_on"]), "closed_on": iso(r["closed_on"]),
              "status": r["status"]} for r in rows]
    return _page(items, cursor, limit)


@app.get(GRC + "/risks")
def grc_risks(cursor: Optional[str] = None, limit: int = Query(50, le=500),
              authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT r.ref, r.title, r.category, r.inherent_score, r.appetite,
                          r.last_reviewed_on, r.review_period_days, p.full_name AS owner
                     FROM risk r LEFT JOIN person p ON p.id = r.owner_person_id
                    ORDER BY r.ref""")
    items = [{"reference": r["ref"], "title": r["title"], "category": r["category"],
              "inherent_score": float(r["inherent_score"]),
              "appetite": float(r["appetite"]), "owner": r["owner"],
              "last_reviewed_on": iso(r["last_reviewed_on"]),
              # "current" is asserted by the platform, not verified. Conflict fodder.
              "review_status": "current",
              "review_period_days": r["review_period_days"]} for r in rows]
    return _page(items, cursor, limit)


@app.get(GRC + "/assets")
def grc_assets(cursor: Optional[str] = None, limit: int = Query(200, le=1000),
               authorization: Optional[str] = Header(None)):
    """The third identifier style. GRC calls the same machine by its asset tag.

    NOTE: lens.blind_spot for this lens reads "anything without a control owner",
    but the generator grants it coverage 1.00 over every asset. This endpoint is
    faithful to lens_visibility as generated, not to the blind_spot string. See
    README "Known gaps".
    """
    require_token(authorization)
    vis = lenses.visible_ids("grc", "asset")
    rows = db.q("""SELECT a.id, a.kind, a.criticality, a.os_family,
                          p.full_name AS owner
                     FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
                    WHERE a.decommissioned_on IS NULL
                    ORDER BY a.id""")
    rows = [r for r in rows if r["id"] in vis]
    items = [{"asset_tag": vis[r["id"]]["external_id"],   # <- GRC names assets by asset tag
              "kind": r["kind"], "criticality": r["criticality"],
              "platform": r["os_family"], "owner": r["owner"],
              "last_synced": iso(vis[r["id"]]["last_seen"])} for r in rows]
    return _page(items, cursor, limit)


@app.get(GRC + "/policies")
def grc_policies(cursor: Optional[str] = None, limit: int = Query(50, le=500),
                 authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT p.ref, p.title, p.approved_on, p.review_period_days,
                          q.full_name AS owner,
                          (SELECT count(*) FROM policy_control pc
                            WHERE pc.policy_id = p.id) AS control_count
                     FROM policy p LEFT JOIN person q ON q.id = p.owner_person_id
                    ORDER BY p.ref""")
    return _page([{"reference": r["ref"], "title": r["title"], "owner": r["owner"],
                   "approved_on": iso(r["approved_on"]),
                   "review_period_days": r["review_period_days"],
                   "implementing_controls": r["control_count"]} for r in rows], cursor, limit)


@app.get(GRC + "/exceptions")
def grc_exceptions(status: Optional[str] = None, cursor: Optional[str] = None,
                   limit: int = Query(50, le=500),
                   authorization: Optional[str] = Header(None)):
    """`status` is what the platform asserts, not what the calendar says. An exception
    can read `active` with an expiry date months in the past."""
    require_token(authorization)
    sql = """SELECT e.id, e.reason, e.approved_on, e.expires_on, e.status,
                    c.ref AS control_ref, p.full_name AS approved_by
               FROM control_exception e
               JOIN control c ON c.id = e.control_id
               LEFT JOIN person p ON p.id = e.approved_by"""
    params = []
    if status:
        sql += " WHERE e.status = %s"
        params.append(status)
    sql += " ORDER BY e.id"
    rows = db.q(sql, tuple(params))
    return _page([{"id": r["id"], "control_reference": r["control_ref"],
                   "reason": r["reason"], "approved_by": r["approved_by"],
                   "approved_on": iso(r["approved_on"]),
                   "expires_on": iso(r["expires_on"]), "status": r["status"]}
                  for r in rows], cursor, limit)


@app.get(GRC + "/treatments")
def grc_treatments(status: Optional[str] = None, cursor: Optional[str] = None,
                   limit: int = Query(50, le=500),
                   authorization: Optional[str] = Header(None)):
    require_token(authorization)
    sql = """SELECT t.id, t.strategy, t.description, t.target_date, t.completed_on,
                    t.status, r.ref AS risk_ref, p.full_name AS owner
               FROM risk_treatment t
               JOIN risk r ON r.id = t.risk_id
               LEFT JOIN person p ON p.id = t.owner_person_id"""
    params = []
    if status:
        sql += " WHERE t.status = %s"
        params.append(status)
    sql += " ORDER BY t.id"
    rows = db.q(sql, tuple(params))
    return _page([{"id": r["id"], "risk_reference": r["risk_ref"],
                   "strategy": r["strategy"], "description": r["description"],
                   "owner": r["owner"], "target_date": iso(r["target_date"]),
                   "completed_on": iso(r["completed_on"]), "status": r["status"]}
                  for r in rows], cursor, limit)


# --- framework / taxonomy sync (DESIGN.md §5) -------------------------------
@app.get(GRC + "/frameworks")
def grc_frameworks(authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT f.id, f.name, f.version, count(q.id) AS requirement_count
                     FROM framework f LEFT JOIN requirement q ON q.framework_id = f.id
                    GROUP BY f.id, f.name, f.version ORDER BY f.name""")
    return {"frameworks": [{"id": r["id"], "name": r["name"], "version": r["version"],
                            "requirement_count": r["requirement_count"]} for r in rows]}


@app.get(GRC + "/requirements")
def grc_requirements(framework: Optional[str] = None, cursor: Optional[str] = None,
                     limit: int = Query(200, le=1000),
                     authorization: Optional[str] = Header(None)):
    require_token(authorization)
    sql = """SELECT q.ref, q.title, f.name AS framework, f.version
               FROM requirement q JOIN framework f ON f.id = q.framework_id"""
    params = []
    if framework:
        sql += " WHERE f.name = %s"
        params.append(framework)
    sql += " ORDER BY f.name, q.ref"
    rows = db.q(sql, tuple(params))
    return _page([{"reference": r["ref"], "title": r["title"],
                   "framework": r["framework"], "framework_version": r["version"]}
                  for r in rows], cursor, limit)


@app.get(GRC + "/crosswalks")
def grc_crosswalks(cursor: Optional[str] = None, limit: int = Query(200, le=1000),
                   authorization: Optional[str] = Header(None)):
    """Equivalence between two frameworks' requirements — and it is mostly partial.
    A control failure therefore moves ISO and CSF by different amounts, which is the
    difference between computing a number and being able to explain it. (§4.2)"""
    require_token(authorization)
    rows = db.q("""SELECT sq.ref AS source_ref, sf.name AS source_framework,
                          tq.ref AS target_ref, tf.name AS target_framework,
                          x.equivalence
                     FROM requirement_crosswalk x
                     JOIN requirement sq ON sq.id = x.source_requirement_id
                     JOIN framework sf ON sf.id = sq.framework_id
                     JOIN requirement tq ON tq.id = x.target_requirement_id
                     JOIN framework tf ON tf.id = tq.framework_id
                    ORDER BY sq.ref, tq.ref""")
    return _page([{"source_framework": r["source_framework"], "source_reference": r["source_ref"],
                   "target_framework": r["target_framework"], "target_reference": r["target_ref"],
                   "equivalence": float(r["equivalence"])} for r in rows], cursor, limit)


# --- binary evidence retrieval (DESIGN.md §5) -------------------------------
MAX_DOWNLOAD_BYTES = 5_000_000
_SECRET = (sorted(STATIC_TOKENS)[0] if STATIC_TOKENS else "vo") + ":evidence"


def _download_token(attachment_id: str) -> str:
    """A second credential for the bytes, handed out with the metadata. Real GRC
    platforms gate attachment content separately from the record API; a connector
    that reuses its bearer token here gets a 403."""
    return hashlib.sha256(f"{attachment_id}:{_SECRET}".encode()).hexdigest()[:32]


@app.get(GRC + "/findings/{finding_id}/attachments")
def grc_attachments(finding_id: str, authorization: Optional[str] = Header(None)):
    require_token(authorization)
    rows = db.q("""SELECT id, filename, media_type, size_bytes, uploaded_on, sha256
                     FROM attachment WHERE finding_id = %s ORDER BY id""", (finding_id,))
    if not db.one("SELECT 1 AS x FROM finding WHERE id = %s", (finding_id,)):
        raise HTTPException(404, "no such finding")
    return {"attachments": [{
        "id": r["id"], "filename": r["filename"], "media_type": r["media_type"],
        "size_bytes": r["size_bytes"], "uploaded_on": iso(r["uploaded_on"]),
        "sha256": r["sha256"],
        "too_large_to_download": r["size_bytes"] > MAX_DOWNLOAD_BYTES,
        "content_url": f"{GRC}/attachments/{r['id']}/content",
        "download_token": _download_token(r["id"]),
    } for r in rows], "max_download_bytes": MAX_DOWNLOAD_BYTES}


@app.get(GRC + "/attachments/{attachment_id}/content")
def grc_attachment_content(attachment_id: str, token: Optional[str] = None,
                           authorization: Optional[str] = Header(None)):
    """Bytes, with the three things a connector must handle: a separate credential,
    a hard size limit, and a real Content-Type it did not choose."""
    require_token(authorization)
    a = db.one("""SELECT id, filename, media_type, size_bytes, sha256
                    FROM attachment WHERE id = %s""", (attachment_id,))
    if not a:
        raise HTTPException(404, "no such attachment")
    if token != _download_token(attachment_id):
        raise HTTPException(403, "content requires the download_token from the "
                                 "attachment metadata")
    if a["size_bytes"] > MAX_DOWNLOAD_BYTES:
        raise HTTPException(413, f"attachment is {a['size_bytes']} bytes; the download "
                                 f"limit is {MAX_DOWNLOAD_BYTES}")
    # Deterministic bytes: same attachment, same content, every run.
    header = {
        "text/plain": b"EVIDENCE MEMO\nfinding: ", "text/csv": b"user,system,reviewed_on\n",
        "application/pdf": b"%PDF-1.4\n% synthetic evidence\n",
        "image/png": b"\x89PNG\r\n\x1a\n",
    }.get(a["media_type"], b"")
    filler = hashlib.sha256(a["sha256"].encode()).digest()
    body = (header + (filler * (a["size_bytes"] // len(filler) + 1)))[:a["size_bytes"]]
    return Response(content=body, media_type=a["media_type"], headers={
        "Content-Length": str(a["size_bytes"]),
        "Content-Disposition": f'attachment; filename="{a["filename"]}"',
        "X-Content-SHA256": a["sha256"],
    })


@app.get(GRC + "/control-mappings")
def grc_mappings(framework: Optional[str] = None, cursor: Optional[str] = None,
                 limit: int = Query(200, le=1000),
                 authorization: Optional[str] = Header(None)):
    require_token(authorization)
    sql = """SELECT c.ref AS control_ref, q.ref AS requirement_ref,
                    q.title AS requirement_title, m.coverage, f.name AS framework
               FROM control_mapping m
               JOIN control c ON c.id = m.control_id
               JOIN requirement q ON q.id = m.requirement_id
               JOIN framework f ON f.id = q.framework_id"""
    params = []
    if framework:
        sql += " WHERE f.name = %s"
        params.append(framework)
    sql += " ORDER BY c.ref, q.ref"
    rows = db.q(sql, tuple(params))
    items = [{"control_reference": r["control_ref"], "framework": r["framework"],
              "requirement_reference": r["requirement_ref"],
              "requirement_title": r["requirement_title"],
              "coverage": float(r["coverage"])} for r in rows]   # <- strength, not boolean
    return _page(items, cursor, limit)
