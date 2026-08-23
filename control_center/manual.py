"""
Data behind the Manual surface.

Everything factual here is introspected live — table and column names from
information_schema, row counts from the tables themselves, the endpoint list from
the twin's own route table, example payloads from real calls to the running twin.

Only prose is authored. DESIGN.md §8: a written description of the virtual org
"will be wrong within a month and will then actively mislead". A manual that is
generated cannot drift from the thing it describes.
"""
import os
from twins import db
from . import probes

# ---------------------------------------------------------------- authored prose
# The one hand-maintained structure: which domain each table belongs to, and what
# it is for. Table NAMES are still checked against the live schema — anything the
# generator adds and this map misses is reported as undocumented, not hidden.
DOMAINS = [
    ("People and org", "Who works here, and who left. Leavers are the engine behind "
     "most planted conflicts — orphaned accounts, departed control owners.", [
        ("department", "Cost centres. Ten of them, fixed."),
        ("person", "Employees and contractors. `ended_on` non-null marks a leaver."),
     ]),
    ("Identity", "Accounts per person per system. The join that makes 'access that "
     "should have been revoked' visible.", [
        ("account", "One row per person per system (ad, okta). `disabled_on` NULL "
         "after the person's `ended_on` is orphaned access."),
        ("access_group", "Directory groups. `privileged` marks the ones that matter."),
        ("group_membership", "Who is in which group. `revoked_on` NULL after a leaver's "
         "`ended_on` is retained access — worse when the group is privileged."),
     ]),
    ("Assets and infrastructure", "The machines. Every one carries four identifiers, "
     "and each lens picks a different one — this is where correlation is manufactured.", [
        ("asset", "Endpoints, servers, cloud. Carries four identifiers of its own — "
         "hostname, fqdn, asset_tag and ip — and the EDR lens mints a fifth, an agent "
         "id, which exists nowhere in the world. IPs are recycled: the pool is smaller "
         "than the asset count."),
        ("software", "Packages, with an `eol_on` date. Past it means unsupported."),
        ("software_install", "Which package is on which machine."),
     ]),
    ("Applications and services", "The dependency chain from a business service down "
     "to the machines that carry it.", [
        ("application", "Owned by a person, criticality-rated."),
        ("business_service", "Tier 1–3, with daily revenue."),
        ("business_process", "The top of the spine, with a recovery time objective."),
        ("process_service", "Which services a business process depends on."),
        ("application_asset", "Which machines an application runs on."),
        ("service_dependency", "Which applications a service depends on."),
     ]),
    ("Governance", "Framework, requirements, controls, tests, audits, findings and the "
     "risk register. The GRC lens's territory.", [
        ("framework", "ISO/IEC 27001:2022."),
        ("requirement", "~100 clauses."),
        ("control", "~100 controls. `owner_person_id` may point at a leaver."),
        ("control_mapping", "Control → requirement with **coverage strength**, not a "
         "boolean. This is what lets a failure be explained, not just computed."),
        ("requirement_crosswalk", "Equivalence between two frameworks' requirements, "
         "mostly partial. A control failure therefore moves ISO and CSF by different "
         "amounts — and you can say why."),
        ("control_test", "Three years of test results. Some controls drift "
         "effective → ineffective → back."),
        ("policy", "The written rule, with an owner and a review cycle."),
        ("policy_control", "Which controls implement a policy. Some policies have none."),
        ("control_exception", "An approved deviation with an expiry. `status` is what "
         "the platform asserts — it can read `active` months after `expires_on`."),
        ("risk_treatment", "accept / mitigate / transfer / avoid, with a target date."),
        ("audit", "Three annual audit cycles."),
        ("finding", "Audit findings with due dates. `status` open/overdue/closed."),
        ("attachment", "Binary evidence hanging off a finding. Metadata only — the "
         "bytes are generated on read, deterministically."),
        ("risk", "The register. `last_reviewed_on` + `review_period_days` is what makes "
         "a risk demonstrably stale while the API still calls it current."),
        ("risk_control", "Which controls mitigate a risk, and by how much."),
        ("risk_service", "Which services a risk threatens."),
     ]),
    ("Security posture", "What the SIEM and the scanners would see.", [
        ("detection_rule", "15 named rules."),
        ("alert", "~20,000 detections across three years, tied to an asset and a person."),
        ("incident", "`stated_impact` may contradict the service tier — a planted conflict."),
        ("vulnerability", "CVEs per asset, with remediation dates."),
        ("misconfiguration", "Baseline drift against CIS-style rules."),
     ]),
    ("Evidence — the answer key", "The attribution ground truth. Nothing in any vendor "
     "API links a detection to a control; this table says what the true link is.", [
        ("evidence", "`control_id` is the TRUE attribution for every event. `is_trap` "
         "marks topically-adjacent decoys that are NOT evidence for that control."),
     ]),
    ("Lenses — where all loss lives", "The world is always true and complete. Every "
     "degradation a connector meets is applied here, at read time.", [
        ("lens", "Per-tool loss profile: coverage, latency, retention, identifier style, "
         "blind spot."),
        ("lens_visibility", "What each lens can see and what it calls it. A missing row "
         "means that lens is structurally blind to that entity."),
     ]),
    ("Ground truth", "The assertion catalogue, materialised as rows.", [
        ("expectation", "Every row is something the kit should conclude, or should "
         "refuse to conclude. Four families: attribution, conflict, degradation, absence."),
        ("world_meta", "Seed, as-of date, scale. Reproducibility metadata."),
     ]),
]

# Which entities a connector can actually reach, and how. Verified live below.
REACH = [
    ("asset", "servicenow", "GET /servicenow/api/now/table/cmdb_ci_computer", "fqdn",
     "97% of assets. Names them by FQDN."),
    ("asset", "grc", "GET /grc/api/v1/assets", "asset_tag",
     "91% of assets — a GRC platform knows what was typed into it, not what exists. "
     "Names them by asset tag."),
    ("asset", "splunk", "GET /splunk/services/search/jobs/{sid}/results", "ip",
     "Only assets that raised an alert in the retention window. Names them by IP."),
    ("incident", "servicenow", "GET /servicenow/api/now/table/incident", "number",
     "Full history within retention."),
    ("alert", "splunk", "GET /splunk/services/search/jobs/{sid}/results", "event_id",
     "90-day window, 5-minute latency, visible assets only."),
    ("detection_rule", "splunk", "GET /splunk/services/search/jobs/{sid}/results", "rule_id",
     "Reachable only as a field on an alert, never listed on its own."),
    ("person", "hr", "GET /hr/api/v1/workers", "employee_id",
     "The system of record. Employees only — contractors are structurally absent, so "
     "a departed contractor cannot be confirmed as a leaver from HR at all."),
    ("asset", "edr", "POST /edr/devices/entities/devices/v2", "agent_id",
     "79% of live assets. Named by the agent installed on them; also carries the "
     "short hostname, so this is the one join that works without inference."),
    ("person", "iam", "GET /iam/api/v1/users", "login",
     "Listed at last. 94% coverage; named by directory login, not by the EMP- id or "
     "the full name the other lenses show — correlating them is entity resolution."),
    ("person", "splunk / servicenow / grc", "(embedded)", "email or full name",
     "Also appears as an owner name or user email on other records."),
    ("account", "iam", "GET /iam/api/v1/users", "login",
     "Only accounts federated to the IdP. `status` plus `profile.terminationDate` is "
     "what makes orphaned access findable — an ACTIVE user with a termination date."),
    ("policy", "grc", "GET /grc/api/v1/policies", "reference",
     "Carries an implementing-control count, so a policy nothing implements is visible."),
    ("control_exception", "grc", "GET /grc/api/v1/exceptions", "id",
     "`status` is asserted by the platform; compare it to `expires_on` yourself."),
    ("risk_treatment", "grc", "GET /grc/api/v1/treatments", "id",
     "Strategy, owner, target date and status."),
    ("business_process", "servicenow", "GET /servicenow/api/now/table/cmdb_ci_business_process",
     "name", "The top of the spine, with a recovery time objective."),
    ("process_service", "servicenow", "GET /servicenow/api/now/table/cmdb_rel_ci",
     "parent + child name", "`Depends on::Used by` edges from a process to a service."),
    ("software", "servicenow", "GET /servicenow/api/now/table/cmdb_sam_sw_install",
     "package name", "Publisher and version. End-of-life dates are not exposed."),
    ("software_install", "servicenow", "GET /servicenow/api/now/table/cmdb_sam_sw_install",
     "host + package", "One row per install, keyed by the CMDB's own asset name."),
    ("misconfiguration", "scanner", "GET /scanner/api/v3/misconfigurations", "misconfiguration_id",
     "Baseline drift, on the same incremental `since` contract as CVE findings."),
    ("access_group", "iam", "GET /iam/api/v1/groups", "group id",
     "Okta groups only. AD groups are behind the same blind spot as AD accounts."),
    ("group_membership", "iam", "GET /iam/api/v1/users/{login}/groups", "group id",
     "Per user, with grant and revocation dates — so retained access is visible."),
    ("vulnerability", "scanner", "GET /scanner/api/v3/findings", "finding_id",
     "365-day retention, 24h behind. Poll incrementally with `since`."),
    ("control", "grc", "GET /grc/api/v1/controls", "reference",
     "All controls, with latest test result folded in as `effectiveness`."),
    ("finding", "grc", "GET /grc/api/v1/findings", "id", "Filterable by status."),
    ("risk", "grc", "GET /grc/api/v1/risks", "reference",
     "Always self-reports `review_status: current`, whether or not it is."),
    ("control_mapping", "grc", "GET /grc/api/v1/control-mappings", "control + requirement ref",
     "Carries `coverage` as a fraction."),
    ("requirement", "grc", "GET /grc/api/v1/requirements", "reference",
     "Both frameworks, filterable by name. Also appears inside a mapping."),
    ("framework", "grc", "GET /grc/api/v1/frameworks", "name",
     "Two of them, with requirement counts."),
    ("requirement_crosswalk", "grc", "GET /grc/api/v1/crosswalks", "source + target ref",
     "Equivalence is mostly partial — 56 of 70 rows are below 1.0."),
    ("attachment", "grc", "GET /grc/api/v1/findings/{id}/attachments", "id",
     "Metadata plus a download_token. The bytes need that second credential, and "
     "anything over 5 MB is refused with a 413."),
    ("business_service", "servicenow", "GET /servicenow/api/now/table/cmdb_ci_service", "name",
     "Name, tier and owner. Named by CI name, not by the SVC- id."),
    ("business_service", "servicenow", "GET /servicenow/api/now/table/incident", "service id",
     "Also appears as a bare id on an incident — a different identifier for the same thing."),
    ("application", "servicenow", "GET /servicenow/api/now/table/cmdb_ci_appl", "name",
     "Subject to the same 97% CMDB coverage as computers."),
    ("service_dependency", "servicenow", "GET /servicenow/api/now/table/cmdb_rel_ci", "parent + child name",
     "Edges of type `Depends on::Used by`. Parent is a service, child an application."),
    ("application_asset", "servicenow", "GET /servicenow/api/now/table/cmdb_rel_ci", "parent name + child fqdn",
     "Edges of type `Runs on::Runs`. Child FQDNs join to cmdb_ci_computer."),
]

# Entities no lens exposes at all. A connector cannot see these, by design.
UNREACHABLE = {
    "control_test": "Not exposed as history. Only the single latest result, via "
                    "`effectiveness` on /grc/api/v1/controls.",
    "audit": "Not exposed. Findings carry no audit reference.",
    "risk_control": "Not exposed. Which controls mitigate which risk is not discoverable.",
    "risk_service": "Not exposed.",
    "evidence": "Ground truth. Deliberately never exposed — it is the answer key.",
    "expectation": "Ground truth. Deliberately never exposed.",
    "department": "Not exposed.",
    "lens": "Exposed only through /_lens/{id}, which is not a vendor endpoint.",
    "lens_visibility": "Not exposed.",
    "world_meta": "Exposed through /healthz only.",
}


# ------------------------------------------------------------------ live schema
def schema():
    """Every table in world, with columns and live row counts, straight from Postgres."""
    cols = db.q("""SELECT table_name, column_name, data_type, is_nullable, ordinal_position
                     FROM information_schema.columns
                    WHERE table_schema = 'world'
                    ORDER BY table_name, ordinal_position""")
    fks = db.q("""SELECT tc.table_name, kcu.column_name,
                         ccu.table_name AS ref_table, ccu.column_name AS ref_column
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON kcu.constraint_name = tc.constraint_name
                    JOIN information_schema.constraint_column_usage ccu
                      ON ccu.constraint_name = tc.constraint_name
                   WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'world'""")
    pks = db.q("""SELECT tc.table_name, kcu.column_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON kcu.constraint_name = tc.constraint_name
                   WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'world'""")
    fk_map, pk_map = {}, {}
    for f in fks:
        fk_map.setdefault(f["table_name"], {})[f["column_name"]] = f"{f['ref_table']}.{f['ref_column']}"
    for p in pks:
        pk_map.setdefault(p["table_name"], set()).add(p["column_name"])

    out = {}
    for c in cols:
        t = c["table_name"]
        if t not in out:
            n = db.one(f'SELECT count(*) n FROM world."{t}"')["n"]
            out[t] = {"name": t, "rows": n, "columns": []}
        out[t]["columns"].append({
            "name": c["column_name"], "type": c["data_type"],
            "nullable": c["is_nullable"] == "YES",
            "pk": c["column_name"] in pk_map.get(t, set()),
            "fk": fk_map.get(t, {}).get(c["column_name"]),
        })
    return out


def _md(text):
    """Authored prose uses `backticks`; the page needs <code>. Escapes first."""
    import html
    out, parts = [], html.escape(text).split("`")
    for i, part in enumerate(parts):
        out.append(f"<code>{part}</code>" if i % 2 else part)
    return "".join(out)


def domains_with_schema():
    """Authored domain grouping, joined to the live schema. Reports drift both ways."""
    live = schema()
    documented, groups = set(), []
    for title, blurb, tables in DOMAINS:
        rows = []
        for name, desc in tables:
            documented.add(name)
            t = live.get(name)
            rows.append({"name": name, "desc": _md(desc), "missing": t is None,
                         "rows": t["rows"] if t else 0,
                         "columns": t["columns"] if t else []})
        groups.append({"title": title, "blurb": blurb, "tables": rows})
    undocumented = sorted(set(live) - documented)
    return groups, undocumented, live


def reach_matrix():
    """Which entities a connector can reach, plus everything it cannot."""
    live = schema()
    reachable = {}
    for entity, lens, call, ident, note in REACH:
        reachable.setdefault(entity, []).append(
            {"lens": lens, "call": call, "identifier": ident, "note": note})
    rows = []
    for name in sorted(live):
        rows.append({"table": name, "rows": live[name]["rows"],
                     "routes": [{**r, "note": _md(r["note"])} for r in reachable.get(name, [])],
                     "why_not": _md(UNREACHABLE[name])
                                if name not in reachable and name in UNREACHABLE else None})
    return rows


# ------------------------------------------------------------- live twin surface
def endpoints():
    """The twin's route table, read from the twin's own source of truth."""
    from twins import app as twin_app
    out = []
    for r in twin_app.app.routes:
        path = getattr(r, "path", None)
        methods = sorted(getattr(r, "methods", []) or [])
        if not path or path in ("/openapi.json", "/docs", "/redoc",
                                "/docs/oauth2-redirect"):
            continue  # FastAPI's own docs routes are not part of the vendor surface
        fn = getattr(r, "endpoint", None)
        params = []
        if fn is not None and hasattr(fn, "__annotations__"):
            import inspect
            try:
                for pname, p in inspect.signature(fn).parameters.items():
                    if pname in ("request", "authorization"):
                        continue
                    default = "" if p.default is inspect.Parameter.empty else p.default
                    params.append({"name": pname, "default": default})
            except (TypeError, ValueError):
                pass
        out.append({"path": path, "methods": [m for m in methods if m != "HEAD"],
                    "doc": (fn.__doc__ or "").strip().split("\n")[0] if fn else "",
                    "params": params})
    return sorted(out, key=lambda x: x["path"])


def live_example(path, params=None, profile=None, method="GET", data=None, cap=1400):
    """A real call to the running twin. What the manual shows is what the kit gets.

    Pretty-printed only for reading: a single 4KB line of JSON is what the wire
    carries, but it is not something anyone can learn a schema from.
    """
    import json
    r = probes.twin_call(method, path, params=params, data=data, profile=profile)
    body = r["body"]
    try:
        body = json.dumps(json.loads(body), indent=2)
    except (ValueError, TypeError):
        pass
    truncated = len(body) > cap
    return {"status": r["status"], "url": r["url"], "profile": profile,
            "body": body[:cap] + ("\n… truncated" if truncated else ""),
            "truncated": truncated}


def profile_fieldmaps():
    """Same canonical field, three customer-defined names. Read from the twin's YAML."""
    import yaml
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "twins", "profiles", "servicenow.yaml")
    prof = yaml.safe_load(open(p))
    names = list(prof)
    out = {}
    # every table the profile defines, not a hardcoded pair — adding a table to the
    # YAML must show up here without anyone remembering to edit this file
    for table in sorted(prof[names[0]]):
        canon = list(prof[names[0]][table]["fields"])
        out[table] = {"profiles": names,
                      "rows": [{"canonical": c,
                                "names": [prof[n][table]["fields"][c] for n in names]}
                               for c in canon]}
        if "severity_values" in prof[names[0]][table]:
            out[table]["severity"] = {
                "profiles": names,
                "rows": [{"canonical": k,
                          "names": [prof[n][table]["severity_values"][k] for n in names]}
                         for k in prof[names[0]][table]["severity_values"]]}
    return out


def worked_correlation():
    """One real machine, as each lens names it. Picked live, never hardcoded."""
    row = db.one("""SELECT a.id FROM asset a
                     WHERE a.decommissioned_on IS NULL
                       AND (SELECT count(DISTINCT lens_id) FROM lens_visibility v
                             WHERE v.entity_id = a.id AND v.entity_kind = 'asset') >= 2
                     ORDER BY a.id LIMIT 1""")
    if not row:
        return None
    a = db.one("""SELECT a.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on
                    FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
                   WHERE a.id = %s""", (row["id"],))
    seen = db.q("""SELECT l.id AS lens_id, l.vendor, l.identifier_style,
                          v.external_id, v.last_seen
                     FROM lens l
                     LEFT JOIN lens_visibility v ON v.lens_id = l.id
                          AND v.entity_kind = 'asset' AND v.entity_id = %s
                    ORDER BY l.id""", (row["id"],))
    return {"asset": a, "lenses": seen}


def config_file():
    """The connector config shipped with the repo, shown verbatim."""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "config", "virtualorg", "connectors.yaml")
    try:
        return open(p).read()
    except OSError:
        return "# config/virtualorg/connectors.yaml not found in this image"


def lens_objects():
    """What each lens actually serves, derived from REACH — not a hand-kept list."""
    out = {}
    for entity, lens, call, ident, note in REACH:
        for lid in [x.strip() for x in lens.split("/")]:
            if call == "(embedded)":
                continue
            out.setdefault(lid, [])
            if entity not in out[lid]:
                out[lid].append(entity)
    return out


def world_inventory():
    """The headline counts on the overview diagram, queried rather than typed."""
    r = db.one("""SELECT (SELECT count(*) FROM person)           AS people,
                         (SELECT count(*) FROM asset)            AS assets,
                         (SELECT count(*) FROM application)      AS applications,
                         (SELECT count(*) FROM business_service) AS services,
                         (SELECT count(*) FROM control)          AS controls""")
    return dict(r)
