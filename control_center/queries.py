"""
Every query the Control Center makes. The ONLY place that touches world-db.

DESIGN.md #8: "If a number appears in the UI it must be a query, never a
computation." So this module returns rows and counts; it does not aggregate,
score, weight or infer. Anything that looks like business logic belongs in the
kit under test, not in the harness that grades it.
"""
from psycopg2 import sql

from twins import db


# ------------------------------------------------------------------ world meta
def world_meta():
    return {r["key"]: r["value"] for r in db.q("SELECT key, value FROM world_meta")}


def table_counts():
    tables = db.q("""SELECT table_name FROM information_schema.tables
                      WHERE table_schema = 'world' ORDER BY table_name""")
    out = []
    for t in tables:
        n = db.one(sql.SQL('SELECT count(*) n FROM world.{}').format(
            sql.Identifier(t["table_name"])))["n"]
        out.append({"table": t["table_name"], "rows": n})
    return out


def lenses():
    return db.q("SELECT * FROM lens ORDER BY id")


def lens(lens_id):
    row = db.one("SELECT * FROM lens WHERE id = %s", (lens_id,))
    if not row:
        return row
    row = dict(row)
    # The noun this lens actually deals in. Hardcoding "asset" made the IAM page say
    # it "calls every asset by its username" when it returns no assets at all.
    kinds = [r["entity_kind"] for r in db.q(
        """SELECT entity_kind, count(*) n FROM lens_visibility
            WHERE lens_id = %s GROUP BY 1 ORDER BY n DESC""", (lens_id,))]
    row["subject"] = kinds[0] if kinds else "entity"
    return row


def lens_entity_counts():
    return db.q("""SELECT lens_id, entity_kind, count(*) n
                     FROM lens_visibility GROUP BY 1,2 ORDER BY 1,2""")


# ------------------------------------------------- surface 1: one entity, every lens
def asset(asset_id):
    return db.one("""SELECT a.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                            p.email AS owner_email, p.id AS owner_id,
                            -- HR is a lens, and for employees it reports the
                            -- termination. Only contractors are invisible to it.
                            p.employment AS owner_employment
                       FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
                      WHERE a.id = %s""", (asset_id,))


def asset_lens_rows(asset_id):
    """What each lens calls this asset, and when it last saw it. NULL row = blind.

    Restricted to lenses that track assets at all. An identity lens does not see
    machines by design, and reporting it as "blind to this asset" would be a
    category error dressed up as a coverage gap.
    """
    return db.q("""SELECT l.id AS lens_id, l.vendor, l.category, l.identifier_style,
                          l.coverage, l.latency_minutes, l.retention_days, l.blind_spot,
                          v.external_id, v.last_seen
                     FROM lens l
                     LEFT JOIN lens_visibility v
                            ON v.lens_id = l.id AND v.entity_kind = 'asset'
                           AND v.entity_id = %s
                    WHERE EXISTS (SELECT 1 FROM lens_visibility x
                                   WHERE x.lens_id = l.id AND x.entity_kind = 'asset')
                    ORDER BY l.id""", (asset_id,))


def asset_alert_count(asset_id):
    return db.one("SELECT count(*) n FROM alert WHERE asset_id = %s", (asset_id,))["n"]


def asset_open_vulns(asset_id):
    return db.q("""SELECT cve, cvss, discovered_on FROM vulnerability
                    WHERE asset_id = %s AND remediated_on IS NULL
                    ORDER BY cvss DESC LIMIT 10""", (asset_id,))


def asset_applications(asset_id):
    return db.q("""SELECT ap.id, ap.name, ap.criticality
                     FROM application_asset aa JOIN application ap ON ap.id = aa.application_id
                    WHERE aa.asset_id = %s ORDER BY ap.id""", (asset_id,))


def asset_expectations(asset_id):
    return db.q("""SELECT * FROM expectation
                    WHERE subject_kind = 'asset' AND subject_id = %s""", (asset_id,))


def assets(limit=100, offset=0, q=None, kind=None, invisible_to=None):
    q_sql = """SELECT a.id, a.hostname, a.fqdn, a.asset_tag, a.ip, a.kind, a.criticality,
                    a.decommissioned_on, p.full_name AS owner_name
               FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
              WHERE 1=1"""
    params = []
    if q:
        q_sql += """ AND (a.id ILIKE %s OR a.hostname ILIKE %s OR a.fqdn ILIKE %s
                        OR a.asset_tag ILIKE %s OR host(a.ip) ILIKE %s)"""
        params += [f"%{q}%"] * 5
    if kind:
        q_sql += " AND a.kind = %s"
        params.append(kind)
    if invisible_to:
        q_sql += """ AND a.id NOT IN (SELECT entity_id FROM lens_visibility
                                     WHERE lens_id = %s AND entity_kind = 'asset')"""
        params.append(invisible_to)
    q_sql += " ORDER BY a.id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(q_sql, tuple(params))


def asset_total(q=None, kind=None, invisible_to=None):
    q_sql = "SELECT count(*) n FROM asset a WHERE 1=1"
    params = []
    if q:
        q_sql += """ AND (a.id ILIKE %s OR a.hostname ILIKE %s OR a.fqdn ILIKE %s
                        OR a.asset_tag ILIKE %s OR host(a.ip) ILIKE %s)"""
        params += [f"%{q}%"] * 5
    if kind:
        q_sql += " AND a.kind = %s"
        params.append(kind)
    if invisible_to:
        q_sql += """ AND a.id NOT IN (SELECT entity_id FROM lens_visibility
                                     WHERE lens_id = %s AND entity_kind = 'asset')"""
        params.append(invisible_to)
    return db.one(q_sql, tuple(params))["n"]


# ------------------------------------------------------- surface 2: the spine
def services():
    return db.q("""SELECT s.*, p.full_name AS owner_name
                     FROM business_service s LEFT JOIN person p ON p.id = s.owner_person_id
                    -- criticality is an ordered category stored as text, so a plain
                    -- DESC sorts it alphabetically and puts tier3 above tier1
                    ORDER BY array_position(ARRAY['tier3','tier2','tier1'],
                                            s.criticality) DESC, s.id""")


def service(service_id):
    return db.one("""SELECT s.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on
                       FROM business_service s LEFT JOIN person p ON p.id = s.owner_person_id
                      WHERE s.id = %s""", (service_id,))


def service_applications(service_id):
    return db.q("""SELECT ap.id, ap.name, ap.criticality, p.full_name AS owner_name
                     FROM service_dependency d
                     JOIN application ap ON ap.id = d.application_id
                     LEFT JOIN person p ON p.id = ap.owner_person_id
                    WHERE d.service_id = %s ORDER BY ap.id""", (service_id,))


def service_assets(service_id):
    return db.q("""SELECT DISTINCT a.id, a.hostname, a.kind, a.criticality, a.ip
                     FROM service_dependency d
                     JOIN application_asset aa ON aa.application_id = d.application_id
                     JOIN asset a ON a.id = aa.asset_id
                    WHERE d.service_id = %s ORDER BY a.id""", (service_id,))


def service_risks(service_id):
    return db.q("""SELECT r.id, r.ref, r.title, r.category, r.inherent_score, r.appetite,
                          r.last_reviewed_on, r.review_period_days
                     FROM risk_service rs JOIN risk r ON r.id = rs.risk_id
                    WHERE rs.service_id = %s ORDER BY r.inherent_score DESC""", (service_id,))


def service_incidents(service_id):
    """Incidents on a service, each carrying whether the answer key flags it.

    `flagged` comes from world.expectation rather than from a rule restated in the
    template. The template used to re-encode the generator's planting condition by
    hand and had already drifted from it: 23 incidents matched the hand-written rule
    while the catalogue held 13, so the page contradicted the thing it is meant to
    illustrate."""
    return db.q("""SELECT i.ref, i.title, i.severity, i.opened_at, i.closed_at,
                          i.stated_impact,
                          EXISTS (SELECT 1 FROM expectation x
                                   WHERE x.subject_kind = 'incident'
                                     AND x.subject_id = i.id
                                     AND x.family = 'conflict') AS flagged
                     FROM incident i WHERE i.service_id = %s
                    ORDER BY i.opened_at DESC LIMIT 15""", (service_id,))


def controls(limit=200, offset=0, q=None):
    q_sql = """SELECT c.id, c.ref, c.title, c.test_frequency, c.automated,
                    p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                    t.tested_on AS last_tested_on, t.result AS last_result,
                    (SELECT count(*) FROM finding f
                      WHERE f.control_id = c.id AND f.status = 'overdue') AS overdue_findings,
                    (SELECT count(*) FROM evidence e
                      WHERE e.control_id = c.id AND NOT e.is_trap) AS evidence_rows
               FROM control c
               LEFT JOIN person p ON p.id = c.owner_person_id
               LEFT JOIN LATERAL (SELECT tested_on, result FROM control_test
                                   WHERE control_id = c.id
                                   ORDER BY tested_on DESC LIMIT 1) t ON true
              WHERE 1=1"""
    params = []
    if q:
        q_sql += " AND (c.ref ILIKE %s OR c.title ILIKE %s)"
        params += [f"%{q}%"] * 2
    q_sql += " ORDER BY c.ref LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(q_sql, tuple(params))


def control(control_id):
    return db.one("""SELECT c.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                            p.id AS owner_id
                       FROM control c LEFT JOIN person p ON p.id = c.owner_person_id
                      WHERE c.id = %s OR c.ref = %s
                      ORDER BY c.id LIMIT 1""", (control_id, control_id))


    q_sql = """SELECT e.id, e.kind, e.source_ref, e.strength, e.observed_at, e.is_trap
               FROM evidence e WHERE e.control_id = %s
               ORDER BY e.observed_at DESC LIMIT 200"""
    return db.q(q_sql, (control_id,))


def control_evidence_summary(control_id):
    return db.q("""SELECT kind, is_trap, count(*) n FROM evidence
                    WHERE control_id = %s GROUP BY 1,2 ORDER BY 1,2""", (control_id,))


def control_tests(control_id):
    return db.q("""SELECT tested_on, result FROM control_test
                    WHERE control_id = %s ORDER BY tested_on DESC LIMIT 24""", (control_id,))


def control_findings(control_id):
    return db.q("""SELECT id, title, severity, raised_on, due_on, closed_on, status
                     FROM finding WHERE control_id = %s ORDER BY raised_on DESC""", (control_id,))


def control_requirements(control_id):
    return db.q("""SELECT q.ref, q.title, m.coverage, f.name AS framework
                     FROM control_mapping m
                     JOIN requirement q ON q.id = m.requirement_id
                     JOIN framework f ON f.id = q.framework_id
                    WHERE m.control_id = %s ORDER BY q.ref""", (control_id,))


def control_risks(control_id):
    return db.q("""SELECT r.id, r.ref, r.title, rc.contribution
                     FROM risk_control rc JOIN risk r ON r.id = rc.risk_id
                    WHERE rc.control_id = %s ORDER BY rc.contribution DESC""", (control_id,))


def control_expectations(control_id):
    return db.q("""SELECT * FROM expectation
                    WHERE subject_kind = 'control' AND subject_id = %s""", (control_id,))


# ------------------------------------------------------- surface 4: the org
def org_counts():
    return db.q("""
        SELECT 'people'          AS entity, count(*) n FROM person
        UNION ALL SELECT 'leavers',        count(*) FROM person WHERE ended_on IS NOT NULL
        UNION ALL SELECT 'accounts',       count(*) FROM account
        UNION ALL SELECT 'orphaned accounts', count(*) FROM account a
                    JOIN person p ON p.id = a.person_id
                   WHERE p.ended_on IS NOT NULL AND a.disabled_on IS NULL
        UNION ALL SELECT 'assets',         count(*) FROM asset
        UNION ALL SELECT 'live assets',    count(*) FROM asset WHERE decommissioned_on IS NULL
        UNION ALL SELECT 'applications',   count(*) FROM application
        UNION ALL SELECT 'services',       count(*) FROM business_service
        UNION ALL SELECT 'controls',       count(*) FROM control
        UNION ALL SELECT 'requirements',   count(*) FROM requirement
        UNION ALL SELECT 'control tests',  count(*) FROM control_test
        UNION ALL SELECT 'findings',       count(*) FROM finding
        UNION ALL SELECT 'overdue findings', count(*) FROM finding WHERE status = 'overdue'
        UNION ALL SELECT 'risks',          count(*) FROM risk
        UNION ALL SELECT 'alerts',         count(*) FROM alert
        UNION ALL SELECT 'incidents',      count(*) FROM incident
        UNION ALL SELECT 'vulnerabilities', count(*) FROM vulnerability
        UNION ALL SELECT 'evidence',       count(*) FROM evidence
        UNION ALL SELECT 'evidence traps', count(*) FROM evidence WHERE is_trap
    """)


def people(limit=100, offset=0, q=None, leavers_only=False):
    q_sql = """SELECT p.id, p.full_name, p.email, p.title, p.employment,
                    p.started_on, p.ended_on, d.name AS department
               FROM person p JOIN department d ON d.id = p.department_id
              WHERE 1=1"""
    params = []
    if q:
        q_sql += " AND (p.id ILIKE %s OR p.full_name ILIKE %s OR p.email ILIKE %s)"
        params += [f"%{q}%"] * 3
    if leavers_only:
        q_sql += " AND p.ended_on IS NOT NULL"
    q_sql += " ORDER BY p.id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(q_sql, tuple(params))


def person(person_id):
    return db.one("""SELECT p.*, d.name AS department FROM person p
                     JOIN department d ON d.id = p.department_id WHERE p.id = %s""", (person_id,))


def person_accounts(person_id):
    return db.q("""SELECT id, system, username, privileged, created_on, disabled_on
                     FROM account WHERE person_id = %s ORDER BY id""", (person_id,))


def person_owns(person_id):
    return {
        "assets": db.q("SELECT id, hostname, kind FROM asset WHERE owner_person_id = %s", (person_id,)),
        "controls": db.q("SELECT id, ref, title FROM control WHERE owner_person_id = %s", (person_id,)),
        "risks": db.q("SELECT id, ref, title FROM risk WHERE owner_person_id = %s", (person_id,)),
        "services": db.q("SELECT id, name FROM business_service WHERE owner_person_id = %s", (person_id,)),
    }


def person_expectations(person_id):
    return db.q("""SELECT * FROM expectation
                    WHERE subject_kind = 'person' AND subject_id = %s""", (person_id,))


def departments():
    return db.q("""SELECT d.id, d.name, d.cost_center, count(p.id) n,
                          count(p.id) FILTER (WHERE p.ended_on IS NOT NULL) leavers
                     FROM department d LEFT JOIN person p ON p.department_id = d.id
                    GROUP BY d.id, d.name, d.cost_center ORDER BY d.name""")


# ------------------------------------------- surface 5: ground truth catalogue
def expectation_families():
    return db.q("""SELECT family, claim, count(*) n FROM expectation
                    GROUP BY 1,2 ORDER BY 1, 3 DESC""")


def expectation_subject_counts():
    """Rows and distinct subjects per family. A kit emits one finding per subject, so
    the distinct count is what scripts/score measures against; the row count is what
    the catalogue holds. Showing only one of them made the two surfaces disagree."""
    return db.q("""SELECT family, count(*) AS rows,
                          count(DISTINCT (subject_kind, subject_id)) AS subjects
                     FROM expectation GROUP BY family ORDER BY family""")


def expectations(family=None, limit=200, offset=0):
    q_sql = "SELECT * FROM expectation WHERE 1=1"
    params = []
    if family:
        q_sql += " AND family = %s"
        params.append(family)
    q_sql += " ORDER BY id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(q_sql, tuple(params))


def expectation_total(family=None):
    q_sql = "SELECT count(*) n FROM expectation WHERE 1=1"
    params = []
    if family:
        q_sql += " AND family = %s"
        params.append(family)
    return db.one(q_sql, tuple(params))["n"]


def attribution_corpus():
    """Precision/recall denominators for the attribution family.

    Both the planted totals and the retrievable ones, because a page showing only
    the planted count tells a reader they face every decoy in the world when the APIs
    will hand them a fraction of that. The retrievable figures are the ones
    `scripts/score` reports against. Exact values move with the seed, so they are
    deliberately not restated here."""
    reach = {r["id"] for r in groundtruth_export()["evidence"] if r["reachable"]}
    row = dict(db.one("""SELECT count(*) FILTER (WHERE NOT is_trap) AS true_links,
                                count(*) FILTER (WHERE is_trap)     AS traps,
                                count(DISTINCT control_id) AS controls_with_evidence
                           FROM evidence"""))
    live = db.q("SELECT id, is_trap FROM evidence")
    row["reachable_links"] = sum(1 for r in live if not r["is_trap"] and r["id"] in reach)
    row["reachable_traps"] = sum(1 for r in live if r["is_trap"] and r["id"] in reach)
    return row


# ------------------------------------------- where the graph breaks (#7 absence)
# Per-table row counts make a table with 25 rows look healthy whether or not those
# rows are wired into the spine. These are the cross-table queries that tell the
# difference. DESIGN.md #7: "For an SSOT, silence must be distinguishable from
# health." Each gap records whether the kit could even see it through the APIs.
SPINE_GAPS = [
    ("applications attached to no business service", "application",
     """SELECT count(*) n FROM world.application a WHERE NOT EXISTS (
          SELECT 1 FROM world.service_dependency d WHERE d.application_id = a.id)""",
     "SELECT count(*) n FROM world.application", True,
     "Nothing depends on them, so they carry no inherited criticality. Now a tuned, "
     "deliberate slice recorded in world.expectation, and discoverable, by diffing "
     "cmdb_ci_appl against the parents of cmdb_rel_ci."),

    ("business services with no application", "business_service",
     """SELECT count(*) n FROM world.business_service s WHERE NOT EXISTS (
          SELECT 1 FROM world.service_dependency d WHERE d.service_id = s.id)""",
     "SELECT count(*) n FROM world.business_service", True,
     "A service with no dependencies cannot have residual risk computed for it."),

    ("applications running on no asset", "application",
     """SELECT count(*) n FROM world.application a WHERE NOT EXISTS (
          SELECT 1 FROM world.application_asset x WHERE x.application_id = a.id)""",
     "SELECT count(*) n FROM world.application", True,
     "The app-to-infrastructure link is broken; no vulnerability can reach the service."),

    # scoped to servers and cloud: endpoints never carry an application by
    # construction, so measuring them here would report 85% and mean nothing
    ("servers and cloud carrying no application", "asset",
     """SELECT count(*) n FROM world.asset a WHERE a.decommissioned_on IS NULL
          AND a.kind IN ('server','cloud')
          AND NOT EXISTS (SELECT 1 FROM world.application_asset x WHERE x.asset_id = a.id)""",
     """SELECT count(*) n FROM world.asset WHERE decommissioned_on IS NULL
          AND kind IN ('server','cloud')""", True,
     "Infrastructure nothing is known to run on. Endpoints are excluded, they never "
     "carry an application in this world."),

    ("live assets invisible to every security lens", "asset",
     """SELECT count(*) n FROM world.asset a WHERE a.decommissioned_on IS NULL
          AND NOT EXISTS (SELECT 1 FROM world.lens_visibility v
                           WHERE v.entity_id = a.id AND v.entity_kind = 'asset'
                             -- derived from lens.category so this cannot drift from the generator's
                             -- SECURITY_LENSES the way two hardcoded lists would
                             AND v.lens_id IN (SELECT id FROM lens
                                                WHERE category IN ('siem','vuln','edr')))""",
     "SELECT count(*) n FROM world.asset WHERE decommissioned_on IS NULL", True,
     "The absence family's headline. Recorded as expectations, scoreable."),

    ("controls with no evidence of any kind", "control",
     """SELECT count(*) n FROM world.control c WHERE NOT EXISTS (
          SELECT 1 FROM world.evidence e WHERE e.control_id = c.id AND NOT e.is_trap)""",
     "SELECT count(*) n FROM world.control", True,
     "Never operationalised. Recorded as expectations, scoreable."),

    ("controls mapped to no requirement", "control",
     """SELECT count(*) n FROM world.control c WHERE NOT EXISTS (
          SELECT 1 FROM world.control_mapping m WHERE m.control_id = c.id)""",
     "SELECT count(*) n FROM world.control", True,
     "A control that satisfies no requirement cannot move a framework score."),

    ("risks mitigated by no control", "risk",
     """SELECT count(*) n FROM world.risk r WHERE NOT EXISTS (
          SELECT 1 FROM world.risk_control rc WHERE rc.risk_id = r.id)""",
     "SELECT count(*) n FROM world.risk", False,
     "Residual equals inherent. risk_control is not exposed by any API."),

    ("risks threatening no service", "risk",
     """SELECT count(*) n FROM world.risk r WHERE NOT EXISTS (
          SELECT 1 FROM world.risk_service rs WHERE rs.risk_id = r.id)""",
     "SELECT count(*) n FROM world.risk", False,
     "Cannot be rolled up into per-service posture."),

    ("business services whose owner has left", "business_service",
     """SELECT count(*) n FROM world.business_service s JOIN world.person p
          ON p.id = s.owner_person_id WHERE p.ended_on IS NOT NULL""",
     "SELECT count(*) n FROM world.business_service", True,
     "Owner name is now exposed on cmdb_ci_service, but not the fact that they left."),

    ("controls whose owner has left", "control",
     """SELECT count(*) n FROM world.control c JOIN world.person p
          ON p.id = c.owner_person_id WHERE p.ended_on IS NOT NULL""",
     "SELECT count(*) n FROM world.control", True,
     "Visible: /grc/api/v1/controls returns the owner name, but not that they left."),

    ("live assets with no owner of record", "asset",
     """SELECT count(*) n FROM world.asset WHERE decommissioned_on IS NULL
          AND owner_person_id IS NULL""",
     "SELECT count(*) n FROM world.asset WHERE decommissioned_on IS NULL", True,
     "By construction, not by accident: only endpoints are given an owner. Server and "
     "cloud ownership is simply not modelled, worth knowing before you build a report "
     "that assumes every asset has a custodian."),
]


def spine_gaps():
    out = []
    for label, entity, sql, total_sql, visible, note in SPINE_GAPS:
        n = db.one(sql)["n"]
        total = db.one(total_sql)["n"]
        out.append({"label": label, "entity": entity, "n": n, "total": total,
                    "pct": round(100.0 * n / total, 1) if total else 0.0,
                    "api_visible": visible, "note": note, "sql": " ".join(sql.split())})
    return out


def orphan_applications():
    return db.q("""SELECT a.id, a.name, a.criticality, p.full_name AS owner_name,
                          (SELECT count(*) FROM application_asset x
                            WHERE x.application_id = a.id) AS assets
                     FROM application a LEFT JOIN person p ON p.id = a.owner_person_id
                    WHERE NOT EXISTS (SELECT 1 FROM service_dependency d
                                       WHERE d.application_id = a.id)
                    ORDER BY a.id""")



# ------------------------------- the top of the spine: business processes
def processes():
    return db.q("""SELECT b.id, b.name, b.criticality, b.rto_hours,
                          p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                          count(ps.service_id) AS services
                     FROM business_process b
                     LEFT JOIN person p ON p.id = b.owner_person_id
                     LEFT JOIN process_service ps ON ps.process_id = b.id
                    GROUP BY b.id, b.name, b.criticality, b.rto_hours,
                             p.full_name, p.ended_on
                    -- same ordered-category problem: alphabetically 'medium' beats
                    -- 'critical', which put the two critical processes last
                    ORDER BY array_position(ARRAY['low','medium','high','critical'],
                                            b.criticality) DESC, b.name""")


def service_processes(service_id):
    return db.q("""SELECT b.id, b.name, b.criticality, b.rto_hours
                     FROM process_service ps JOIN business_process b ON b.id = ps.process_id
                    WHERE ps.service_id = %s ORDER BY b.name""", (service_id,))


def control_policies(control_id):
    return db.q("""SELECT p.ref, p.title FROM policy_control pc
                     JOIN policy p ON p.id = pc.policy_id
                    WHERE pc.control_id = %s ORDER BY p.ref""", (control_id,))


def control_exceptions(control_id):
    return db.q("""SELECT id, reason, approved_on, expires_on, status
                     FROM control_exception WHERE control_id = %s ORDER BY id""", (control_id,))



# ------------------------------------------------- the scoring export (surface 5)
def groundtruth_export():
    """Everything a scorer needs, and nothing a kit should ever see.

    This lives on the Control Center rather than the twin on purpose. The twins are
    what the kit under test talks to, and the answer key must not be reachable from
    there at any price. The Control Center is the harness side of the boundary.
    """
    alias = []
    for r in db.q("SELECT id, ref FROM control"):
        alias += [("control", r["id"], r["id"]), ("control", r["ref"], r["id"])]
    for r in db.q("SELECT id, ref FROM risk"):
        alias += [("risk", r["id"], r["id"]), ("risk", r["ref"], r["id"])]
    for r in db.q("SELECT id, ref FROM policy"):
        alias += [("policy", r["id"], r["id"]), ("policy", r["ref"], r["id"])]
    for r in db.q("SELECT id, ref FROM incident"):
        alias += [("incident", r["id"], r["id"]), ("incident", r["ref"], r["id"])]
    for r in db.q("SELECT id, hostname, fqdn, asset_tag, host(ip) AS ip FROM asset"):
        alias += [("asset", v, r["id"]) for v in
                  (r["id"], r["hostname"], r["fqdn"], r["asset_tag"], r["ip"])]
    for r in db.q("SELECT id, email FROM person"):
        alias += [("person", r["id"], r["id"]), ("person", r["email"], r["id"]),
                  ("person", r["email"].split("@")[0], r["id"])]
    for r in db.q("SELECT id, name FROM application"):
        alias += [("application", r["id"], r["id"]), ("application", r["name"], r["id"])]
    for r in db.q("SELECT id, name FROM business_service"):
        alias += [("business_service", r["id"], r["id"]),
                  ("business_service", r["name"], r["id"])]
    # business_process was the only kind with no identity alias, so `BP-01` resolved
    # only by falling through, and `bp-01` did not resolve at all.
    for r in db.q("SELECT id, name FROM business_process"):
        alias += [("business_process", r["id"], r["id"]),
                  ("business_process", r["name"], r["id"])]
    for r in db.q("SELECT entity_kind, entity_id, external_id FROM lens_visibility"):
        alias.append((r["entity_kind"], r["external_id"], r["entity_id"]))

    # An alias that names more than one entity resolves to none of them. 84 IP
    # addresses are shared by 207 assets, because the world recycles them on purpose;
    # silently picking whichever row came last would hand the scorer a wrong entity
    # and charge the kit a false positive and a false negative for it.
    seen, ambiguous = {}, set()
    for k, a, i in alias:
        if not a:
            continue
        key = (k, str(a).strip().lower())
        if key in seen and seen[key] != i:
            ambiguous.add(key)
        seen[key] = i

    return {
        "world": {r["key"]: r["value"] for r in db.q("SELECT key, value FROM world_meta")},
        "expectations": [
            {"id": r["id"], "family": r["family"], "subject_kind": r["subject_kind"],
             "subject_id": r["subject_id"], "claim": r["claim"],
             "reachable": r["reachable"]}
            # `reachable` marks whether any lens exposes the evidence a kit would need
            # to reach this conclusion. Attribution recall has been corrected for this
            # since the denominators were fixed; findings recall was not, so a kit was
            # scored against conclusions no API supports. Privileged-group membership
            # is planted on AD groups, and the IAM lens serves Okta groups only.
            for r in db.q("""
                SELECT e.id, e.family, e.subject_kind, e.subject_id, e.claim,
                       NOT (e.claim LIKE '%%privileged group%%'
                            AND NOT EXISTS (
                              SELECT 1 FROM account a
                                JOIN group_membership m ON m.account_id = a.id
                                JOIN access_group g ON g.id = m.group_id AND g.privileged
                               WHERE a.person_id = e.subject_id AND a.system = 'okta'
                                 AND m.revoked_on IS NULL)) AS reachable
                  FROM expectation e ORDER BY e.id""")],
        # source_ref too: a kit sees an alert id or a finding id, never an evidence id,
        # so it can only ever name the source record it was reasoning about.
        #
        # `reachable` marks the links whose source record a connector can actually
        # retrieve, and it is computed against the same windows the twins enforce
        # rather than assumed. Excluding only control_test history was far too
        # generous: it left every alert in the denominator, including the ones
        # Splunk drops for being outside its 90-day retention or on an asset its
        # 0.83 coverage never sees. A flawless kit was scored against thousands of
        # links no API would hand it, and told it had missed them.
        "evidence": [
            {"id": r["id"], "source_ref": r["source_ref"], "kind": r["kind"],
             "control_id": r["control_id"], "is_trap": r["is_trap"],
             "reachable": r["reachable"]}
            for r in db.q("""
                WITH w AS (
                  SELECT (((SELECT value FROM world_meta WHERE key = 'as_of')::date
                           + time '09:00') AT TIME ZONE 'UTC') AS now_ts),
                     sp AS (SELECT latency_minutes, retention_days
                              FROM lens WHERE id = 'splunk')
                SELECT e.id, e.source_ref, e.kind, e.control_id, e.is_trap,
                       CASE
                         -- the GRC API exposes only the latest result per control,
                         -- never the history
                         WHEN e.kind = 'control_test' THEN false
                         -- every finding is listed, with no visibility filter
                         WHEN e.kind = 'finding' THEN true
                         -- schema.sql permits 'incident' and 'vulnerability' too.
                         -- The generator emits neither today; if it ever does, an
                         -- ELSE false would silently drop them from the recall
                         -- denominator, which is a wrong answer key with no error.
                         WHEN e.kind IN ('incident', 'vulnerability') THEN true
                         WHEN e.kind = 'alert' THEN EXISTS (
                           SELECT 1 FROM alert a
                             JOIN lens_visibility v ON v.entity_id = a.asset_id
                                  AND v.lens_id = 'splunk' AND v.entity_kind = 'asset'
                            WHERE a.id = e.source_ref
                              AND a.occurred_at <= (SELECT now_ts FROM w)
                                  - ((SELECT latency_minutes FROM sp) || ' minutes')::interval
                              AND a.occurred_at >= (SELECT now_ts FROM w)
                                  - ((SELECT retention_days FROM sp) || ' days')::interval)
                         ELSE false
                       END AS reachable
                  FROM evidence e ORDER BY e.id""")],
        # Emitted from the deduplicated map, not the raw list: re-iterating `alias`
        # shipped 1,522 duplicate rows, a quarter of the payload, for no benefit.
        "aliases": [{"kind": k, "alias": a, "id": i}
                    for (k, a), i in sorted(seen.items())
                    if (k, a) not in ambiguous],
        "ambiguous_aliases": [{"kind": k, "alias": a} for k, a in sorted(ambiguous)],
    }
