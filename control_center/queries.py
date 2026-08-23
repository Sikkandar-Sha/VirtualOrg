"""
Every query the Control Center makes. The ONLY place that touches world-db.

DESIGN.md #8: "If a number appears in the UI it must be a query, never a
computation." So this module returns rows and counts; it does not aggregate,
score, weight or infer. Anything that looks like business logic belongs in the
kit under test, not in the harness that grades it.
"""
from twins import db


# ------------------------------------------------------------------ world meta
def world_meta():
    return {r["key"]: r["value"] for r in db.q("SELECT key, value FROM world_meta")}


def table_counts():
    tables = db.q("""SELECT table_name FROM information_schema.tables
                      WHERE table_schema = 'world' ORDER BY table_name""")
    out = []
    for t in tables:
        n = db.one(f'SELECT count(*) n FROM world."{t["table_name"]}"')["n"]
        out.append({"table": t["table_name"], "rows": n})
    return out


def lenses():
    return db.q("SELECT * FROM lens ORDER BY id")


def lens(lens_id):
    return db.one("SELECT * FROM lens WHERE id = %s", (lens_id,))


def lens_entity_counts():
    return db.q("""SELECT lens_id, entity_kind, count(*) n
                     FROM lens_visibility GROUP BY 1,2 ORDER BY 1,2""")


# ------------------------------------------------- surface 1: one entity, every lens
def asset(asset_id):
    return db.one("""SELECT a.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                            p.email AS owner_email, p.id AS owner_id
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
    sql = """SELECT a.id, a.hostname, a.fqdn, a.asset_tag, a.ip, a.kind, a.criticality,
                    a.decommissioned_on, p.full_name AS owner_name
               FROM asset a LEFT JOIN person p ON p.id = a.owner_person_id
              WHERE 1=1"""
    params = []
    if q:
        sql += """ AND (a.id ILIKE %s OR a.hostname ILIKE %s OR a.fqdn ILIKE %s
                        OR a.asset_tag ILIKE %s OR host(a.ip) ILIKE %s)"""
        params += [f"%{q}%"] * 5
    if kind:
        sql += " AND a.kind = %s"
        params.append(kind)
    if invisible_to:
        sql += """ AND a.id NOT IN (SELECT entity_id FROM lens_visibility
                                     WHERE lens_id = %s AND entity_kind = 'asset')"""
        params.append(invisible_to)
    sql += " ORDER BY a.id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(sql, tuple(params))


def asset_total(q=None, kind=None, invisible_to=None):
    sql = "SELECT count(*) n FROM asset a WHERE 1=1"
    params = []
    if q:
        sql += """ AND (a.id ILIKE %s OR a.hostname ILIKE %s OR a.fqdn ILIKE %s
                        OR a.asset_tag ILIKE %s OR host(a.ip) ILIKE %s)"""
        params += [f"%{q}%"] * 5
    if kind:
        sql += " AND a.kind = %s"
        params.append(kind)
    if invisible_to:
        sql += """ AND a.id NOT IN (SELECT entity_id FROM lens_visibility
                                     WHERE lens_id = %s AND entity_kind = 'asset')"""
        params.append(invisible_to)
    return db.one(sql, tuple(params))["n"]


# ------------------------------------------------------- surface 2: the spine
def services():
    return db.q("""SELECT s.*, p.full_name AS owner_name
                     FROM business_service s LEFT JOIN person p ON p.id = s.owner_person_id
                    ORDER BY s.criticality DESC, s.id""")


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
    return db.q("""SELECT ref, title, severity, opened_at, closed_at, stated_impact
                     FROM incident WHERE service_id = %s
                    ORDER BY opened_at DESC LIMIT 15""", (service_id,))


def controls(limit=200, offset=0, q=None):
    sql = """SELECT c.id, c.ref, c.title, c.test_frequency, c.automated,
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
        sql += " AND (c.ref ILIKE %s OR c.title ILIKE %s)"
        params += [f"%{q}%"] * 2
    sql += " ORDER BY c.ref LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(sql, tuple(params))


def control(control_id):
    return db.one("""SELECT c.*, p.full_name AS owner_name, p.ended_on AS owner_ended_on,
                            p.id AS owner_id
                       FROM control c LEFT JOIN person p ON p.id = c.owner_person_id
                      WHERE c.id = %s OR c.ref = %s""", (control_id, control_id))


def control_evidence(control_id, include_traps=True):
    sql = """SELECT e.id, e.kind, e.source_ref, e.strength, e.observed_at, e.is_trap
               FROM evidence e WHERE e.control_id = %s"""
    if not include_traps:
        sql += " AND NOT e.is_trap"
    sql += " ORDER BY e.observed_at DESC LIMIT 200"
    return db.q(sql, (control_id,))


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
    sql = """SELECT p.id, p.full_name, p.email, p.title, p.employment,
                    p.started_on, p.ended_on, d.name AS department
               FROM person p JOIN department d ON d.id = p.department_id
              WHERE 1=1"""
    params = []
    if q:
        sql += " AND (p.id ILIKE %s OR p.full_name ILIKE %s OR p.email ILIKE %s)"
        params += [f"%{q}%"] * 3
    if leavers_only:
        sql += " AND p.ended_on IS NOT NULL"
    sql += " ORDER BY p.id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(sql, tuple(params))


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


def expectations(family=None, limit=200, offset=0):
    sql = "SELECT * FROM expectation WHERE 1=1"
    params = []
    if family:
        sql += " AND family = %s"
        params.append(family)
    sql += " ORDER BY id LIMIT %s OFFSET %s"
    params += [limit, offset]
    return db.q(sql, tuple(params))


def expectation_total(family=None):
    sql = "SELECT count(*) n FROM expectation WHERE 1=1"
    params = []
    if family:
        sql += " AND family = %s"
        params.append(family)
    return db.one(sql, tuple(params))["n"]


def attribution_corpus():
    """Precision/recall denominators for the attribution family."""
    return db.one("""SELECT count(*) FILTER (WHERE NOT is_trap) AS true_links,
                            count(*) FILTER (WHERE is_trap)     AS traps,
                            count(DISTINCT control_id)          AS controls_with_evidence
                       FROM evidence""")


# ------------------------------------------- where the graph breaks (#7 absence)
# Per-table row counts make a table with 25 rows look healthy whether or not those
# rows are wired into the spine. These are the cross-table queries that tell the
# difference. DESIGN.md #7: "For an SSOT, silence must be distinguishable from
# health." Each gap records whether the kit could even see it through the APIs.
SPINE_GAPS = [
    ("applications attached to no business service", "application",
     """SELECT count(*) n FROM application a WHERE NOT EXISTS (
          SELECT 1 FROM service_dependency d WHERE d.application_id = a.id)""",
     "SELECT count(*) n FROM application", True,
     "Nothing depends on them, so they carry no inherited criticality. Now a tuned, "
     "deliberate slice recorded in world.expectation, and discoverable, by diffing "
     "cmdb_ci_appl against the parents of cmdb_rel_ci."),

    ("business services with no application", "business_service",
     """SELECT count(*) n FROM business_service s WHERE NOT EXISTS (
          SELECT 1 FROM service_dependency d WHERE d.service_id = s.id)""",
     "SELECT count(*) n FROM business_service", True,
     "A service with no dependencies cannot have residual risk computed for it."),

    ("applications running on no asset", "application",
     """SELECT count(*) n FROM application a WHERE NOT EXISTS (
          SELECT 1 FROM application_asset x WHERE x.application_id = a.id)""",
     "SELECT count(*) n FROM application", True,
     "The app-to-infrastructure link is broken; no vulnerability can reach the service."),

    # scoped to servers and cloud: endpoints never carry an application by
    # construction, so measuring them here would report 85% and mean nothing
    ("servers and cloud carrying no application", "asset",
     """SELECT count(*) n FROM asset a WHERE a.decommissioned_on IS NULL
          AND a.kind IN ('server','cloud')
          AND NOT EXISTS (SELECT 1 FROM application_asset x WHERE x.asset_id = a.id)""",
     """SELECT count(*) n FROM asset WHERE decommissioned_on IS NULL
          AND kind IN ('server','cloud')""", True,
     "Infrastructure nothing is known to run on. Endpoints are excluded, they never "
     "carry an application in this world."),

    ("live assets invisible to every security lens", "asset",
     """SELECT count(*) n FROM asset a WHERE a.decommissioned_on IS NULL
          AND NOT EXISTS (SELECT 1 FROM lens_visibility v
                           WHERE v.entity_id = a.id AND v.entity_kind = 'asset'
                             AND v.lens_id = 'splunk')""",
     "SELECT count(*) n FROM asset WHERE decommissioned_on IS NULL", True,
     "The absence family's headline. Recorded as expectations, scoreable."),

    ("controls with no evidence of any kind", "control",
     """SELECT count(*) n FROM control c WHERE NOT EXISTS (
          SELECT 1 FROM evidence e WHERE e.control_id = c.id AND NOT e.is_trap)""",
     "SELECT count(*) n FROM control", True,
     "Never operationalised. Recorded as expectations, scoreable."),

    ("controls mapped to no requirement", "control",
     """SELECT count(*) n FROM control c WHERE NOT EXISTS (
          SELECT 1 FROM control_mapping m WHERE m.control_id = c.id)""",
     "SELECT count(*) n FROM control", True,
     "A control that satisfies no requirement cannot move a framework score."),

    ("risks mitigated by no control", "risk",
     """SELECT count(*) n FROM risk r WHERE NOT EXISTS (
          SELECT 1 FROM risk_control rc WHERE rc.risk_id = r.id)""",
     "SELECT count(*) n FROM risk", False,
     "Residual equals inherent. risk_control is not exposed by any API."),

    ("risks threatening no service", "risk",
     """SELECT count(*) n FROM risk r WHERE NOT EXISTS (
          SELECT 1 FROM risk_service rs WHERE rs.risk_id = r.id)""",
     "SELECT count(*) n FROM risk", False,
     "Cannot be rolled up into per-service posture."),

    ("business services whose owner has left", "business_service",
     """SELECT count(*) n FROM business_service s JOIN person p
          ON p.id = s.owner_person_id WHERE p.ended_on IS NOT NULL""",
     "SELECT count(*) n FROM business_service", True,
     "Owner name is now exposed on cmdb_ci_service, but not the fact that they left."),

    ("controls whose owner has left", "control",
     """SELECT count(*) n FROM control c JOIN person p
          ON p.id = c.owner_person_id WHERE p.ended_on IS NOT NULL""",
     "SELECT count(*) n FROM control", True,
     "Visible: /grc/api/v1/controls returns the owner name, but not that they left."),

    ("live assets with no owner of record", "asset",
     """SELECT count(*) n FROM asset WHERE decommissioned_on IS NULL
          AND owner_person_id IS NULL""",
     "SELECT count(*) n FROM asset WHERE decommissioned_on IS NULL", True,
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
                    ORDER BY b.criticality DESC, b.name""")


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
