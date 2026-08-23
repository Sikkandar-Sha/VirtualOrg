#!/usr/bin/env python3
"""
VirtualOrg, deterministic world generator.

Produces a complete, TRUE enterprise plus three years of causally coherent history,
then derives each lens's degraded view of it (lens_visibility) and writes the
ground-truth expectations that the kit under test will be scored against.

Same seed + same as-of date => byte-identical world.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import random
import psycopg2
from psycopg2.extras import execute_values, Json

# --------------------------------------------------------------------------- data
FIRST = ["Sarah","James","Priya","Chen","Maria","Omar","Anna","David","Fatima","Luis",
         "Grace","Tom","Yuki","Ravi","Elena","Marcus","Aisha","Peter","Nina","Hassan",
         "Clara","Jonas","Mei","Samuel","Leila","Victor","Ruth","Ahmed","Ingrid","Paulo"]
LAST  = ["Chen","Okafor","Nakamura","Silva","Haddad","Novak","Petrov","Sharma","Kowalski",
         "Andersen","Mwangi","Rossi","Dubois","Fernandez","Yilmaz","Larsson","Costa",
         "Bergman","Nasser","Kaur","Moreau","Weber","Tanaka","Oyelaran","Vargas"]
DEPTS = [("Engineering","CC-1000"),("Finance","CC-2000"),("Operations","CC-3000"),
         ("Sales","CC-4000"),("Human Resources","CC-5000"),("Legal","CC-6000"),
         ("Information Security","CC-7000"),("Customer Support","CC-8000"),
         ("Marketing","CC-9000"),("Procurement","CC-9500")]
TITLES = ["Analyst","Senior Analyst","Manager","Engineer","Senior Engineer","Lead",
          "Director","Specialist","Coordinator","Administrator"]
OS_ENDPOINT = [("Windows","11 23H2"),("Windows","10 22H2"),("macOS","14.5"),("Ubuntu","22.04 LTS")]
OS_SERVER   = [("Windows","Server 2022"),("Ubuntu","22.04 LTS"),("Ubuntu","24.04 LTS"),("RHEL","9.4")]

CONTROL_THEMES = [
    ("Access Control","access"),("Privileged Access","access"),("MFA Enforcement","access"),
    ("Joiner Mover Leaver","access"),("Vulnerability Management","vuln"),
    ("Patch Management","vuln"),("Endpoint Protection","endpoint"),
    ("Logging and Monitoring","monitoring"),("Incident Response","ir"),
    ("Backup and Recovery","resilience"),("Change Management","change"),
    ("Data Classification","data"),("Encryption at Rest","data"),
    ("Encryption in Transit","data"),("Third Party Risk","vendor"),
    ("Security Awareness","people"),("Network Segmentation","network"),
    ("Configuration Baselines","config"),("Asset Inventory","asset"),
    ("Secure Development","sdlc"),
]
RULES = [
    ("Privileged Account Added to Domain Admins","access","high"),
    ("MFA Bypass Attempt","access","high"),
    ("Impossible Travel Sign-in","access","medium"),
    ("Disabled Account Authentication","access","high"),
    ("Endpoint Protection Agent Stopped","endpoint","high"),
    ("Malware Quarantined","endpoint","medium"),
    ("Unsigned Binary Execution","endpoint","medium"),
    ("Audit Log Cleared","monitoring","high"),
    ("Log Source Silent","monitoring","medium"),
    ("Unapproved Production Change","change","medium"),
    ("Large Outbound Transfer","data","high"),
    ("Unencrypted Database Connection","data","medium"),
    ("Lateral Movement Detected","network","high"),
    ("Backup Job Failed","resilience","low"),
    ("Baseline Drift Detected","config","low"),
]
CSF = [
    ("GV.OC-01", "Organizational mission is understood"),
    ("GV.RM-01", "Risk management objectives are agreed"),
    ("GV.RM-02", "Risk appetite is established and communicated"),
    ("GV.SC-01", "Supply chain risk management processes are established"),
    ("GV.RR-02", "Roles and responsibilities for risk are established"),
    ("GV.PO-01", "Policy for cybersecurity is established"),
    ("ID.AM-01", "Inventories of hardware are maintained"),
    ("ID.AM-02", "Inventories of software are maintained"),
    ("ID.AM-05", "Assets are prioritized by criticality"),
    ("ID.RA-01", "Vulnerabilities in assets are identified and recorded"),
    ("ID.RA-05", "Threats and likelihoods are used to understand risk"),
    ("ID.IM-01", "Improvements are identified from evaluations"),
    ("PR.AA-01", "Identities and credentials are managed"),
    ("PR.AA-02", "Identities are proofed and bound to credentials"),
    ("PR.AA-03", "Users and services are authenticated"),
    ("PR.AA-05", "Access permissions enforce least privilege"),
    ("PR.AT-01", "Personnel are provided awareness and training"),
    ("PR.DS-01", "Confidentiality of data-at-rest is protected"),
    ("PR.DS-02", "Confidentiality of data-in-transit is protected"),
    ("PR.DS-11", "Backups of data are created and tested"),
    ("PR.PS-01", "Configuration management practices are established"),
    ("PR.PS-02", "Software is maintained, replaced and removed"),
    ("PR.PS-04", "Log records are generated and made available"),
    ("PR.PS-05", "Unauthorized software execution is prevented"),
    ("PR.IR-01", "Networks and environments are protected"),
    ("DE.CM-01", "Networks are monitored to find adverse events"),
    ("DE.CM-03", "Personnel activity is monitored"),
    ("DE.CM-09", "Computing hardware and software are monitored"),
    ("DE.AE-02", "Adverse events are analyzed"),
    ("DE.AE-06", "Information on adverse events is shared"),
    ("RS.MA-01", "The incident response plan is executed"),
    ("RS.MA-02", "Incident reports are triaged and validated"),
    ("RS.AN-03", "Analysis is performed to determine what has taken place"),
    ("RS.MI-01", "Incidents are contained"),
    ("RS.CO-02", "Internal and external stakeholders are notified"),
    ("RC.RP-01", "The recovery portion of the plan is executed"),
    ("RC.RP-05", "Integrity of restored assets is verified"),
    ("RC.CO-03", "Recovery activities are communicated"),
]
PROCESSES = [("Order to cash", "critical", 4), ("Procure to pay", "high", 24),
             ("Record to report", "high", 48), ("Hire to retire", "medium", 72),
             ("Customer onboarding", "critical", 8), ("Incident to resolution", "high", 4)]
SOFTWARE = [("Microsoft Office", "Microsoft", "2019", True), ("Google Chrome", "Google", "126", False),
            ("OpenSSL", "OpenSSL Project", "1.1.1", True), ("Java Runtime", "Oracle", "8u401", True),
            ("Docker Engine", "Docker", "27.1", False), ("Python", "PSF", "3.9", True),
            ("nginx", "F5", "1.24", False), ("PostgreSQL", "PGDG", "13", True),
            ("Node.js", "OpenJS", "20.15", False), ("7-Zip", "Igor Pavlov", "22.01", False)]
BASELINES = [("CIS-1.1.1", "Password history not enforced", "medium"),
             ("CIS-2.3.1", "Guest account not disabled", "high"),
             ("CIS-5.2.4", "SSH root login permitted", "critical"),
             ("CIS-9.1.2", "Host firewall disabled", "high"),
             ("CIS-18.9.4", "Screen lock timeout too long", "low"),
             ("CIS-3.4.1", "Audit logging not configured", "high"),
             ("CIS-6.2.9", "World-writable files present", "medium")]
POLICIES = [("POL-001", "Information Security Policy"), ("POL-002", "Access Control Policy"),
            ("POL-003", "Acceptable Use Policy"), ("POL-004", "Data Classification Policy"),
            ("POL-005", "Business Continuity Policy"), ("POL-006", "Change Management Policy"),
            ("POL-007", "Third Party Security Policy"), ("POL-008", "Incident Response Policy"),
            ("POL-009", "Vulnerability Management Policy"), ("POL-010", "Cryptography Policy")]
SERVICES = [("Payments","tier1",480000),("Customer Portal","tier1",260000),
            ("Order Management","tier1",310000),("Payroll","tier2",40000),
            ("Internal Analytics","tier3",6000),("Partner API","tier2",95000)]
RISK_TITLES = [
    ("Unauthorised access to customer data","Cyber"),("Ransomware disrupting operations","Cyber"),
    ("Unpatched internet-facing vulnerability","Cyber"),("Insider data exfiltration","Cyber"),
    ("Third-party service outage","Operational"),("Failure of payment settlement","Operational"),
    ("Loss of key personnel","People"),("Regulatory reporting breach","Compliance"),
    ("Inadequate change control","Operational"),("Backup restoration failure","Resilience"),
]

# --------------------------------------------------------------------------- helpers
def daterange_days(a, b):
    return (b - a).days


def gen_day(rng, lo, hi):
    """A date on a caller-supplied stream, so late additions do not disturb the main one."""
    span = max(0, (hi - lo).days)
    return lo + dt.timedelta(days=rng.randint(0, span))

class Gen:
    def __init__(self, seed, today, scale):
        self.r = random.Random(seed)
        self.today = today
        self.start = today - dt.timedelta(days=365 * 3)
        self.scale = scale
        self.rows = {}

    def put(self, table, rows):
        self.rows.setdefault(table, []).extend(rows)

    def pick(self, seq):
        return self.r.choice(seq)

    def day(self, lo=None, hi=None):
        lo = lo or self.start
        hi = hi or self.today
        return lo + dt.timedelta(days=self.r.randint(0, max(0, daterange_days(lo, hi))))

    def ts(self, lo=None, hi=None):
        d = self.day(lo, hi)
        return dt.datetime.combine(d, dt.time(self.r.randint(0, 23), self.r.randint(0, 59)),
                                   tzinfo=dt.timezone.utc)

# --------------------------------------------------------------------------- build
def build(g: argparse.Namespace, gen: Gen):
    r, today, start = gen.r, gen.today, gen.start
    chaos = getattr(g, "chaos", 1)
    n_people   = int(500 * gen.scale)
    n_assets   = int(300 * gen.scale)
    n_apps     = int(25  * gen.scale)
    n_controls = 100
    n_reqs     = 100
    n_risks    = 40

    # ---- departments & people
    depts = [{"id": f"DEP-{i:03d}", "name": n, "cost_center": cc}
             for i, (n, cc) in enumerate(DEPTS, 1)]
    gen.put("department", [(d["id"], d["name"], d["cost_center"]) for d in depts])

    people, leavers = [], []
    for i in range(1, n_people + 1):
        pid = f"EMP-{i:04d}"
        fn, ln = gen.pick(FIRST), gen.pick(LAST)
        started = gen.day(start - dt.timedelta(days=365 * 6), today - dt.timedelta(days=20))
        ended = None
        if r.random() < 0.12:                       # 12% leavers over the window
            ended = gen.day(started + dt.timedelta(days=90), today)
            if ended > today:
                ended = None
        p = {"id": pid, "name": f"{fn} {ln}",
             "email": f"{fn.lower()}.{ln.lower()}{i}@acme.example",
             "dept": gen.pick(depts)["id"], "title": gen.pick(TITLES),
             "employment": "contractor" if r.random() < 0.15 else "employee",
             "started": started, "ended": ended}
        people.append(p)
        if ended:
            leavers.append(p)
    gen.put("person", [(p["id"], p["name"], p["email"], p["dept"], p["title"],
                        p["employment"], p["started"], p["ended"]) for p in people])

    # ---- accounts (orphaned access for some leavers = planted conflict)
    accounts, orphaned = [], []
    for i, p in enumerate(people, 1):
        for sysname in ("ad", "okta"):
            aid = f"IDN-{i:04d}-{sysname}"
            disabled = p["ended"]
            if p["ended"] and r.random() < 0.30:    # 30% of leavers keep an account
                disabled = None
                orphaned.append((p, aid))
            accounts.append((aid, p["id"], sysname,
                             p["email"].split("@")[0], r.random() < 0.08,
                             p["started"], disabled))
    gen.put("account", accounts)

    # ---- assets (IP recycling is real: pool smaller than asset count)
    pool = [str(ip) for ip in ipaddress.IPv4Network("10.42.0.0/17").hosts()][:int(n_assets * 0.8)]
    assets = []
    for i in range(1, n_assets + 1):
        aid = f"AST-{i:04d}"
        kind = "endpoint" if i <= n_assets * 0.75 else ("server" if i <= n_assets * 0.93 else "cloud")
        osf, osv = gen.pick(OS_ENDPOINT if kind == "endpoint" else OS_SERVER)
        host = f"{'LT' if kind=='endpoint' else ('SRV' if kind=='server' else 'CLD')}-{4000+i}"
        procured = gen.day(start - dt.timedelta(days=365 * 4), today - dt.timedelta(days=30))
        decom = gen.day(procured + dt.timedelta(days=200), today) if r.random() < 0.10 else None
        owner = gen.pick(people)["id"] if kind == "endpoint" else None
        crit = "critical" if kind != "endpoint" and r.random() < 0.25 else gen.pick(["low","medium","high"])
        assets.append({"id": aid, "host": host, "fqdn": f"{host.lower()}.corp.local",
                       "tag": f"AT-{900000+i}", "ip": gen.pick(pool), "kind": kind,
                       "osf": osf, "osv": osv, "owner": owner, "crit": crit,
                       "procured": procured, "decom": decom})
    gen.put("asset", [(a["id"], a["host"], a["fqdn"], a["tag"], a["ip"], a["kind"],
                       a["osf"], a["osv"], a["owner"], a["crit"], a["procured"], a["decom"])
                      for a in assets])

    # ---- applications & services
    apps = []
    for i in range(1, n_apps + 1):
        apps.append({"id": f"APP-{i:03d}", "name": f"{gen.pick(['Core','Edge','Atlas','Nexus','Orion','Vertex','Harbor','Ledger'])} {gen.pick(['Gateway','Service','Engine','Store','Console','Sync'])} {i}",
                     "owner": gen.pick(people)["id"], "crit": gen.pick(["low","medium","high","critical"])})
    gen.put("application", [(a["id"], a["name"], a["owner"], a["crit"]) for a in apps])

    servers = [a for a in assets if a["kind"] in ("server", "cloud")]
    app_asset = []
    for a in apps:
        for s in r.sample(servers, min(len(servers), r.randint(1, 4))):
            app_asset.append((a["id"], s["id"]))
    gen.put("application_asset", sorted(set(app_asset)))

    services = []
    for i, (name, tier, rev) in enumerate(SERVICES, 1):
        services.append({"id": f"SVC-{i:02d}", "name": name, "tier": tier,
                         "owner": gen.pick(people)["id"], "rev": rev})
    gen.put("business_service", [(s["id"], s["name"], s["tier"], s["owner"], s["rev"]) for s in services])

    # Service -> application dependencies.
    #
    # A dedicated random stream, so adding this logic does not shift every draw
    # that follows and silently rewrite the rest of the world.
    #
    # The previous version sampled 2-5 apps per service straight from the full
    # pool, which left ~40% of applications attached to nothing purely by
    # coupon-collector arithmetic, an accident that looked like a planted
    # condition. Coverage is now guaranteed, and a tuned slice is held back
    # deliberately and written into world.expectation so it is scoreable.
    r2 = random.Random(g.seed ^ 0x5EED)
    n_unmapped = max(1, int(len(apps) * 0.12))
    shuffled = apps[:]
    r2.shuffle(shuffled)
    unmapped_apps, mappable = shuffled[:n_unmapped], shuffled[n_unmapped:]

    svc_dep = []
    for i, a in enumerate(mappable):          # every mappable app gets a service
        svc_dep.append((services[i % len(services)]["id"], a["id"]))
    for s in services:                        # then depth: uneven, overlapping graphs
        for a in r2.sample(mappable, r2.randint(1, 3)):
            svc_dep.append((s["id"], a["id"]))
    gen.put("service_dependency", sorted(set(svc_dep)))

    # ---- framework, requirements, controls, mappings (coverage strength)
    gen.put("framework", [("FW-ISO27001", "ISO/IEC 27001", "2022")])
    reqs = []
    for i in range(1, n_reqs + 1):
        clause = 5 + (i - 1) // 12
        reqs.append({"id": f"REQ-{i:03d}", "ref": f"A.{clause}.{((i-1) % 12) + 1}",
                     "title": f"{gen.pick(CONTROL_THEMES)[0]} requirement {i}"})
    gen.put("requirement", [(q["id"], "FW-ISO27001", q["ref"], q["title"]) for q in reqs])

    # ---- second framework, crosswalk. Its own stream: adding it must not rewrite
    # the world that already exists.
    r4 = random.Random(g.seed ^ 0xC5F2)
    gen.put("framework", [("FW-NISTCSF", "NIST CSF", "2.0")])
    csf = [{"id": f"CSF-{i:03d}", "ref": ref, "title": title}
           for i, (ref, title) in enumerate(CSF, 1)]
    gen.put("requirement", [(q["id"], "FW-NISTCSF", q["ref"], q["title"]) for q in csf])

    # A crosswalk is a claim about equivalence, and it is rarely exact. Partial
    # equivalence is why a single control failure moves two frameworks by different
    # amounts, and why you can explain the difference rather than just compute it.
    cross = []
    for q in csf:
        for t in r4.sample(reqs, r4.randint(1, 3)):
            cross.append((q["id"], t["id"], round(r4.choice([0.25, 0.5, 0.75, 1.0]), 2)))
    gen.put("requirement_crosswalk", list({(a, b): (a, b, e) for a, b, e in cross}.values()))

    controls = []
    for i in range(1, n_controls + 1):
        theme, tag = CONTROL_THEMES[(i - 1) % len(CONTROL_THEMES)]
        owner = gen.pick(people)
        controls.append({"id": f"CTL-{i:03d}", "ref": f"C-{i:03d}",
                         "title": f"{theme}, control {i}", "tag": tag,
                         "owner": owner, "freq": gen.pick(["monthly","quarterly","annual"]),
                         "automated": r.random() < 0.4})
    gen.put("control", [(c["id"], c["ref"], c["title"], c["owner"]["id"], c["freq"], c["automated"])
                        for c in controls])

    mappings = []
    for c in controls:
        for q in r.sample(reqs, r.randint(1, 3)):
            mappings.append((c["id"], q["id"], round(r.choice([0.25, 0.5, 0.75, 1.0]), 2)))
    for c in controls:
        for q in r4.sample(csf, r4.randint(1, 3)):
            mappings.append((c["id"], q["id"], round(r4.choice([0.25, 0.5, 0.75, 1.0]), 2)))
    gen.put("control_mapping", list({(a, b): (a, b, cv) for a, b, cv in mappings}.values()))

    # ---- control tests across three years
    # ~8% of controls are defined in the framework but never operationalised:
    # no tests, no findings, no evidence, no signal at all. Silence is not health.
    never_tested = set(x["id"] for x in r.sample(controls, max(1, int(len(controls) * 0.08))))

    freq_days = {"monthly": 30, "quarterly": 91, "annual": 365}
    tests, latest_result = [], {}
    for c in controls:
        if c["id"] in never_tested:
            continue
        step = freq_days[c["freq"]]
        d = start
        k = 0
        while d < today:
            k += 1
            # drift: some controls degrade in the middle of the window and recover
            drift = 0.35 if (r.random() < 0.25 and start + dt.timedelta(days=400) < d <
                             today - dt.timedelta(days=200)) else 0.10
            res = "ineffective" if r.random() < drift * 0.5 else ("partial" if r.random() < drift else "effective")
            tests.append((f"CTT-{c['id']}-{k:03d}", c["id"], d, res, gen.pick(people)["id"]))
            latest_result[c["id"]] = (d, res)
            d += dt.timedelta(days=step + r.randint(-5, 5))
    gen.put("control_test", tests)

    # ---- audits & findings
    audits, findings = [], []
    for yr in range(3):
        a_start = start + dt.timedelta(days=365 * yr + 30)
        audits.append((f"AUD-{yr+1}", f"Annual ISO 27001 audit {a_start.year}", "FW-ISO27001",
                       a_start, a_start + dt.timedelta(days=45)))
    n_find = 0
    for aid, _, _, a_start, _ in audits:
        for _ in range(r.randint(18, 26)):
            n_find += 1
            c = gen.pick([x for x in controls if x["id"] not in never_tested])
            sev = gen.pick(["low","medium","high","critical"])
            raised = a_start + dt.timedelta(days=r.randint(0, 45))
            due = raised + dt.timedelta(days={"low":180,"medium":120,"high":60,"critical":30}[sev])
            closed = None
            if r.random() < 0.62:
                closed = raised + dt.timedelta(days=r.randint(10, 260))
                if closed > today:
                    closed = None
            status = "closed" if closed else ("overdue" if due < today else "open")
            findings.append({"id": f"AF-{n_find:03d}", "audit": aid, "control": c["id"],
                             "title": f"{c['title'].split('. ')[0]} not consistently performed",
                             "sev": sev, "raised": raised, "due": due, "closed": closed,
                             "status": status})
    gen.put("finding", [(f["id"], f["audit"], f["control"], f["title"], f["sev"],
                         f["raised"], f["due"], f["closed"], f["status"]) for f in findings])
    gen.put("audit", audits)

    # ---- audit attachments (binary evidence). Metadata only; bytes are generated
    # on read by the twin, so the world stays small and still reproducible.
    DOCS = [("evidence-memo", "text/plain", "txt"), ("control-test-report", "application/pdf", "pdf"),
            ("screenshot", "image/png", "png"), ("access-review-export", "text/csv", "csv")]
    atts, n_att = [], 0
    for f in findings:
        for _ in range(r4.randint(0, 3)):
            n_att += 1
            kind, media, ext = DOCS[r4.randrange(len(DOCS))]
            # one attachment in twenty is deliberately over the download limit
            size = r4.randint(6_000_000, 9_000_000) if r4.random() < 0.05 \
                else r4.randint(1_200, 480_000)
            aid = f"ATT-{n_att:04d}"
            atts.append((aid, f["id"], f"{kind}-{f['id']}.{ext}", media, size,
                         f["raised"] + dt.timedelta(days=r4.randint(0, 20)),
                         hashlib.sha256(aid.encode()).hexdigest()))
    gen.put("attachment", atts)

    # ---- risks
    risks = []
    for i in range(1, n_risks + 1):
        title, cat = RISK_TITLES[(i - 1) % len(RISK_TITLES)]
        period = gen.pick([90, 90, 180])
        # ~15% of risks are demonstrably overdue for review: planted conflict
        stale = r.random() < 0.15
        last_rev = today - dt.timedelta(days=period + r.randint(30, 300) if stale
                                        else r.randint(5, period - 10))
        risks.append({"id": f"RSK-{i:03d}", "ref": f"R-{i:03d}", "title": f"{title} ({i})",
                      "cat": cat, "inherent": round(r.uniform(9, 25), 1),
                      "appetite": round(r.uniform(4, 10), 1),
                      "owner": gen.pick(people)["id"], "last_rev": last_rev,
                      "period": period, "stale": stale})
    gen.put("risk", [(x["id"], x["ref"], x["title"], x["cat"], x["inherent"], x["appetite"],
                      x["owner"], x["last_rev"], x["period"]) for x in risks])

    rc, rs = [], []
    for x in risks:
        for c in r.sample(controls, r.randint(2, 5)):
            rc.append((x["id"], c["id"], round(r.uniform(0.1, 0.5), 2)))
        for s in r.sample(services, r.randint(1, 2)):
            rs.append((x["id"], s["id"]))
    gen.put("risk_control", list({(a, b): (a, b, c) for a, b, c in rc}.values()))
    gen.put("risk_service", sorted(set(rs)))

    # ---- detection rules & alerts
    rules = [(f"RUL-{i:02d}", n, s) for i, (n, tag, s) in enumerate(RULES, 1)]
    rule_tag = {f"RUL-{i:02d}": tag for i, (n, tag, s) in enumerate(RULES, 1)}
    gen.put("detection_rule", rules)

    live_assets = [a for a in assets if a["decom"] is None]
    alerts = []
    n_alerts = int(20000 * gen.scale)
    for i in range(1, n_alerts + 1):
        rid = gen.pick(rules)[0]
        a = gen.pick(live_assets)
        alerts.append((f"ALR-{i:06d}", rid, a["id"], gen.pick(people)["id"],
                       gen.pick(["low","medium","high"]), gen.ts()))
    gen.put("alert", alerts)

    # ---- incidents (one planted tier-1 "no impact" contradiction)
    incidents, planted_incidents = [], []
    for i in range(1, int(120 * gen.scale) + 1):
        s = gen.pick(services)
        opened = gen.ts()
        closed = opened + dt.timedelta(hours=r.randint(2, 200))
        sev = r.randint(1, 4)
        impact = "no customer impact" if r.random() < 0.45 else "customer impacting"
        inc = (f"INC-{i:04d}", f"INC-{opened.year}-{i:04d}",
               f"{gen.pick(['Degraded','Outage','Data issue','Access failure'])} on {s['name']}",
               gen.pick(["Unauthorised Access","Availability","Data Integrity","Malware"]),
               sev, s["id"], opened, closed, impact)
        incidents.append(inc)
        if s["tier"] == "tier1" and impact == "no customer impact" and sev <= 2:
            planted_incidents.append((inc[0], s))
    gen.put("incident", incidents)

    # ---- vulnerabilities
    vulns = []
    for i in range(1, int(1500 * gen.scale) + 1):
        a = gen.pick(live_assets)
        disc = gen.day()
        rem = disc + dt.timedelta(days=r.randint(3, 220)) if r.random() < 0.7 else None
        if rem and rem > today:
            rem = None
        # The year is deliberately impossible. CVE years are assignment years, so
        # nothing will ever be issued in the 9000s, and an identifier from this world
        # can therefore never be mistaken for a real advisory or looked up and acted
        # on. The draw is still randint(2022, 2026) so that the random stream, and
        # therefore every downstream value in the world, is unchanged.
        vulns.append((f"VUL-{i:05d}", a["id"],
                      f"CVE-{r.randint(2022, 2026) + 7000}-{r.randint(1000,49999)}",
                      round(r.uniform(3.1, 9.9), 1), disc, rem))
    gen.put("vulnerability", vulns)

    # ---- evidence: TRUE attribution plus deliberate traps
    # never-operationalised controls are excluded from every evidence pool:
    # they must end up with genuinely zero signal.
    evidenceable = [c for c in controls if c["id"] not in never_tested]
    theme_controls = {}
    for c in evidenceable:
        theme_controls.setdefault(c["tag"], []).append(c)

    evid, n_ev = [], 0
    # control tests are always evidence for their own control
    for tid, cid, d, res, _ in tests:
        n_ev += 1
        evid.append((f"EVD-{n_ev:06d}", "control_test", tid, cid, 1.0,
                     dt.datetime.combine(d, dt.time(9, 0), tzinfo=dt.timezone.utc), False))
    # findings are evidence for their control
    for f in findings:
        n_ev += 1
        evid.append((f"EVD-{n_ev:06d}", "finding", f["id"], f["control"], 0.9,
                     dt.datetime.combine(f["raised"], dt.time(9, 0), tzinfo=dt.timezone.utc), False))
    # a sample of alerts is genuine evidence for a control sharing the rule's theme;
    # A slice is a TRAP: the event is linked to a control it does not evidence.
    # The decoy is drawn from the whole control library rather than from the rule's
    # own theme, so it is not reliably topically adjacent. What it measures is
    # whether a system will assert a link it cannot support, which is the failure
    # that matters. Making decoys same-theme would make them more tempting but
    # also unlearnable, since the world models no signal that would separate them.
    sample = r.sample(alerts, min(len(alerts), int(4000 * gen.scale)))
    for al in sample:
        tag = rule_tag[al[1]]
        pool_c = theme_controls.get(tag) or evidenceable
        trap = r.random() < 0.18
        c = gen.pick(evidenceable if trap else pool_c)
        n_ev += 1
        evid.append((f"EVD-{n_ev:06d}", "alert", al[0], c["id"],
                     round(r.uniform(0.2, 0.6), 2), al[5], trap))
    gen.put("evidence", evid)

    # controls with NO evidence source at all -> absence expectations
    have_ev = {e[3] for e in evid if not e[6]}
    uncovered = [c for c in controls if c["id"] not in have_ev]

    r5 = random.Random(g.seed ^ 0xDA1)
    # business process, the Service -> Process hop the spine draws
    procs = [{"id": f"BP-{i:02d}", "name": n, "crit": crit, "rto": rto,
              "owner": people[r5.randrange(len(people))]["id"]}
             for i, (n, crit, rto) in enumerate(PROCESSES, 1)]
    gen.put("business_process", [(p_["id"], p_["name"], p_["owner"], p_["crit"], p_["rto"])
                                 for p_ in procs])
    ps = []
    for p_ in procs:
        for sv in r5.sample(services, r5.randint(1, 3)):
            ps.append((p_["id"], sv["id"]))
    gen.put("process_service", sorted(set(ps)))


    # ---- lenses (all loss lives here)
    #
    # The chaos dial (DESIGN.md #4.4) lives in the loss profiles, never in the world.
    # The world is always true; only what the lenses do to it changes.
    #
    #   0  pristine      one identifier scheme, complete coverage, no staleness
    #   1  realistic     recycled IPs, four naming schemes, gaps, stale rows
    #   2  pathological  level 1 plus collisions, homoglyphs, whitespace, case drift
    base_lenses = [
        ("splunk",     "Splunk",     "siem",   0.83, 5,    "ip",        90,
         "assets with no forwarder installed"),
        ("servicenow", "ServiceNow", "itsm",   0.97, 1440, "fqdn",      3650,
         "assets procured outside IT"),
        # Coverage of the estate is partial and the blind spot says why: a GRC
        # platform knows what was typed into it, not what exists. It still holds the
        # whole control library, that is its own domain, entered by definition.
        ("grc",        "Onspring",   "grc",    0.91, 10080,"asset_tag", 3650,
         "assets never entered into the register by hand"),
        # Appended AFTER the original three on purpose: the loop below draws from the
        # main random stream, and nothing after it does. Adding lenses here therefore
        # leaves the rest of the world byte-identical.
        ("iam",        "Okta",       "iam",    0.94, 15,   "username",  3650,
         "accounts in systems that were never federated to the IdP"),
        ("scanner",    "Tenable",    "vuln",   0.88, 1440, "hostname",  365,
         "assets that have never been scanned, including anything off the corporate network"),
        # HR is the system of record for employees and knows nothing about anyone
        # engaged through an agency. That blind spot is the point: a departed
        # contractor cannot be confirmed as a leaver from HR at all.
        ("hr",         "Workday",    "hcm",    1.00, 1440, "employee_id", 3650,
         "contractors, they are engaged through vendor management, not HR"),
        ("edr",        "CrowdStrike","edr",    0.79, 5,    "agent_id",  30,
         "assets where the agent was never deployed"),
    ]

    if chaos == 0:
        # Everything names things the same way and nothing is stale or missing.
        # Correlation becomes trivial, which is the point: baseline regression.
        # People-facing lenses share one scheme, asset-facing lenses share another.
        lenses = [(lid, v, cat, 1.00, 0,
                   "username" if cat in ("iam", "hcm") else "fqdn", 36500,
                   "nothing, chaos level 0 is the pristine baseline")
                  for lid, v, cat, _c, _l, _st, _r, _b in base_lenses]
    else:
        lenses = base_lenses
    gen.put("lens", lenses)

    def agent_id(a):
        """Opaque to everything else in the world, an EDR names machines by the
        agent it installed, not by anything the machine itself carries."""
        h = hashlib.sha1(a["id"].encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    ident = {"ip": lambda a: str(a["ip"]), "fqdn": lambda a: a["fqdn"],
             "hostname": lambda a: a["host"], "asset_tag": lambda a: a["tag"],
             "agent_id": agent_id}
    vis, unseen_by_security, silent_agents = [], [], []
    for lid, _, cat, cov, lat, style, _ret, _bs in lenses:
        if cat == "hcm":
            for i, p in enumerate(people, 1):
                if chaos and p["employment"] == "contractor":
                    continue                      # the blind spot, applied
                # At chaos 0 HR names people the same way the IdP does, so the join
                # is free. That is what "one identifier scheme" has to mean.
                ext = p["email"].split("@")[0] if chaos == 0 else f"WD-{100000 + i}"
                vis.append((lid, "person", p["id"], ext,
                            dt.datetime.combine(today, dt.time(6, 0), tzinfo=dt.timezone.utc)))
            continue
        if cat == "edr":
            # Agent health is a property of the data, not an injected failure: some
            # agents are installed and simply stopped reporting weeks ago.
            for a in assets:
                if a["decom"] is not None or r.random() >= cov:
                    continue
                silent = r.random() < 0.12
                age = r.randint(9, 40) * 24 if silent else r.randint(0, 3)
                if chaos == 0:            # draws already taken, results overridden
                    silent, age = False, 0
                vis.append((lid, "asset", a["id"],
                            ident[style](a) if chaos == 0 else agent_id(a),
                            dt.datetime.combine(today, dt.time(8, 0), tzinfo=dt.timezone.utc)
                            - dt.timedelta(hours=age)))
                if silent:
                    silent_agents.append((a, age // 24))
            continue
        if cat == "iam":
            # The directory sees people, not machines, and knows them by their login.
            # A fifth naming scheme: correlating "control owner Sarah Chen" to a login
            # is entity resolution across a name, not an id.
            for p in people:
                if r.random() < cov:
                    vis.append((lid, "person", p["id"], p["email"].split("@")[0],
                                dt.datetime.combine(today, dt.time(8, 0), tzinfo=dt.timezone.utc)
                                - dt.timedelta(minutes=r.randint(0, 240))))
            continue
        seen_assets = [a for a in assets if r.random() < cov]
        for a in seen_assets:
            stale_h = r.randint(0, 24) if lid != "servicenow" else r.randint(0, 72)
            if chaos == 0:
                stale_h = 0
            vis.append((lid, "asset", a["id"], ident[style](a),
                        dt.datetime.combine(today, dt.time(8, 0), tzinfo=dt.timezone.utc)
                        - dt.timedelta(hours=stale_h)))
        if cat == "grc":
            for c in controls:
                vis.append((lid, "control", c["id"], c["ref"],
                            dt.datetime.combine(today, dt.time(8, 0), tzinfo=dt.timezone.utc)))
        if cat == "itsm":
            # The CMDB carries the application and service layer, and names CIs by
            # their name, not by the fqdn it uses for computers. Same lens, two
            # identifier styles, which is what real CMDBs actually do.
            stamp = dt.datetime.combine(today, dt.time(8, 0), tzinfo=dt.timezone.utc)
            for ap in apps:
                if r2.random() < cov:                       # same coverage loss as assets
                    vis.append((lid, "application", ap["id"], ap["name"], stamp))
            for sv in services:                             # services are always registered
                vis.append((lid, "business_service", sv["id"], sv["name"], stamp))
            for pr in procs:                                # and so are business processes
                vis.append((lid, "business_process", pr["id"], pr["name"], stamp))
    mangled = 0
    if chaos >= 2:
        # Level 2 is for fuzzing, not scoring: identifiers stop being trustworthy
        # keys. A connector that assumes they are clean breaks here, which is the
        # whole reason this level exists.
        r3 = random.Random(g.seed ^ 0xC0FFEE)
        HOMOGLYPH = {"o": "\u043e", "a": "\u0430", "e": "\u0435", "c": "\u0441", "p": "\u0440"}
        by_lens = {}
        for i, (lid, kind, eid, ext, seen) in enumerate(vis):
            by_lens.setdefault(lid, []).append(i)
        for lid, idxs in by_lens.items():
            for i in idxs:
                lid_, kind, eid, ext, seen = vis[i]
                roll = r3.random()
                if roll < 0.02:                                   # trailing whitespace
                    ext = ext + " "
                elif roll < 0.04:                                 # case drift
                    ext = ext.upper() if ext.islower() else ext.lower()
                elif roll < 0.06:                                 # cyrillic homoglyph
                    for a, b in HOMOGLYPH.items():
                        if a in ext:
                            ext = ext.replace(a, b, 1)
                            break
                elif roll < 0.07 and len(idxs) > 1:               # id collision
                    ext = vis[r3.choice(idxs)][3]
                else:
                    continue
                vis[i] = (lid_, kind, eid, ext, seen)
                mangled += 1

    gen.put("lens_visibility", vis)

    seen_by = {}
    for lid, kind, eid, *_ in vis:
        seen_by.setdefault(eid, set()).add(lid)
    SECURITY_LENSES = {"splunk", "scanner", "edr"}
    scanned_not_monitored = []
    for a in assets:
        if a["decom"] is not None:
            continue
        seen = seen_by.get(a["id"], set())
        if not (seen & SECURITY_LENSES):
            unseen_by_security.append(a)
        elif "scanner" in seen and "splunk" not in seen:
            # A subtler gap than total darkness, and the more common one in real
            # estates: the machine is inventoried and scanned, but nothing watches it.
            scanned_not_monitored.append(a)

    # ---- expectations: the assertion catalogue, materialised
    exp, n_exp = [], 0

    def add(family, kind, sid, claim, detail):
        nonlocal n_exp
        n_exp += 1
        exp.append((f"EXP-{n_exp:05d}", family, kind, sid, claim, Json(detail)))

    for a in unseen_by_security[:200]:
        add("absence", "asset", a["id"],
            "asset is live and in ITSM but invisible to every security lens",
            {"hostname": a["host"], "criticality": a["crit"]})
    edr_seen = {eid for lid, kind, eid, *_ in vis if lid == "edr"}
    for a in assets:
        if a["decom"] is None and a["id"] not in edr_seen:
            add("absence", "asset", a["id"],
                "asset is live but carries no endpoint protection agent",
                {"hostname": a["host"], "criticality": a["crit"]})
    for a, days in silent_agents:
        # The first degradation-family rows that come from the world rather than from
        # WireMock: the source is not down, it is quietly stale for this one machine.
        add("degradation", "asset", a["id"],
            "endpoint agent is installed but has not reported in over a week",
            {"hostname": a["host"], "days_silent": days})
    for p in people:
        if p["ended"] and p["employment"] == "contractor":
            add("absence", "person", p["id"],
                "leaver is a contractor, so no HR record confirms the termination",
                {"left_on": p["ended"].isoformat(), "employment": p["employment"]})
    for a in scanned_not_monitored[:200]:
        add("absence", "asset", a["id"],
            "asset is scanned for vulnerabilities but monitored by no SIEM",
            {"hostname": a["host"], "criticality": a["crit"]})
    for c in uncovered:
        add("absence", "control", c["id"],
            "control has no evidence source of any kind",
            {"ref": c["ref"], "title": c["title"]})
    for ap in sorted(unmapped_apps, key=lambda x: x["id"]):
        add("absence", "application", ap["id"],
            "application is not attached to any business service",
            {"name": ap["name"], "criticality": ap["crit"]})
    for p, aid in orphaned:
        add("conflict", "person", p["id"],
            "person has left but an account remains enabled",
            {"left_on": p["ended"].isoformat(), "account": aid})
    for c in controls:
        if c["owner"]["ended"]:
            add("conflict", "control", c["id"],
                "control owner of record has left the company",
                {"owner": c["owner"]["id"], "left_on": c["owner"]["ended"].isoformat()})
    for x in risks:
        if x["stale"]:
            add("conflict", "risk", x["id"],
                "risk presented as current but review period has lapsed",
                {"last_reviewed_on": x["last_rev"].isoformat(), "period_days": x["period"]})
    for iid, s in planted_incidents:
        add("conflict", "incident", iid,
            "incident recorded as no customer impact on a tier-1 service",
            {"service": s["id"], "tier": s["tier"]})
    # effective-but-contradicted controls
    for c in controls:
        if c["id"] not in latest_result:
            continue
        d, res = latest_result[c["id"]]
        overdue = [f for f in findings if f["control"] == c["id"] and f["status"] == "overdue"]
        if res == "effective" and overdue:
            add("conflict", "control", c["id"],
                "control tested effective while an overdue audit finding stands against it",
                {"tested_on": d.isoformat(), "findings": [f["id"] for f in overdue]})
    for e in evid:
        if e[6]:
            add("attribution", "evidence", e[0],
                "evidence is linked to a control it does not evidence",
                {"control_id": e[3], "source": e[2]})


    # ---- the day-one domains DESIGN.md #3 names but that were never built:
    # business processes, policies, exceptions, treatments, software inventory,
    # misconfigurations, groups and entitlements. Own stream, so adding them does
    # not rewrite the world that already exists.
    # software inventory, including software past end of life
    sw = [{"id": f"SW-{i:03d}", "name": n, "pub": pub, "ver": v,
           "eol": (today - dt.timedelta(days=r5.randint(30, 900))) if eol else None}
          for i, (n, pub, v, eol) in enumerate(SOFTWARE, 1)]
    gen.put("software", [(x["id"], x["name"], x["pub"], x["ver"], x["eol"]) for x in sw])
    inst = []
    for a in assets:
        if a["decom"] is not None:
            continue
        for x in r5.sample(sw, r5.randint(2, 6)):
            inst.append((a["id"], x["id"], gen_day(r5, a["procured"], today)))
    gen.put("software_install", sorted(set(inst)))

    # misconfigurations against a CIS-style baseline
    mis, n_mis = [], 0
    for a in assets:
        if a["decom"] is not None:
            continue
        for _ in range(r5.randint(0, 3)):
            n_mis += 1
            ref, title, sev = BASELINES[r5.randrange(len(BASELINES))]
            det = gen_day(r5, start, today)
            rem = det + dt.timedelta(days=r5.randint(5, 200)) if r5.random() < 0.55 else None
            if rem and rem > today:
                rem = None
            mis.append((f"MIS-{n_mis:05d}", a["id"], ref, title, sev, det, rem))
    gen.put("misconfiguration", mis)

    # policies, and the controls that implement them
    pols = [{"id": f"PLC-{i:03d}", "ref": ref, "title": t,
             "owner": people[r5.randrange(len(people))]["id"],
             "approved": gen_day(r5, start, today - dt.timedelta(days=30)),
             "period": r5.choice([365, 365, 730])}
            for i, (ref, t) in enumerate(POLICIES, 1)]
    gen.put("policy", [(x["id"], x["ref"], x["title"], x["owner"], x["approved"], x["period"])
                       for x in pols])
    pc, uncovered_policies = [], []
    for x in pols:
        # two policies are deliberately implemented by nothing at all
        if r5.random() < 0.2:
            uncovered_policies.append(x)
            continue
        for cc in r5.sample(controls, r5.randint(2, 6)):
            pc.append((x["id"], cc["id"]))
    gen.put("policy_control", sorted(set(pc)))

    # control exceptions, some expired but still recorded as active
    exc, n_exc, stale_exc = [], 0, []
    for cc in r5.sample(controls, 18):
        n_exc += 1
        approved = gen_day(r5, start + dt.timedelta(days=200), today - dt.timedelta(days=40))
        expires = approved + dt.timedelta(days=r5.choice([90, 180, 365]))
        lapsed = expires < today
        # the platform keeps calling it active even once the date has passed
        status = "active" if (not lapsed or r5.random() < 0.6) else "expired"
        exc.append((f"EXC-{n_exc:03d}", cc["id"],
                    r5.choice(["compensating control in place", "vendor limitation",
                               "scheduled for remediation", "legacy system, migration planned"]),
                    cc["owner"]["id"], approved, expires, status))
        if lapsed and status == "active":
            stale_exc.append((f"EXC-{n_exc:03d}", cc, expires))
    gen.put("control_exception", exc)

    # risk treatments
    trt, n_trt, overdue_trt = [], 0, []
    for x in risks:
        for _ in range(r5.randint(1, 2)):
            n_trt += 1
            strategy = r5.choice(["mitigate", "mitigate", "accept", "transfer", "avoid"])
            target = gen_day(r5, start + dt.timedelta(days=300), today + dt.timedelta(days=200))
            done = target - dt.timedelta(days=r5.randint(0, 60)) if r5.random() < 0.5 else None
            if done and done > today:
                done = None
            status = "complete" if done else ("overdue" if target < today else
                                              r5.choice(["planned", "in_progress"]))
            trt.append((f"TRT-{n_trt:03d}", x["id"], strategy,
                        f"{strategy.title()}, {x['title']}",
                        people[r5.randrange(len(people))]["id"], target, done, status))
            if status == "overdue" and x["inherent"] > x["appetite"]:
                overdue_trt.append((f"TRT-{n_trt:03d}", x, target))
    gen.put("risk_treatment", trt)

    # access groups and membership, retained privileged access is a real conflict
    groups = [{"id": f"GRP-{i:02d}", "name": n, "sys": sysn, "priv": priv}
              for i, (n, sysn, priv) in enumerate([
                  ("Domain Admins", "ad", True), ("Server Operators", "ad", True),
                  ("Finance Readers", "ad", False), ("All Staff", "okta", False),
                  ("Payments Admins", "okta", True), ("Support Agents", "okta", False),
                  ("Engineering", "okta", False), ("Backup Operators", "ad", True)], 1)]
    gen.put("access_group", [(x["id"], x["name"], x["sys"], x["priv"]) for x in groups])
    mem, retained_priv = [], []
    by_person = {}
    for acc in accounts:
        by_person.setdefault(acc[1], []).append(acc)
    for p_ in people:
        for acc in by_person.get(p_["id"], []):
            for gp in r5.sample([x for x in groups if x["sys"] == acc[2]],
                                r5.randint(0, 2)):
                revoked = p_["ended"]
                if p_["ended"] and r5.random() < 0.25:
                    revoked = None                       # never revoked
                    if gp["priv"]:
                        retained_priv.append((p_, gp))
                mem.append((gp["id"], acc[0], acc[5], revoked))
    gen.put("group_membership", list({(a, b): (a, b, c, d) for a, b, c, d in mem}.values()))

    for x in uncovered_policies:
        add("absence", "policy", x["id"],
            "policy is approved but no control implements it",
            {"ref": x["ref"], "title": x["title"]})
    for eid, cc, expires in stale_exc:
        add("conflict", "control", cc["id"],
            "control exception is recorded as active but its expiry date has passed",
            {"exception": eid, "expired_on": expires.isoformat()})
    for tid, x, target in overdue_trt:
        add("conflict", "risk", x["id"],
            "risk treatment is overdue while the risk remains above appetite",
            {"treatment": tid, "target_date": target.isoformat(),
             "inherent": float(x["inherent"]), "appetite": float(x["appetite"])})
    for p_, gp in retained_priv:
        add("conflict", "person", p_["id"],
            "person has left but retains membership of a privileged group",
            {"group": gp["name"], "left_on": p_["ended"].isoformat()})
    eol_ids = {x["id"] for x in sw if x["eol"]}
    eol_assets = sorted({aid for aid, sid, _ in inst if sid in eol_ids})
    for aid in eol_assets[:200]:
        add("absence", "asset", aid,
            "asset runs software that is past its end-of-life date",
            {"packages": sorted({x["name"] for x in sw
                                 if x["id"] in {s2 for a2, s2, _ in inst if a2 == aid}
                                 and x["eol"]})[:4]})
    gen.put("expectation", exp)

    gen.put("world_meta", [
        ("seed", str(g.seed)), ("as_of", today.isoformat()),
        ("history_start", start.isoformat()), ("scale", str(gen.scale)),
        ("chaos", str(chaos)), ("mangled_identifiers", str(mangled)),
        ("generator_version", "3"),
    ])

# --------------------------------------------------------------------------- load
ORDER = ["department","person","account","asset","application","business_service",
         "application_asset","service_dependency","framework","requirement","control",
         "control_mapping","requirement_crosswalk","control_test","audit","finding",
         "attachment","risk","risk_control",
         "risk_service","risk_treatment","policy","policy_control","control_exception",
         "access_group","group_membership","software","software_install",
         "business_process","process_service","misconfiguration",
         "detection_rule","alert","incident","vulnerability","evidence",
         "lens","lens_visibility","expectation","world_meta"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default="postgresql://vo@127.0.0.1:5433/world")
    ap.add_argument("--seed", type=int, default=48392)
    ap.add_argument("--as-of", default="2026-08-21")
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--chaos", type=int, default=1, choices=[0, 1, 2],
                    help="0 pristine, 1 realistic (default), 2 pathological")
    g = ap.parse_args()

    today = dt.date.fromisoformat(g.as_of)
    gen = Gen(g.seed, today, g.scale)
    build(g, gen)

    conn = psycopg2.connect(g.dsn)
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute("SET search_path TO world")
    for t in reversed(ORDER):
        cur.execute(f"TRUNCATE {t} CASCADE")
    for t in ORDER:
        rows = gen.rows.get(t, [])
        if not rows:
            continue
        ncols = len(rows[0])
        execute_values(cur, f"INSERT INTO {t} VALUES %s",
                       rows, template="(" + ",".join(["%s"] * ncols) + ")", page_size=2000)
    conn.commit()

    cur.execute("""SELECT family, count(*) FROM expectation GROUP BY 1 ORDER BY 1""")
    fams = cur.fetchall()
    print(f"seed={g.seed} as_of={today} scale={gen.scale} chaos={g.chaos}")
    for t in ORDER:
        n = len(gen.rows.get(t, []))
        if n:
            print(f"  {t:<20} {n:>7}")
    print("expectations by family:", dict(fams))
    conn.close()

if __name__ == "__main__":
    main()
