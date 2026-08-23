"""
Reachability probes. The Control Center answers "is everything running" by asking
each dependency the question that actually matters, can it be reached and does it
answer correctly, rather than by reading container state from the Docker daemon.

It never mutates anything it probes.
"""
import os
import httpx
from twins import db

TWIN = os.environ.get("VO_TWIN_BASE", "http://twin-gateway:8080")
KEYCLOAK = os.environ.get("VO_KEYCLOAK_BASE", "http://keycloak:8080")
WIREMOCK = os.environ.get("VO_WIREMOCK_BASE", "http://wiremock:8080")
TOKEN = os.environ.get("VO_TOKEN", "vo-dev-token")
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _http(name, url, expect=200, headers=None, optional=False):
    """Keycloak serves /health on its management port, not 8080, probe a real
    endpoint the service actually answers on instead of a health path that 404s."""
    try:
        r = httpx.get(url, headers=headers or {}, timeout=4)
        ok = r.status_code == expect
        return {"name": name, "state": "up" if ok else ("off" if optional else "degraded"),
                "detail": f"HTTP {r.status_code}", "url": url, "optional": optional}
    except Exception as e:
        return {"name": name, "state": "off" if optional else "down",
                "detail": type(e).__name__, "url": url, "optional": optional}


def world_db():
    try:
        n = db.one("SELECT count(*) n FROM asset")["n"]
        meta = db.one("SELECT value FROM world_meta WHERE key = 'as_of'")
        return {"name": "world-db", "state": "up",
                "detail": f"{n} assets · as-of {meta['value'] if meta else '?'}",
                "url": "postgres", "optional": False}
    except Exception as e:
        return {"name": "world-db", "state": "down", "detail": type(e).__name__,
                "url": "postgres", "optional": False}


def all_probes():
    return [
        world_db(),
        _http("twin-gateway", f"{TWIN}/healthz"),
        _http("keycloak", f"{KEYCLOAK}/realms/master", optional=True),
        _http("wiremock", f"{WIREMOCK}/__admin/mappings", optional=True),
    ]


def lens_reachability():
    """One live call per lens, through the twin, exactly as a connector would."""
    checks = [
        ("servicenow", "GET /servicenow/api/now/table/cmdb_ci_computer",
         f"{TWIN}/servicenow/api/now/table/cmdb_ci_computer?sysparm_limit=1"),
        ("grc", "GET /grc/api/v1/controls", f"{TWIN}/grc/api/v1/controls?limit=1"),
        ("iam", "GET /iam/api/v1/users", f"{TWIN}/iam/api/v1/users?limit=1"),
        ("scanner", "GET /scanner/api/v3/findings", f"{TWIN}/scanner/api/v3/findings?limit=1"),
        ("hr", "GET /hr/api/v1/workers", f"{TWIN}/hr/api/v1/workers?per_page=1"),
        ("edr", "GET /edr/devices/queries/devices/v1", f"{TWIN}/edr/devices/queries/devices/v1?limit=1"),
    ]
    out = []
    for lens_id, label, url in checks:
        try:
            r = httpx.get(url, headers=AUTH, timeout=6)
            out.append({"lens": lens_id, "call": label, "state": "up" if r.status_code == 200
                        else "degraded", "detail": f"HTTP {r.status_code}"})
        except Exception as e:
            out.append({"lens": lens_id, "call": label, "state": "down", "detail": type(e).__name__})
    # Splunk is an async job: submit -> poll -> the connector pattern most likely to break
    try:
        sid = httpx.post(f"{TWIN}/splunk/services/search/jobs", headers=AUTH,
                         data={"search": "search index=main"}, timeout=8).json()["sid"]
        state = "degraded"
        for _ in range(4):
            s = httpx.get(f"{TWIN}/splunk/services/search/jobs/{sid}",
                          headers=AUTH, timeout=8).json()["entry"][0]["content"]
            if s["isDone"]:
                state = "up"
                break
        out.insert(1, {"lens": "splunk", "call": "POST job → poll → DONE",
                       "state": state, "detail": f"sid {sid[:8]}…"})
    except Exception as e:
        out.insert(1, {"lens": "splunk", "call": "POST job → poll → DONE",
                       "state": "down", "detail": type(e).__name__})
    return out


def twin_call(method, path, params=None, data=None, profile=None):
    """Surface 3's try-it console. Executes against the real twin, returns raw."""
    headers = dict(AUTH)
    if profile:
        headers["X-VO-Profile"] = profile
    url = f"{TWIN}{path}"
    try:
        if method == "POST":
            r = httpx.post(url, headers=headers, data=data or {}, timeout=30)
        else:
            r = httpx.get(url, headers=headers, params=params or {}, timeout=30)
        body = r.text
        return {"status": r.status_code, "body": body, "url": str(r.url),
                "headers": dict(r.headers)}
    except Exception as e:
        return {"status": 0, "body": f"{type(e).__name__}: {e}", "url": url, "headers": {}}


def lens_note(lens_id):
    """The twin's own coverage note, including whether it enforces its window.
    Read from the API rather than restated here, so the page cannot drift from it."""
    try:
        return httpx.get(f"{TWIN}/_lens/{lens_id}", headers=AUTH, timeout=6).json()
    except Exception:
        return None


def provenance():
    """#5's standing hazard, surfaced. A hazard nobody can see is not mitigated."""
    try:
        return httpx.get(f"{TWIN}/_provenance", headers=AUTH, timeout=6).json()
    except Exception as e:
        return {"lenses": {}, "unverified": [], "certified": False,
                "warning": f"provenance unavailable: {type(e).__name__}"}
