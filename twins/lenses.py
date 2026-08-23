"""
Loss application. The world is always true; every degradation happens here.

A lens can only return entities present in lens_visibility, must call them by the
identifier IT uses, cannot see past its retention window, and cannot see anything
newer than its sync latency.
"""
import datetime as dt
from . import db

# Deliberately not cached across requests. `scripts/reset` and `scripts/seed` swap
# the world underneath a running gateway, which is the documented golden-file loop, so
# a process-lifetime cache here would keep serving the previous world's retention
# window and coverage. Ground-truth reachability is computed against these values, so
# stale ones would silently mis-score every kit. Two trivial indexed reads per request
# is the right trade for a local twin.
def lens(lens_id):
    row = db.one("SELECT * FROM lens WHERE id = %s", (lens_id,))
    if not row:
        raise KeyError(f"unknown lens: {lens_id}")
    return dict(row)


def world_now():
    row = db.one("SELECT value FROM world_meta WHERE key = 'as_of'")
    d = dt.date.fromisoformat(row["value"])
    return dt.datetime.combine(d, dt.time(9, 0), tzinfo=dt.timezone.utc)

def horizon(lens_id):
    """Newest data this lens can have seen, given its sync latency."""
    return world_now() - dt.timedelta(minutes=lens(lens_id)["latency_minutes"])

def floor(lens_id):
    """Oldest data this lens still retains."""
    return world_now() - dt.timedelta(days=lens(lens_id)["retention_days"])

def visible_ids(lens_id, kind):
    rows = db.q("""SELECT entity_id, external_id, last_seen
                     FROM lens_visibility
                    WHERE lens_id = %s AND entity_kind = %s""", (lens_id, kind))
    return {r["entity_id"]: r for r in rows}

def coverage_note(lens_id):
    l = lens(lens_id)
    return {"coverage": float(l["coverage"]), "identifier_style": l["identifier_style"],
            "latency_minutes": l["latency_minutes"], "retention_days": l["retention_days"],
            "blind_spot": l["blind_spot"]}
