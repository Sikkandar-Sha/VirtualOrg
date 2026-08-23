#!/usr/bin/env python3
"""
A deliberately small consumer of VirtualOrg, so the environment has something to
demonstrate against and the scoring contract has a worked example.

It is not a good risk-posture product, and it is not trying to be. It does the
obvious thing at each step so that where it fails, it fails for reasons the
environment was built to expose:

  * it finds the conflicts that a single source contradicts itself about, which is
    the easy half
  * it finds orphaned access only because it joins HR to the IdP on email, which is
    the correlation the environment forces
  * it attributes alerts to controls by matching words, which is exactly the naive
    inference the planted traps are there to punish

Run it against a live VirtualOrg, then score the result:

    python3 examples/reference-kit/kit.py > posture.json
    ./scripts/score posture.json
"""
import datetime as dt
import json
import os
import re
import sys

import httpx
from urllib.parse import urlparse

BASE = os.environ.get("VO_BASE", "http://127.0.0.1:8080")
TOKEN = os.environ.get("VO_TOKEN", "vo-dev-token")
c = httpx.Client(base_url=BASE, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60)


def cursor_pages(path, **params):
    """GRC hands back an opaque cursor. Echo it; never build one."""
    out, cur = [], None
    while True:
        p = dict(params)
        if cur:
            p["cursor"] = cur
        r = c.get(path, params=p)
        r.raise_for_status()
        body = r.json()
        out += body["items"]
        cur = body.get("next_cursor")
        if not cur:
            return out


def page_number(path, **params):
    """Workday counts pages and tells you how many there are."""
    out, page = [], 1
    while True:
        r = c.get(path, params={"per_page": 500, "page": page, **params})
        r.raise_for_status()
        body = r.json()
        out += body["workers"]
        if page >= body["total_pages"]:
            return out
        page += 1


def same_origin(url):
    """The next URL comes from the server, and this client carries a bearer token. An
    upstream that pointed rel="next" at another host would be handed the credential.
    A harness is not where that matters, but this file is meant to be copied, and the
    check costs one line."""
    if url.startswith("/"):
        return True
    u, b = urlparse(url), urlparse(BASE)
    return (u.scheme, u.netloc) == (b.scheme, b.netloc)


def link_header(path, **params):
    """Okta gives you the next URL. Following it is the whole contract."""
    out = []
    r = c.get(path, params={"limit": 200, **params})
    r.raise_for_status()
    out += r.json()
    link = r.headers.get("link", "")
    seen = 0
    while 'rel="next"' in link and seen < 10_000:
        seen += 1
        url = [x.split(">")[0].strip().lstrip("<") for x in link.split(",") if 'rel="next"' in x][0]
        if not same_origin(url):
            raise RuntimeError(f"rel=next pointed off-origin, refusing to send the token: {url}")
        r = c.get(url)
        r.raise_for_status()
        out += r.json()
        link = r.headers.get("link", "")
    return out


def async_job(search):
    """Splunk: submit, poll until it admits it is done, then fetch."""
    sid = c.post("/splunk/services/search/jobs", data={"search": search}).json()["sid"]
    for _ in range(30):
        st = c.get(f"/splunk/services/search/jobs/{sid}").json()["entry"][0]["content"]
        if st["isDone"]:
            break
    else:
        raise RuntimeError("search job never completed")
    out, off = [], 0
    while True:
        rows = c.get(f"/splunk/services/search/jobs/{sid}/results",
                     params={"offset": off, "count": 5000}).json()["results"]
        out += rows
        if len(rows) < 5000:
            return out
        off += 5000


def main():
    meta = c.get("/healthz").json()["world"]
    as_of = dt.date.fromisoformat(meta["as_of"])
    findings, attributions = [], []

    def finding(family, kind, subject):
        findings.append({"family": family, "subject_kind": kind, "subject_id": subject})

    # --- conflicts a single source contradicts itself about -------------------
    # An exception the platform still calls active, with an expiry date in the past.
    for e in cursor_pages("/grc/api/v1/exceptions", status="active"):
        if dt.date.fromisoformat(e["expires_on"]) < as_of:
            finding("conflict", "control", e["control_reference"])

    # A control rated effective while an overdue finding stands against it.
    overdue = {f["control_reference"] for f in cursor_pages("/grc/api/v1/findings", status="overdue")}
    for ctl in cursor_pages("/grc/api/v1/controls"):
        if ctl["effectiveness"] == "effective" and ctl["reference"] in overdue:
            finding("conflict", "control", ctl["reference"])

    # A risk the register calls current whose review period has lapsed.
    for r in cursor_pages("/grc/api/v1/risks"):
        age = (as_of - dt.date.fromisoformat(r["last_reviewed_on"])).days
        if age > r["review_period_days"]:
            finding("conflict", "risk", r["reference"])

    # A treatment past its target date while the risk is still above appetite.
    appetite = {r["reference"]: (r["inherent_score"], r["appetite"]) for r in cursor_pages("/grc/api/v1/risks")}
    for t in cursor_pages("/grc/api/v1/treatments", status="overdue"):
        inh, app = appetite.get(t["risk_reference"], (0, 0))
        if inh > app:
            finding("conflict", "risk", t["risk_reference"])

    # A policy nothing implements.
    for p in cursor_pages("/grc/api/v1/policies"):
        if p["implementing_controls"] == 0:
            finding("absence", "policy", p["reference"])

    # --- the conflict that needs two sources ---------------------------------
    # The IdP will not tell you who left: terminationDate is written by the
    # deprovisioning workflow, so when that workflow failed the field is empty.
    # HR is the system of record, and it cannot see contractors at all.
    hr_terminated = {w["primary_work_email"] for w in page_number("/hr/api/v1/workers")
                     if w["termination_date"]}
    for u in link_header("/iam/api/v1/users"):
        if u["status"] == "ACTIVE" and u["profile"]["email"] in hr_terminated:
            finding("conflict", "person", u["profile"]["login"])

    # --- attribution, done naively on purpose --------------------------------
    # Match the words in a detection rule name against the words in a control title.
    # This is the obvious approach, it is wrong often enough to be interesting, and
    # the traps in the world exist to measure exactly how wrong.
    STOP = {"and", "of", "the", "to", "a", "in", "on", "for", "control"}

    def words(s):
        # split on anything that is not a word character, so punctuation in a title
        # never becomes part of a token
        return {w.lower() for w in re.split(r"\W+", s) if w} - STOP

    controls = cursor_pages("/grc/api/v1/controls")
    ctl_words = [(x["reference"], words(x["title"])) for x in controls]
    for alert in async_job("search index=main"):
        aw = words(alert.get("signature", ""))
        best, score = None, 0
        for ref, cw in ctl_words:
            overlap = len(aw & cw)
            if overlap > score:
                best, score = ref, overlap
        if best and score >= 1:
            attributions.append({"evidence_id": alert["event_id"], "control_id": best})

    json.dump({
        # All five values that identify a world. The scorer refuses anything less,
        # because scale and chaos change the answer key as surely as the seed does.
        "meta": {"world_seed": int(meta["seed"]), "as_of": meta["as_of"],
                 "scale": meta["scale"], "chaos": meta["chaos"],
                 "generator_version": meta["generator_version"], "mode": "simulated"},
        "findings": findings,
        "attributions": attributions,
    }, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
