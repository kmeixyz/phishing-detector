"""Certificate Transparency history via crt.sh.

Worth its own collector for one reason: it gives an age signal where domain
age does not exist. Half the phishing corpus lives on free subdomains, where
`domain_age_days` is unavailable by definition — nobody registered
`kit-abc.vercel.app`. But a certificate was issued for that exact hostname,
and CT logs record when. "First certificate seen three days ago" is the age
of the site, not of the hosting provider.

crt.sh is free and needs no key. It is also slow and frequently overloaded, so
this is treated as best-effort: a failure narrows the evidence and is recorded.
Wildcard queries over a whole provider will time out; only exact hostnames are
requested here.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx

from ..config import ENVELOPE
from ..data import store
from ..features.lexical import CLOUD_HOSTS
from ..features.user_content import tenant_platform
from ..urls import is_dns_name, parse
from .base import FAILED, OK, CollectorResult, RateLimiter, read_capped, timed

CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
_limit = RateLimiter(0.5)  # both services are free; do not hammer them

# A successful answer is a fact about the domain and keeps for a fortnight. A
# failure usually means Certspotter's per-IP quota or a crt.sh 502, so it is
# retried within the hour rather than being trusted for two weeks.
ANSWER_TTL_DAYS = 14
FAILURE_TTL_DAYS = 1 / 24


# Popular names have long histories; 16 MB holds crt.sh's answer for a large
# brand's regional site with room to spare.
MAX_ANSWER_BYTES = 16 * 1024 * 1024
# Wall clock for one CT lookup, every request included.
CT_DEADLINE_S = 20.0


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _summarise(stamps: list[datetime], count: int, issuers: int, source: str,
               complete: bool) -> dict:
    """`complete` says whether expired certificates were included.

    Certspotter's issuances endpoint lists only *unexpired* certificates, so
    its oldest is the oldest one still valid -- about thirteen months at most,
    on a name decades old. That is a lower bound on the site's age, never
    evidence that it is young. crt.sh keeps the full history.
    """
    first = min(stamps) if stamps else None
    now = datetime.now(timezone.utc)
    return {
        "source": source,
        "complete_history": complete,
        "cert_count": count,
        "first_seen": first.isoformat() if first else "",
        "ct_age_days": (now - first).days if first else None,
        "distinct_issuers": issuers,
    }


def _json_rows(client: httpx.Client, endpoint: str, params: dict,
               deadline: float) -> list | None:
    """GET a JSON array, or None if the service did not usefully answer.

    Neither service is reliable enough to distinguish failure modes on: a
    connection error, a 502, a truncated body and an HTML error page are all
    just "ask the other one".
    """
    left = deadline - time.monotonic()
    if left < 1:
        return None
    try:
        with client.stream("GET", endpoint, params=params,
                           timeout=min(ENVELOPE.per_collector_timeout_s, left)) as r:
            if r.status_code != 200:
                return None
            # Bounded like every other body this service reads. A cut-off
            # answer does not parse, and is treated as no answer.
            body, _, truncated = read_capped(r, MAX_ANSWER_BYTES)
    except httpx.HTTPError:
        return None
    if truncated:
        return None
    try:
        rows = json.loads(body)
    except ValueError:
        return None
    return rows if isinstance(rows, list) else None


def _try_certspotter(hostname: str, client: httpx.Client, deadline: float) -> dict | None:
    """Primary. Free without a key, though rate-limited per IP."""
    rows = _json_rows(client, CERTSPOTTER, {
        "domain": hostname, "include_subdomains": "false", "expand": "issuer",
    }, deadline)
    if rows is None:
        return None
    stamps = [t for t in (_parse_ts(str(row.get("not_before") or "")) for row in rows) if t]
    issuers = {str(row.get("issuer", {}).get("name", "")) for row in rows}
    return _summarise(stamps, len(rows), len(issuers), "Certspotter", complete=False)


def _try_crtsh(hostname: str, client: httpx.Client, deadline: float) -> dict | None:
    """Fallback. Richer history, but frequently returns 502 under load.

    Asked twice, because its failures are transient more often than not: the
    same query answered 404 and then 200 with 1,410 rows a few seconds apart.
    With Certspotter rate-limited per address, this is the only source left,
    and the wrong-suffix exemption for a regional brand site rests on it.
    """
    rows = _json_rows(client, CRTSH, {"q": hostname, "output": "json"}, deadline)
    if rows is None:
        rows = _json_rows(client, CRTSH, {"q": hostname, "output": "json"}, deadline)
    if rows is None:
        return None
    stamps = [t for t in (_parse_ts(str(row.get("entry_timestamp") or
                                        row.get("not_before") or "")) for row in rows) if t]
    issuers = {str(row.get("issuer_name", "")) for row in rows}
    return _summarise(stamps, len(rows), len(issuers), "crt.sh", complete=True)


def _history(hostname: str, client: httpx.Client, deadline: float) -> dict | None:
    """Certspotter, falling back to crt.sh when it does not answer."""
    return (_try_certspotter(hostname, client, deadline)
            or _try_crtsh(hostname, client, deadline))


def collect(url: str) -> CollectorResult:
    res = CollectorResult(name="CT log history")
    with timed(res):
        p = parse(url)
        # Only a real DNS name is sent. crt.sh reads `%` as a wildcard, so a
        # host that was anything else could ask it for every name under a TLD.
        if p.is_ip_host or not is_dns_name(p.ascii_hostname or p.hostname):
            res.status = FAILED
            res.detail = "no hostname to query"
            res.conclusive = True
            return res

        cached = store.lookup_get("ct", p.hostname, max_age_days=ANSWER_TTL_DAYS)
        if cached is not None and cached["status"] != OK:
            cached = store.lookup_get("ct", p.hostname, max_age_days=FAILURE_TTL_DAYS)
        if cached is not None:
            res.status, res.detail, res.data = cached["status"], cached["detail"], cached["data"]
            return res

        if not _limit.wait(max_wait=ENVELOPE.per_collector_timeout_s):
            res.status = FAILED
            res.detail = "certificate log lookups are queued too deep on this instance"
            return res
        with httpx.Client(
            timeout=ENVELOPE.per_collector_timeout_s,
            headers={"User-Agent": ENVELOPE.user_agent},
            follow_redirects=True,
        ) as client:
            # One deadline for every request below. Each was allowed the full
            # per-collector timeout, and with two services, a retry and a
            # fallback that was a minute -- past the whole scan's budget.
            deadline = time.monotonic() + CT_DEADLINE_S
            data = _history(p.hostname, client, deadline)
            # `www.wikipedia.org` has no certificate of its own; the cert is on
            # `wikipedia.org` with www in its SAN list. Fall back to the
            # registrable domain so a real site is not reported as having no
            # certificate history at all.
            # Never for a platform customer, though: `kit-x.sourceforge.io`
            # has no certificate history of its own to fall back from, and
            # sourceforge.io's decade of it would have made the kit look
            # long-lived -- the same borrowed age the registration rules refuse.
            if (data is None or data.get("cert_count", 0) == 0) and \
                    p.registrable and p.registrable != p.hostname and \
                    not tenant_platform(p.hostname, CLOUD_HOSTS):
                wider = _history(p.registrable, client, deadline)
                if wider and wider.get("cert_count", 0) > 0:
                    wider["source"] += f" ({p.registrable})"
                    data = wider

        if data is None:
            res.status = FAILED
            res.detail = "no CT source answered (Certspotter and crt.sh both unavailable)"
            # The failure is cached too, briefly: during a bulk run every scan
            # would otherwise re-attempt both services and pay the full timeout
            # for a result already known to be unavailable.
            store.lookup_put("ct", p.hostname, res.status, res.detail, {})
            return res

        res.data = data
        age = data.get("ct_age_days")
        if data["cert_count"] == 0:
            res.detail = f"no certificates logged for this hostname ({data['source']})"
        elif age is None:
            res.detail = f"{data['cert_count']} cert(s) via {data['source']}, no timestamps"
        else:
            res.detail = (f"{data['cert_count']} cert(s) via {data['source']}, first seen {age}d ago"
                          if data.get("complete_history") else
                          f"{data['cert_count']} current cert(s) via {data['source']}, "
                          f"oldest {age}d old (expired ones not listed)")
        store.lookup_put("ct", p.hostname, res.status, res.detail, res.data)
    return res
