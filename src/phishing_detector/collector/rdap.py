"""Registration evidence via RDAP, with WHOIS as the fallback.

Domain age is the single strongest feature in this whole project — phishing
domains are typically days old — so it is worth two independent paths to it.

RDAP first: it is the IETF replacement for WHOIS, returns structured JSON, and
spares you writing a text parser per registrar. `python-whois` breaks
constantly on unusual TLDs, which is exactly where phishing lives, so WHOIS is
kept only for suffixes with no RDAP coverage and is parsed defensively.

Both are aggressively rate-limited. These are volunteer-operated services and
they will ban you.
"""

from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone

import httpx

from ..config import ENVELOPE
from ..data import store
from ..features.lexical import CLOUD_HOSTS
from ..features.user_content import tenant_platform
from ..urls import idna_ascii, is_dns_name, parse
from .base import FAILED, TIMEOUT, CollectorResult, RateLimiter, read_capped, timed

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
IANA_WHOIS = "whois.iana.org"

_rdap_limit = RateLimiter(ENVELOPE.rdap_requests_per_second)
_whois_limit = RateLimiter(ENVELOPE.whois_requests_per_second)
# WHOIS runs after the parallel collectors, so its queue wait comes straight
# out of the visitor's time.
WHOIS_MAX_WAIT_S = 8.0

_PRIVACY_HINTS = ("privacy", "redacted", "whoisguard", "withheld", "protected",
                  "data protected", "not disclosed", "gdpr")


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    for candidate in (text, text.split("T")[0]):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _summarise(created: datetime | None, expires: datetime | None,
               registrar: str, privacy: bool, source: str,
               lookup_domain: str = "", describes_site: bool = True) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "source": source,
        "lookup_domain": lookup_domain,
        # False when the record belongs to a hosting provider rather than to
        # the site being scanned.
        "describes_site": describes_site,
        "created": created.isoformat() if created else "",
        "expires": expires.isoformat() if expires else "",
        "domain_age_days": (now - created).days if created else None,
        "days_to_expiry": (expires - now).days if expires else None,
        "registration_period_days": (expires - created).days if created and expires else None,
        "registrar": registrar,
        "privacy_enabled": privacy,
    }


def _vcard_name(entity: dict) -> str:
    """The `fn` (formatted name) entry of an RDAP entity's vCard, if it has one.

    The vCard is a jCard array: ["vcard", [[field, params, type, value], ...]].
    Registrars populate it inconsistently, so every level is checked.
    """
    vcard = entity.get("vcardArray") or []
    if len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
            return str(item[3])
    return ""


def collect_rdap(url: str) -> CollectorResult:
    res = CollectorResult(name="RDAP")
    with timed(res):
        p = parse(url)
        # Query the billable domain: there is an RDAP record for vercel.app and
        # none for kit-abc.vercel.app. Whether that record describes *this site*
        # is decided downstream, where the shared-hosting case is handled.
        lookup = p.icann_registrable or p.registrable
        # Formatted into a registry URL and a WHOIS query line, so only a real
        # name goes out.
        if p.is_ip_host or not p.registrable or not is_dns_name(idna_ascii(lookup)):
            res.status = FAILED
            res.detail = "no registrable domain"
            res.conclusive = True
            return res

        cached = store.lookup_get("rdap", lookup)
        if cached is not None:
            res.status, res.detail, res.data = cached["status"], cached["detail"], cached["data"]
            # Everything cached here is a property of the *domain*, but
            # `describes_site` is a property of the URL: one cached record for
            # `vercel.app` is shared by every customer subdomain under it. The
            # comment below the write said this was recomputed on read, and it
            # was not -- so a kit on a provider subdomain inherited the
            # provider's registration age and the "new domain with a login
            # form" rule stopped firing.
            res.data = dict(res.data, describes_site=_describes_site(p))
            return res

        if not _rdap_limit.wait(max_wait=ENVELOPE.per_collector_timeout_s):
            res.status = TIMEOUT
            res.detail = "registry lookups are queued too deep on this instance"
            return res
        try:
            with httpx.stream(
                "GET", RDAP_BOOTSTRAP.format(domain=lookup),
                timeout=ENVELOPE.per_collector_timeout_s,
                follow_redirects=True,
                headers={"User-Agent": ENVELOPE.user_agent, "Accept": "application/rdap+json"},
            ) as r:
                # One domain's record is a few KB; a megabyte is generous.
                body, _, truncated = read_capped(r, 1024 * 1024)
        except httpx.TimeoutException:
            res.status = TIMEOUT
            res.detail = f"timeout after {ENVELOPE.per_collector_timeout_s:.0f}s"
            return res
        except httpx.HTTPError as exc:
            res.status = FAILED
            res.detail = type(exc).__name__
            return res

        if r.status_code == 404:
            res.status = FAILED
            res.detail = "no RDAP record for this domain"
            res.conclusive = True
            return res
        if r.status_code != 200:
            res.status = FAILED
            res.detail = f"RDAP HTTP {r.status_code}"
            return res

        try:
            if truncated:
                raise ValueError("RDAP answer over 1 MB")
            doc = json.loads(body)
        except ValueError:
            res.status = FAILED
            res.detail = "RDAP returned non-JSON"
            return res

        created = expires = None
        for event in doc.get("events", []) or []:
            action = str(event.get("eventAction", "")).lower()
            when = _parse_iso(str(event.get("eventDate", "")))
            if action == "registration":
                created = when
            elif action == "expiration":
                expires = when

        registrar = ""
        privacy = False
        for entity in doc.get("entities", []) or []:
            roles = [str(x).lower() for x in entity.get("roles", []) or []]
            name = _vcard_name(entity)
            if "registrar" in roles and name:
                registrar = name
            if any(h in str(entity).lower() for h in _PRIVACY_HINTS):
                privacy = True

        if any(h in str(doc.get("remarks", "")).lower() for h in _PRIVACY_HINTS):
            privacy = True

        res.data = _summarise(created, expires, registrar, privacy, "RDAP",
                              lookup_domain=lookup, describes_site=_describes_site(p))
        if created is None:
            res.status = FAILED
            res.detail = "RDAP record carried no registration date"
        else:
            res.detail = f"created {created.date()}, {res.data['domain_age_days']}d old"
        # `describes_site` is per-URL, so the cache-hit path above recomputes
        # it; everything else stored here is a domain property.
        store.lookup_put("rdap", lookup, res.status, res.detail, res.data)
    return res


def _ask_whois(server: str, query: str, timeout: float, cap: int) -> bytes:
    """One WHOIS exchange: connect, send the query, read the reply up to `cap`.

    Raises OSError (of which socket.timeout is a subclass) — the two callers
    report a timeout differently, so the distinction is left to them.
    """
    deadline = time.monotonic() + timeout
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall(f"{query}\r\n".encode())
        data = b""
        # `timeout` is per recv, so a server answering a byte at a time would
        # never trip it. The whole answer shares one deadline instead.
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > cap:
                break
        else:
            raise socket.timeout("WHOIS answer did not finish in time")
    return data


def _describes_site(p) -> bool:
    """Whether the registration record is this site's rather than its host's.

    The public suffix list marks `kit.vercel.app` as a site of its own; it
    does not know that `kit-x.sourceforge.io` or a bucket on
    `s3.amazonaws.com` is a customer's too, and those were given the
    platform's registration age as their own.
    """
    return not (p.on_shared_hosting or tenant_platform(p.hostname, CLOUD_HOSTS))


def _whois_server(suffix: str) -> str | None:
    """The WHOIS server IANA publishes for a TLD, or None."""
    if not _whois_limit.wait(max_wait=WHOIS_MAX_WAIT_S):
        return None
    try:
        data = _ask_whois(IANA_WHOIS, suffix, timeout=10, cap=64_000)
    except OSError:
        return None
    m = re.search(r"^whois:\s*(\S+)", data.decode("utf-8", "replace"), re.MULTILINE)
    return m.group(1) if m else None


def collect_whois(url: str) -> CollectorResult:
    """Text WHOIS, parsed defensively. Only worth running when RDAP has failed."""
    res = CollectorResult(name="WHOIS fallback")
    with timed(res):
        p = parse(url)
        lookup = p.icann_registrable or p.registrable
        # Formatted into a WHOIS query line, so only a real name goes out.
        if p.is_ip_host or not p.suffix or not is_dns_name(idna_ascii(lookup)):
            res.status = FAILED
            res.detail = "no registrable domain"
            res.conclusive = True
            return res
        icann_suffix = lookup.split(".", 1)[-1]
        server = _whois_server(icann_suffix)
        if not server:
            res.status = FAILED
            res.detail = f"no WHOIS server published for .{icann_suffix}"
            return res

        if not _whois_limit.wait(max_wait=WHOIS_MAX_WAIT_S):
            res.status = TIMEOUT
            res.detail = "WHOIS lookups are queued too deep on this instance"
            return res
        try:
            data = _ask_whois(server, lookup,
                              timeout=ENVELOPE.per_collector_timeout_s, cap=128_000)
        except socket.timeout:
            res.status = TIMEOUT
            res.detail = f"timeout after {ENVELOPE.per_collector_timeout_s:.0f}s"
            return res
        except OSError as exc:
            res.status = FAILED
            res.detail = str(exc)
            return res

        text = data.decode("utf-8", "replace")
        low = text.lower()

        def field(*keys: str) -> str:
            for key in keys:
                m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return ""

        created = _parse_iso(field("creation date", "created", "registered on", "registration time"))
        expires = _parse_iso(field("registry expiry date", "expiry date", "expires on", "expiration date"))
        registrar = field("registrar", "sponsoring registrar")
        privacy = any(h in low for h in _PRIVACY_HINTS)

        res.data = _summarise(created, expires, registrar, privacy, f"WHOIS ({server})",
                              lookup_domain=lookup, describes_site=_describes_site(p))
        if created is None:
            res.status = FAILED
            res.detail = "WHOIS response carried no parseable creation date"
        else:
            res.detail = f"created {created.date()} via {server}"
    return res
