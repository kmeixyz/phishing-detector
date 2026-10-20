"""DNS evidence.

MX presence is the quiet star here. Real organisations receive mail; a domain
registered on Tuesday to host one login page usually has no mail records at
all. Very low TTLs point at fast-flux hosting.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..config import ENVELOPE
from ..netguard import BlockedAddress, check_url
from ..urls import idna_ascii, parse
from .base import FAILED, CollectorResult, timed

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 5.0
_RESOLVER.lifetime = ENVELOPE.per_collector_timeout_s


def _ascii(name: str) -> str:
    """Encode a hostname the way the HTTP client does, so both describe one domain.

    dnspython's default codec is IDNA2003, where `faß.example` maps to
    `fass.example`; httpx uses IDNA2008, where it maps to `xn--fa-hia.example`.
    Those are two different registered domains, so a unicode hostname would
    otherwise have its registration evidence -- DNS, and everything derived
    from these addresses -- describe a domain nobody fetched, and one an
    attacker can register separately.

    This was the first place the divergence was found and fixed. It now shares
    `urls.idna_ascii` with the address guard and the TLS collector, because
    leaving each caller its own copy is how the guard ended up checking a
    different name than the client connected to.
    """
    return idna_ascii(name)


def _query(name: str, rtype: str):
    try:
        return _RESOLVER.resolve(_ascii(name), rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.name.LabelTooLong, ValueError):
        return None


def collect_addresses(url: str) -> CollectorResult:
    res = CollectorResult(name="DNS A / AAAA")
    with timed(res):
        p = parse(url)
        if p.is_ip_host:
            res.data = {"a_records": [p.hostname], "aaaa_records": [], "min_ttl": None,
                        "is_literal_ip": True}
            res.detail = "hostname is an IP literal"
            return res

        # Refuse to report the answer for a name that points inside the
        # network. Nothing here fetches, so this is not an SSRF guard -- it is
        # a disclosure one. The fetch collector already refuses these, and
        # printing the A/AAAA records beside the refusal handed back exactly
        # what the refusal withheld: a resolver oracle for internal names,
        # answerable by anyone who can reach the scanner.
        #
        # Which refusal it was is still said: "does not resolve to a public
        # host" for a name that does not exist at all told the result page it
        # pointed somewhere private. No address is named either way.
        try:
            check_url(f"http://{p.hostname}/")
        except BlockedAddress as exc:
            reason = str(exc)
            res.status = FAILED
            if "within" in reason or "stalled" in reason:
                res.detail = "the name did not resolve in time"
            elif "public address" in reason:
                res.detail = "the address does not resolve to a public host"
            else:
                res.detail = "the name does not resolve"
            return res

        a = _query(p.hostname, "A")
        aaaa = _query(p.hostname, "AAAA")
        if a is None and aaaa is None:
            res.status = FAILED
            res.detail = "no A or AAAA record"
            return res

        ttls = [r.rrset.ttl for r in (a, aaaa) if r is not None and r.rrset is not None]
        addrs = [str(x) for x in (a or [])]
        v6 = [str(x) for x in (aaaa or [])]
        res.data = {
            "a_records": addrs,
            "aaaa_records": v6,
            "min_ttl": min(ttls) if ttls else None,
            "is_literal_ip": False,
        }
        res.detail = f"{len(addrs) + len(v6)} record(s), TTL {min(ttls) if ttls else '?'}s"
    return res


def collect_mail_and_ns(url: str) -> CollectorResult:
    res = CollectorResult(name="DNS MX / NS")
    with timed(res):
        p = parse(url)
        if p.is_ip_host:
            res.status = FAILED
            res.detail = "no domain to query"
            res.conclusive = True
            return res

        mx = _query(p.registrable, "MX")
        ns = _query(p.registrable, "NS")
        # A root exchange (null MX) says the domain does not accept email.
        mx_hosts = [str(r.exchange).rstrip(".") for r in (mx or [])
                    if str(r.exchange).rstrip(".")]
        null_mx = any(str(r.exchange) == "." and r.preference == 0 for r in (mx or []))
        ns_hosts = [str(r.target).rstrip(".") for r in (ns or [])]

        res.data = {
            "mx_records": mx_hosts,
            "ns_records": ns_hosts,
            "has_mx": bool(mx_hosts),
            "null_mx": null_mx,
            "ns_provider": ns_hosts[0].split(".", 1)[-1] if ns_hosts else "",
        }
        res.detail = (
            f"{len(mx_hosts)} MX, {len(ns_hosts)} NS"
            if mx_hosts else f"no MX, {len(ns_hosts)} NS"
        )
        if not mx_hosts and not ns_hosts:
            res.status = FAILED
            res.detail = "no MX or NS records"
            res.conclusive = True
    return res
