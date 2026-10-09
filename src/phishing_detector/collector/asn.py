"""Hosting ASN and country via Team Cymru's IP-to-ASN service.

Chosen over MaxMind GeoLite2 deliberately: GeoLite2 is free but requires an
account, a license key and EULA acceptance, whereas Cymru answers plain DNS
TXT queries with no credential at all. One less thing standing between a fresh
clone and a working scan.
"""

from __future__ import annotations

import ipaddress
import time

import dns.exception
import dns.resolver

from .base import FAILED, CollectorResult, timed

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 5.0
_RESOLVER.lifetime = 10.0


def _txt(name: str, lifetime: float | None = None) -> str | None:
    try:
        answer = _RESOLVER.resolve(name, "TXT", lifetime=lifetime)
        return b"".join(answer[0].strings).decode("utf-8", "replace")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, IndexError, ValueError):
        return None


def collect(ip: str | None, lifetime: float | None = None) -> CollectorResult:
    """`lifetime` caps both lookups together, in seconds: what is left of the scan."""
    res = CollectorResult(name="ASN / geo")
    ends = None if lifetime is None else time.monotonic() + min(lifetime, _RESOLVER.lifetime)

    def left() -> float | None:
        return None if ends is None else max(0.1, ends - time.monotonic())

    with timed(res):
        if not ip:
            res.status = FAILED
            res.detail = "no address resolved"
            return res

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            res.status = FAILED
            res.detail = f"not an address: {ip}"
            return res

        if addr.version == 4:
            query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            nibbles = ".".join(reversed(addr.exploded.replace(":", "")))
            query = nibbles + ".origin6.asn.cymru.com"

        raw = _txt(query, left())
        if not raw:
            res.status = FAILED
            res.detail = "Cymru lookup returned nothing"
            return res

        # "13335 | 104.16.0.0/12 | US | arin | 2010-07-09" — short answers are
        # normal, so every field past the ASN is read defensively.
        parts = [x.strip() for x in raw.split("|")]

        def part(i: int) -> str:
            return parts[i] if len(parts) > i else ""

        asn = part(0).split()[0] if part(0) else ""
        name = ""
        if asn:
            as_raw = _txt(f"AS{asn}.asn.cymru.com", left())
            if as_raw:
                name = as_raw.split("|")[-1].strip()

        country = part(2)
        res.data = {
            "asn": f"AS{asn}" if asn else "",
            "prefix": part(1),
            "country": country,
            "registry": part(3),
            "as_name": name,
        }
        res.detail = f"AS{asn} {country} {name}".strip()
    return res
