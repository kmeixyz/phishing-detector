"""Fetch the page's favicon and hash it.

One extra request, to the icon the page itself declares (falling back to the
conventional /favicon.ico that browsers request unprompted on every visit).
That keeps it inside the same rule as everything else here: fetch what the
submitted page points at, never a path we invented.

The payoff is a precision signal. A page serving PayPal's byte-identical
favicon from an unrelated domain has been copied from PayPal, and that is a
much harder fact to argue with than any statistical feature.
"""

from __future__ import annotations

import hashlib

import httpx

from ..config import ENVELOPE
from ..data.favicons import MAX_ICON_BYTES, declared_icon
from ..data.favicons import load as load_hashes
from ..netguard import BlockedAddress, guarded_client, guarded_stream
from ..urls import parse
from .base import FAILED, SKIPPED, CollectorResult, read_capped, timed


def _icon_url(html: str, page_url: str) -> str:
    """The icon the page declares, or the /favicon.ico browsers ask for anyway."""
    declared = declared_icon(html, page_url)
    if declared:
        return declared
    p = parse(page_url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}/favicon.ico"


def collect(page_url: str, html: str = "", deadline_s: float | None = None) -> CollectorResult:
    """`deadline_s`, when given, shortens the icon's own deadline to what is left of the scan."""
    res = CollectorResult(name="Favicon")
    with timed(res):
        target = _icon_url(html, page_url)
        if httpx.URL(target).scheme not in ("http", "https"):
            res.status = SKIPPED
            res.detail = ("the page uses an inline icon; no separate image was requested"
                          if target.lower().startswith("data:")
                          else "the icon address does not use HTTP or HTTPS")
            return res
        content, oversize, status_code = b"", False, 0
        try:
            # The scanned page names this address in its own <link rel=icon>,
            # so it is attacker-chosen: unguarded it reaches loopback and
            # private hosts, and the recorded size and hash answer whether they
            # exist. `guarded_stream` checks every hop, because checking only
            # the first one and then following redirects re-opens the same hole
            # from the second request onward.
            limit = ENVELOPE.icon_deadline_s if deadline_s is None else min(ENVELOPE.icon_deadline_s, deadline_s)
            with guarded_client(deadline_s=limit,
                                timeout=httpx.Timeout(10.0, connect=6.0),
                                follow_redirects=False, verify=False,
                                headers={"User-Agent": ENVELOPE.user_agent}) as client:
                # Streamed and capped while reading, on the decoded size.
                # `client.get` would buffer the whole body first, and httpx's
                # own decoding inflates a compressed body in one step before
                # any size check can run.
                with guarded_stream(client, target) as r:
                    status_code = r.status_code
                    content, _, oversize = read_capped(r, MAX_ICON_BYTES + 1)
        except BlockedAddress as exc:
            res.status = SKIPPED
            res.detail = f"icon address not fetched: {exc}"
            return res
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            res.status = FAILED
            res.detail = type(exc).__name__
            return res

        if status_code != 200 or not content:
            res.status = FAILED
            res.detail = f"no icon (HTTP {status_code})"
            # A 4xx, or an empty 200, is the site saying it has no icon. A
            # 5xx is the site failing to say anything.
            res.conclusive = status_code < 500
            return res
        if oversize:
            res.status = FAILED
            res.detail = "icon exceeds size cap"
            return res

        digest = hashlib.sha256(content).hexdigest()
        brand = load_hashes().get(digest, "")
        # The page's name, as the model was fitted with. The rules also ask
        # whether a matching name is one the brand really owns
        # (`favicon_on_brand_named_domain`), which this cannot.
        own = parse(page_url).domain

        res.data = {
            "icon_url": target,
            "sha256": digest,
            "bytes": len(content),
            "brand_match": brand,
            # The whole point: it is the brand's icon, on a domain that is not
            # the brand's.
            "impersonates": bool(brand) and brand != own,
            "icon_origin": parse(target).registrable,
        }
        res.detail = (f"matches {brand}'s favicon" if brand
                      else f"{len(content)} bytes, no brand match")
    return res
