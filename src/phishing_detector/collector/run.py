"""Scan orchestration.

Sub-collectors run concurrently and are isolated from each other: each is
wrapped so that an exception, a hang or a hard timeout produces a failed
result rather than propagating. Half of these lookups time out on any given
run against real phishing infrastructure, and the scan still has to finish.

`scan_events` yields progress as each collector lands, which is what the
interface streams. `scan` is the blocking convenience wrapper.
"""

from __future__ import annotations

import logging
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from concurrent.futures import TimeoutError as FutureTimeout
from functools import partial
from time import monotonic
from typing import Callable, Iterator

from ..config import (ENVELOPE, HostScanRefused, containerised, host_scanning_allowed,
                      refuse_host_scan_message, shared_instance)
from ..urls import parse
from . import asn, ctlog, dns_records, favicon, http_chain, rdap, render, tls
from .base import (FAILED, SKIPPED, TIMEOUT, CollectorResult, EvidenceBundle,
                   load_cached, new_bundle)

# Display order, which is also the order the interface lists them in.
COLLECTOR_ORDER = (
    "HTTP chain", "TLS certificate", "DNS A / AAAA", "DNS MX / NS",
    "RDAP", "WHOIS fallback", "ASN / geo", "CT log history", "Favicon", "JS render",
)

_log = logging.getLogger("phishing_detector.collector")

# "auto" renders only when the plain fetch came back looking client-rendered,
# which is the only case where rendering buys anything. "off" never renders;
# "force" always does. All three are still subject to PHISHING_DETECTOR_ALLOW_JS.
RENDER_OFF, RENDER_AUTO, RENDER_FORCE = "off", "auto", "force"

# The collectors that need nothing but the URL, and so can all start at once.
# Everything else in COLLECTOR_ORDER depends on one of these having landed.
INDEPENDENT: tuple[tuple[str, Callable[[str], CollectorResult]], ...] = (
    ("HTTP chain", http_chain.collect),
    ("TLS certificate", tls.collect),
    ("DNS A / AAAA", dns_records.collect_addresses),
    ("DNS MX / NS", dns_records.collect_mail_and_ns),
    ("RDAP", rdap.collect_rdap),
    ("CT log history", ctlog.collect),
)


# The end of the scan budget kept for the steps that need the collectors'
# answers first: ASN needs an address, the icon needs the page, WHOIS needs
# RDAP to have failed. Capped at a quarter of the budget for short budgets.
DEPENDENT_RESERVE_S = 12.0
BUDGET_SPENT = "the scan budget was spent"


def _guard(name: str, fn: Callable[[], CollectorResult]) -> CollectorResult:
    """No sub-collector may take the run down with it.

    A collector's own failures (a timeout, a refused connection) are written
    as evidence and never get here. What does is a fault, and its message can
    carry paths and internal names, so a shared instance shows the visitor the
    exception's type only and keeps the rest for the log.
    """
    try:
        result = fn()
        if not isinstance(result, CollectorResult):
            raise TypeError(f"returned {type(result).__name__}, not a CollectorResult")
        return result
    except Exception as exc:  # noqa: BLE001 - deliberate: hostile input, unknown failure modes
        _log.warning("collector %s failed", name, exc_info=True)
        detail = type(exc).__name__ if shared_instance() else f"{type(exc).__name__}: {exc}"
        return CollectorResult(name=name, status=FAILED, detail=detail)


def _bounded(pool: ThreadPoolExecutor, name: str, fn: Callable[[], CollectorResult],
             seconds: float) -> CollectorResult:
    """`fn` on the pool, waited on for at most `seconds`.

    The dependent steps ran on the scan's own thread, so one that ignored its
    own deadline held the whole check past the budget for as long as it liked.
    """
    future = pool.submit(_guard, name, fn)
    try:
        return future.result(timeout=max(seconds, 0))
    except FutureTimeout:
        future.cancel()
        return CollectorResult(name=name, status=TIMEOUT, detail=BUDGET_SPENT)


def _should_render(bundle: EvidenceBundle, mode: str) -> bool:
    """Whether rendering is worth the risk for this particular page.

    RENDER_FORCE has been earned upstream: `web/app.py::_render_permitted` only
    grants it after a scan without JavaScript already came back inconclusive.

    RENDER_AUTO has not. It decides from the fetched HTML -- content the scanned
    page controls -- so a page shaped as a script-heavy empty shell authorises
    its own execution on the very first scan. That is the shape a client-side
    kit has, which is exactly why auto-render is useful and exactly why it
    cannot be trusted to the page. It is therefore allowed only where execution
    is contained: inside the container, where the evidence lives in a volume and
    nothing reaches the host. On the host, an unearned render is refused.
    """
    if mode == RENDER_OFF:
        return False
    if not render.available()[0]:
        return False
    if mode == RENDER_FORCE:
        return True
    if not containerised():
        return False

    http = bundle.data("HTTP chain")
    html = http.get("html", "")
    if not html:
        return False
    # Cheap proxy for "the body is a shell that JavaScript fills in": very
    # little text, but scripts present to produce it.
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    return len(soup.get_text(strip=True)) < 200 and len(soup.find_all("script")) > 0


def scan_events(url: str, use_cache: bool = True,
                render_mode: str = RENDER_AUTO) -> Iterator[tuple[str, object]]:
    """Yield ('collector', CollectorResult) then ('bundle', EvidenceBundle)."""
    if use_cache:
        cached = load_cached(url)
        # A bundle collected without rendering cannot answer a request that
        # wants it, so fall through to a fresh scan instead of serving one that
        # is missing the evidence being asked for.
        stale = (render_mode == RENDER_FORCE
                 and render.available()[0]
                 and cached is not None
                 and not cached.get("JS render").ok)
        if cached is not None and not stale:
            for name in COLLECTOR_ORDER:
                if name in cached.results:
                    yield "collector", cached.results[name]
            yield "bundle", cached
            return

    # Only a fresh fetch writes a live page to disk, so the containment guard
    # belongs here rather than above the cache check — otherwise a cache hit
    # for an already-scanned URL refuses too, even though it stores nothing.
    if not host_scanning_allowed():
        raise HostScanRefused(refuse_host_scan_message())

    bundle = new_bundle(url)
    p = parse(url)

    # Not a `with` block: leaving one waits for every worker, including the
    # ones the budget below has already given up on. A collector that is still
    # inside a socket call when the deadline passes is reported as timed out
    # and then left to finish on its own thread; the scan moves on without it.
    pool = ThreadPoolExecutor(max_workers=6)
    # The dependent steps get their own workers: collectors the budget gave
    # up on can still be holding every one of `pool`'s.
    tail = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {
            pool.submit(_guard, name, partial(fn, url)): name
            for name, fn in INDEPENDENT
        }

        pending = set(futures)
        budget = ENVELOPE.total_scan_timeout_s
        # The budget is the whole check's, and the scan page says so. ASN,
        # the icon and WHOIS run after the collectors and used to get their
        # own full timeouts past it -- a hung source made a "45 s" check take
        # 60 and more. They now share a reserve at the end, and each is given
        # only what is left of it.
        finish_by = monotonic() + budget
        deadline = finish_by - min(DEPENDENT_RESERVE_S, budget / 4)
        while pending:
            # The budget is for the whole scan, so each wait gets what is left
            # of it rather than the whole of it again. Handing every wait the
            # full budget let it restart on each completion, and "45s" meant
            # "45s after the last collector finished".
            remaining = deadline - monotonic()
            done, pending = (wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
                             if remaining > 0 else (set(), pending))
            if not done:
                for fut in pending:
                    name = futures[fut]
                    result = CollectorResult(name=name, status=TIMEOUT,
                                             detail=f"exceeded {budget:.0f}s scan budget")
                    bundle.results[name] = result
                    yield "collector", result
                    fut.cancel()
                break
            for fut in done:
                result = fut.result()
                bundle.results[result.name] = result
                yield "collector", result

        # --- the page is somewhere else --------------------------------
        # After a redirect to another domain the page belongs to the
        # destination, but registration, certificate, DNS and CT were all
        # looked up for the address submitted -- the shortener, the open
        # redirect, the aged domain someone bought to front a kit. So they are
        # looked up again for the destination, inside what is left of the
        # budget, and replace the first answers. `evidence_follows_final` on
        # the chain tells the rules that registration now describes the page.
        subject = url
        http_result = bundle.get("HTTP chain")
        final = http_result.data.get("final_url", "") if http_result.ok else ""
        final_reg = parse(final).registrable if final else ""
        if (final_reg and final_reg != p.registrable
                and not http_result.data.get("destination_unreached")
                and deadline - monotonic() > 2):
            followed = {pool.submit(_guard, name, partial(fn, final)): name
                        for name, fn in INDEPENDENT if name != "HTTP chain"}
            done, _ = wait(followed, timeout=deadline - monotonic())
            # All or nothing: a bundle holding the destination's DNS beside the
            # redirector's registration would describe neither site, and say so
            # nowhere. If the budget runs out first, the first answers stand.
            if len(done) == len(followed):
                for fut in done:
                    result = fut.result()
                    result.detail = (f"{result.detail} (for {parse(final).hostname}, "
                                     "where the address leads)")
                    bundle.results[result.name] = result
                    yield "collector", result
                http_result.data["evidence_follows_final"] = True
                subject = final

        # --- dependent steps ------------------------------------------
        # ASN needs an address; WHOIS is only worth the traffic once RDAP has
        # actually failed, which keeps load off the WHOIS operators.
        addresses = bundle.data("DNS A / AAAA").get("a_records") or []
        if not addresses:
            asn_result = CollectorResult(name="ASN / geo", status=FAILED,
                                         detail="no address resolved")
        elif finish_by - monotonic() < 0.25:
            asn_result = CollectorResult(name="ASN / geo", status=SKIPPED, detail=BUDGET_SPENT)
        else:
            asn_result = _bounded(tail, "ASN / geo", lambda: asn.collect(
                addresses[0], lifetime=finish_by - monotonic()), finish_by - monotonic())
        bundle.results["ASN / geo"] = asn_result
        yield "collector", asn_result

        # Needs the fetched HTML to find the declared icon, so it runs after
        # the HTTP chain rather than alongside it.
        http_data = bundle.data("HTTP chain")
        if http_data and finish_by - monotonic() < 0.25:
            fav = CollectorResult(name="Favicon", status=SKIPPED, detail=BUDGET_SPENT)
        elif http_data:
            fav = _bounded(tail, "Favicon", lambda: favicon.collect(
                http_data.get("final_url") or url, http_data.get("html", ""),
                deadline_s=finish_by - monotonic()), finish_by - monotonic())
        else:
            fav = CollectorResult(name="Favicon", status=SKIPPED,
                                  detail="page was not fetched")
        bundle.results["Favicon"] = fav
        yield "collector", fav

        if bundle.get("RDAP").ok:
            whois_result = CollectorResult(
                name="WHOIS fallback", status=SKIPPED, detail="not needed, RDAP answered"
            )
        elif parse(subject).is_ip_host:
            whois_result = CollectorResult(
                name="WHOIS fallback", status=SKIPPED, detail="hostname is an IP literal"
            )
        elif finish_by - monotonic() < 2:
            # Too little is left for a WHOIS exchange, and starting one would
            # only spend a worker on an answer the budget already gave up on.
            whois_result = CollectorResult(
                name="WHOIS fallback", status=SKIPPED, detail=BUDGET_SPENT
            )
        else:
            whois_result = _bounded(tail, "WHOIS fallback", lambda: rdap.collect_whois(subject),
                                    finish_by - monotonic())
        bundle.results["WHOIS fallback"] = whois_result
        yield "collector", whois_result

        # Rendering last, and only when it adds something. It is the one step
        # that executes attacker-controlled code, so it never runs speculatively.
        if _should_render(bundle, render_mode):
            render_result = _guard("JS render", lambda: render.collect(url))
        else:
            usable, why = render.available()
            if not usable:
                why_not = why
            elif render_mode == RENDER_AUTO:
                why_not = "not needed, the page returned real markup"
            else:
                why_not = "rendering disabled for this scan"
            render_result = CollectorResult(name="JS render", status=SKIPPED, detail=why_not)
        bundle.results["JS render"] = render_result
        bundle.envelope = dict(ENVELOPE.with_javascript(render_result.ok).as_rows())
        yield "collector", render_result
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        tail.shutdown(wait=False, cancel_futures=True)

    bundle.save()
    yield "bundle", bundle


def scan(url: str, use_cache: bool = True,
         render_mode: str = RENDER_AUTO) -> EvidenceBundle:
    bundle: EvidenceBundle | None = None
    for kind, payload in scan_events(url, use_cache=use_cache, render_mode=render_mode):
        if kind == "bundle":
            bundle = payload  # type: ignore[assignment]
    if bundle is None:   # scan_events always ends with its bundle; not an assert, which -O strips
        raise RuntimeError("scan finished without an evidence bundle")
    return bundle


def registration(bundle: EvidenceBundle) -> dict:
    """Whichever of RDAP or WHOIS answered, or {} if neither did."""
    for name in ("RDAP", "WHOIS fallback"):
        r = bundle.results.get(name)
        if r and r.ok and r.data.get("domain_age_days") is not None:
            return r.data
    return {}
