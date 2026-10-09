"""FastAPI interface.

Three views mirroring the states a scan can actually be in: idle, scanning
(streamed, because per-collector progress is real information — it tells the
user which evidence is missing while the run happens), and result.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.templating import Jinja2Templates

from ..config import (ENVELOPE, HostScanRefused, MisconfiguredDeployment, allowed_hosts,
                      deployment_problems, javascript_permitted, on_vercel,
                      production_origin, stateless,
                      requests_per_minute, shared_instance,
                      warn_about_deployment)
from ..data import store
from ..verify import crosscheck
from .. import urls as urlparse_mod
from ..features.lexical import CLOUD_HOSTS
from ..features.user_content import tenant_platform
from ..netguard import is_public_address
from ..collector import render as render_mod
from ..collector.run import COLLECTOR_ORDER, RENDER_AUTO, RENDER_FORCE, scan_events
from ..model import interval as interval_mod
from ..model.persist import Manifest, load_base_pipeline, load_pipeline
from ..model.score import score, score_bundle
from .presentation import plain_failure, result_details

HERE = Path(__file__).parent


def _asset_version() -> str:
    """Cache-busting token: a hash of every file in static/.

    Without it an edited stylesheet keeps rendering from cache — which cost
    real time here: the mobile fixes appeared to do nothing at all until the
    link was reloaded by hand.

    Content, not modification times. It used to be the newest mtime in the
    directory, which is only as good as the platform's file clock: a
    deployment bundle that stamps every file with the same time would keep
    the token fixed across releases, and a returning visitor would keep last
    release's script against this release's markup. The files are still
    stat'ed on every call, so an edit during development -- which `--reload`
    does not see, since it watches Python files -- changes the token at once;
    the hashing itself only reruns when that signature moves.
    """
    try:
        files = sorted(f for f in (HERE / "static").iterdir() if f.is_file())
        signature = tuple((f.name, f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    except OSError:
        return "0"
    return _hash_static(signature)


@lru_cache(maxsize=4)
def _hash_static(signature: tuple) -> str:
    digest = hashlib.sha256()
    try:
        for name, _, _ in signature:
            digest.update(name.encode())
            digest.update((HERE / "static" / name).read_bytes())
    except OSError:
        return "0"
    return digest.hexdigest()[:12]


class _VersionedStatic(StaticFiles):
    """Static files, cached for as long as their URL says they are current.

    Every reference the templates emit carries `?v=<content hash>`, so a URL
    with today's token names exactly these bytes and can be cached for good.
    Anything else -- no token, an old one -- is told to revalidate. Without an
    explicit header a browser falls back to guessing freshness from
    Last-Modified, which is only as trustworthy as the file clock.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        if response.status_code in (200, 304):
            query = scope.get("query_string", b"").decode("latin-1")
            current = f"v={_asset_version()}" in query.split("&")
            response.headers["Cache-Control"] = (
                "public, max-age=31536000, immutable" if current else "no-cache")
        return response


# Checked at import, before uvicorn binds a port. A contradiction between
# "this is public" and "accept any Host" fails open and is invisible from
# outside, so startup is the only moment anything can say so.
_problems = deployment_problems()
if _problems:
    raise MisconfiguredDeployment(
        "Refusing to start.\n\n" + "\n\n".join(_problems))
for _note in warn_about_deployment():
    print(f"WARNING: {_note}", file=sys.stderr)


# `/docs`, `/redoc` and `/openapi.json` are off on a shared instance. They load
# Swagger's assets from a CDN, which this application's own Content Security
# Policy blocks -- so they render as broken pages rather than useful ones -- and
# they publish the route schema to anyone who asks. Locally they are a
# convenience worth having, so the switch follows the same flag as the other
# operator-only surfaces.
app = FastAPI(title="Phishing Detector", docs_url=None if shared_instance() else "/docs",
              redoc_url=None if shared_instance() else "/redoc",
              openapi_url=None if shared_instance() else "/openapi.json")

# Routes that change local state or make the scanner issue a request. They are
# reachable from any page the operator happens to be visiting -- this app binds
# loopback and has no authentication, so "only I can reach it" is not true of a
# browser. A form POST and an <img src> both cross that boundary silently.
#
# `/result` is in here because it is a scan trigger, not a reader: on a cache
# miss it runs the whole collector chain and writes an evidence bundle, and
# with PHISHING_DETECTOR_ALLOW_JS set auto-render executes the scanned page's
# JavaScript. Guarding it only when `render` was present in the query string
# left every one of those effects reachable from an `<img>` tag on any page the
# operator happened to be visiting. The cost is that a `/result` URL opened
# straight from the address bar, with no referer, is now refused; the way to
# reach one is the form on `/`, which is same-site.
#
# `/runs/rename` and `/runs/delete` used to be here too. They are gone: history
# lives in the visitor's browser, so renaming and removing an entry are local
# edits that never reach the server.
#
# `/scan` is here as well: it renders a page that immediately opens `/api/scan`
# same-origin, so a top-level navigation to it drives a scan just as surely as
# calling the API directly.
_GUARDED_PATHS = frozenset({"/feedback", "/submit", "/api/scan", "/result", "/scan"})


# A hostname and nothing else: labels, dots, an optional trailing dot. No
# slashes, no spaces, no colons -- anything else is not a name this serves.
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                       r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?")


def _route_path(request: Request) -> str:
    """The path, normalised the way the router will resolve it.

    Starlette builds `url.path` from the raw target, and a `Host` header like
    `scan.example.com:/` splices into it: the path arrives as `//api/scan`,
    which is in neither `_GUARDED_PATHS` nor `_COSTLY_PATHS` while the router
    still dispatches it to the scan endpoint. Comparing sets against a raw path
    is only safe if the path is normalised first.
    """
    path = request.url.path
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/") or "/"


def _same_site(candidate: str, host: str) -> bool:
    """True when `candidate` (an Origin or Referer) points back at this server."""
    if not candidate or not host:
        return False
    return urlsplit(candidate).netloc == host


# Scans are the expensive thing and the thing worth abusing: each one fans out
# six collectors against third-party services. Reading a page the visitor has
# already scanned is cheap, so the limit is applied where the cost is -- one
# charge per fetch, not per request.
#
# `/submit` and `/scan` used to be in here too. Neither fetches anything (one
# redirects, the other renders the progress page), but one check through the
# form is `/submit`, `/scan`, `/api/scan` and `/result` in turn, so a limit of
# 20 a minute ran out on the sixth check. `/result` is charged by the route
# itself, and only when its handoff token misses and it has to scan live.
#
# `/feedback` is in here because it calls `score()` to attach the verdict to the
# report, which on a cache miss is a full fetch -- the one route that reached
# the network without being counted.
_COSTLY_PATHS = frozenset({"/api/scan", "/feedback"})
TOO_MANY_CHECKS = "Too many checks from your address. Wait a minute and try again."

# The bundle a progress stream just finished, waiting for the result page.
#
# `/scan` streams the collectors as they land, then sends the browser to
# `/result`. Without this the result page ran the whole scan a second time to
# show what the first one found -- and on a deployment that keeps no cache,
# that was every check, twice. So the finished bundle is parked here under a
# random token the stream hands to the browser, and `/result` collects it once.
#
# It is a handoff, not storage: process memory only, one read, gone in two
# minutes regardless, at most a few dozen at a time. A token that misses --
# expired, another process, a made-up value -- costs one live scan, which is
# what the page did before. The token says nothing about the URL; the URL still
# travels in the query string as it always did.
#
# Each caller holds only a few of the slots. With one shared pool, a single
# address running scans back to back pushed everyone else's results out before
# their browsers could collect them, and each of those visitors paid for a
# second scan.
_HANDOFF: dict[str, tuple[float, object, str]] = {}
_HANDOFF_LOCK = threading.Lock()
_HANDOFF_TTL_S = 120.0
_HANDOFF_MAX = 64
_HANDOFF_PER_CALLER = 4


# The evidence a result page is showing, kept for its "Report a problem" form.
# A report is about the verdict the person saw, so it has to be scored from
# the same bundle: `/feedback` used to score with the disk cache, which on an
# instance with weeks-old bundles recorded -- and then displayed -- a
# different verdict from the one being reported. Only on an instance that
# collects reports; longer-lived than the handoff, because a result is read
# before it is disputed, and smaller.
_REPORTABLE: dict[str, tuple[float, object, str]] = {}
_REPORTABLE_TTL_S = 1800.0
_REPORTABLE_MAX = 32
_REPORTABLE_PER_CALLER = 2


def _park(store: dict, ttl: float, cap: int, per_caller: int, bundle, owner: str) -> str:
    token = secrets.token_urlsafe(18)
    now = time.monotonic()
    with _HANDOFF_LOCK:
        for key in [k for k, (expires, _, _) in store.items() if expires <= now]:
            del store[key]
        mine = [k for k, (_, _, who) in store.items() if who == owner]
        for key in mine[: max(0, len(mine) - per_caller + 1)]:
            del store[key]
        while len(store) >= cap:
            del store[next(iter(store))]
        store[token] = (now + ttl, bundle, owner)
    return token


def _collect_parked(store: dict, token: str, url: str | None):
    with _HANDOFF_LOCK:
        entry = store.pop(token, None)
    if entry is None or entry[0] <= time.monotonic():
        return None
    if url is not None and getattr(entry[1], "url", None) != urlparse_mod.parse(url).raw:
        return None
    return entry[1]


def _stash(bundle, owner: str = "") -> str:
    return _park(_HANDOFF, _HANDOFF_TTL_S, _HANDOFF_MAX, _HANDOFF_PER_CALLER, bundle, owner)


def _take(token: str, url: str | None = None):
    """The parked bundle, once -- and only for the address it was collected for.

    The token says nothing about the URL, which travels separately in the
    query string, so `/result?url=B&t=<A's token>` used to show B's address
    over A's evidence. Only the token's holder could see that, but a verdict
    page naming one site and describing another should not exist at all.
    """
    return _collect_parked(_HANDOFF, token, url)


# caller -> timestamps of their recent costly requests. Bounded by pruning, so
# a long run of one-request-each callers cannot grow it without limit.
_RECENT_CALLS: dict[str, list[float]] = {}
_MAX_TRACKED_CALLERS = 4096

# Held across the read-modify-write below. It holds today without one, because
# the middleware runs in the event loop and there is no await inside the
# critical section -- but that is a property of how this happens to be called,
# not of the code, and it disappears the moment anyone adds an await or calls
# it from a thread. `collector/base.RateLimiter` carries a comment about the
# unlocked version of exactly this bug letting eight threads through a 2 req/s
# limit; once per project is enough.
_LIMIT_LOCK = threading.Lock()


# One line per refusal, to stderr, which journald captures under systemd. There
# is no admin page for this and there should not be: the app has no
# authentication, so any route that reported who was hammering it would report
# that to them too. The log is the one place only the operator can read.
#
# Format is `key=value` so it survives grep and `scripts/abuse_report.py` can
# parse it without a log library on either end.
_log = logging.getLogger("phishing_detector.refused")
_errors = logging.getLogger("phishing_detector.web")

SCAN_FAILED = "The check could not be completed. Try again in a moment."

# On a stateless instance the log is the one place a visitor's address would
# still land, and the platform keeps it for a while. So the address is replaced
# with a keyed hash: the key is drawn once per process and never written, so
# the same caller reads the same within one process's log -- enough to see
# "one address, four hundred refusals" -- and nobody, including the operator,
# can turn the token back into an address afterwards.
_CALLER_KEY = secrets.token_bytes(16)


def _loggable(caller: str) -> str:
    if not stateless():
        return caller
    digest = hmac.new(_CALLER_KEY, caller.encode("utf-8", "replace"), "sha256").hexdigest()
    return f"h:{digest[:12]}"


def _log_token(value: str) -> str:
    """A caller-supplied string made safe to put in a `key=value` log line.

    The path and the caller come from the request; a decoded `%0A` in either
    would start a new line of the operator's log, written by a stranger.
    """
    return "".join(c if c.isprintable() and not c.isspace() else f"\\x{ord(c):02x}"
                   for c in value[:200])


def record_refusal(kind: str, caller: str, path: str, detail: str = "") -> None:
    """Note that a request was turned away, and why."""
    line = f"refused kind={kind} caller={_log_token(_loggable(caller))} path={_log_token(path)}"
    if detail:
        line += f" detail={detail!r}"
    _log.warning(line)


def _caller(request: Request) -> str:
    """Who to count this request against.

    `request.client.host` is the peer address, which behind a proxy is the proxy
    itself -- uvicorn runs with `--proxy-headers --forwarded-allow-ips=127.0.0.1`
    so that it becomes the real client instead. X-Forwarded-For is deliberately
    not read here: trusting it directly would let any caller pick their own
    bucket by sending a header.

    Vercel is the one exception, and only because the platform documents that
    it overwrites `x-forwarded-for` and `x-vercel-forwarded-for` with the
    address it saw and refuses to forward a caller-supplied value. There is no
    uvicorn in front of the function to do this translation, so without it
    every visitor would share the peer address of the platform's own proxy --
    one bucket for the whole site, and the limit throttling everyone at once.
    """
    if on_vercel():
        forwarded = (request.headers.get("x-vercel-forwarded-for")
                     or request.headers.get("x-forwarded-for") or "")
        first = forwarded.split(",")[0].strip()
        if first:
            return _bucket(first)
    return _bucket(request.client.host) if request.client else "unknown"


def _bucket(address: str) -> str:
    """The unit one visitor controls: an IPv4 address, or an IPv6 /64.

    A single IPv6 subscriber is routinely handed a whole /64, so counting per
    address gave them 2^64 fresh allowances.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 4:
        return str(ip)
    if ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _over_limit(caller: str, limit: int, now: float) -> bool:
    with _LIMIT_LOCK:
        window_start = now - 60.0
        calls = [t for t in _RECENT_CALLS.get(caller, ()) if t > window_start]
        if len(calls) >= limit:
            _RECENT_CALLS[caller] = calls
            return True
        calls.append(now)
        _RECENT_CALLS[caller] = calls

        if len(_RECENT_CALLS) > _MAX_TRACKED_CALLERS:
            for key in [k for k, v in _RECENT_CALLS.items() if not v or v[-1] <= window_start]:
                del _RECENT_CALLS[key]
            # Dropping stale entries is not enough on its own: if every tracked
            # caller is recent, nothing is stale and the map keeps growing. Evict
            # the least recently seen until it is back under the cap. Evicting an
            # active caller only forgives them their earlier requests, which is the
            # right way to be wrong under memory pressure.
            if len(_RECENT_CALLS) > _MAX_TRACKED_CALLERS:
                oldest = sorted(_RECENT_CALLS, key=lambda k: _RECENT_CALLS[k][-1])
                for key in oldest[: len(_RECENT_CALLS) - _MAX_TRACKED_CALLERS]:
                    del _RECENT_CALLS[key]
        return False


# Middleware, in registration order. Starlette wraps in reverse, so the LAST
# one registered is the OUTERMOST -- the order below is deliberately upside
# down from the order they execute in:
#
#   no_cache_html      (outermost: every response, including 421/429/403, gets
#                       the security headers)
#     trusted_host     (Host is validated before anything reasons about it)
#       cross_origin_guard
#         rate_limit   (only requests that could start a fetch are counted)
#           the route
#
# The guard sits above the limiter on purpose. The other way round, a
# cross-site `<img src=".../api/scan?url=x">` was refused -- but only after it
# had been charged to the visitor's address, so any page open in their browser
# could spend their quota for them. A phishing page could keep its own victim
# from checking it, and everyone behind the same NAT with them.
#
# The Host check has to sit above `cross_origin_guard`, which compares Origin
# against Host: letting it compare against a Host nobody has validated means it
# is deciding on the caller's own say-so. That was harmless while the request
# died at the Host check anyway, but only by luck of ordering.


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Cap how often one caller can make this instance go and fetch things.

    Off by default: on loopback the only caller is the operator. Set
    PHISHING_DETECTOR_RPM on anything more than one person can reach, or the
    deployment is an open fetch service -- someone else's crawler, running under
    this machine's address, this project's User-Agent and its API keys, with the
    abuse reports arriving here.

    A fixed window per minute, in memory. It is deliberately not a distributed
    or persistent limiter: this is one process, and a limit that resets on
    restart is still the difference between "expensive to abuse" and "free".
    """
    path = _route_path(request)
    if path in _COSTLY_PATHS and _charge(request):
        if path == "/api/scan":
            # The progress page reads this with EventSource, which drops the
            # body of any non-200 response and reports only that the
            # connection failed -- so a 429 here told the visitor "connection
            # lost". The refusal travels as an event the page can show.
            return _sse_error(TOO_MANY_CHECKS, {"Retry-After": "60"})
        return PlainTextResponse(TOO_MANY_CHECKS, status_code=429, headers={"Retry-After": "60"})
    return await call_next(request)


def _sse(event: dict) -> str:
    """One server-sent event carrying `event` as JSON."""
    return f"data: {json.dumps(event)}\n\n"


def _sse_error(detail: str, headers: dict | None = None) -> StreamingResponse:
    """A progress stream that carries one error event and ends."""
    return StreamingResponse(iter([_sse({"type": "error", "detail": detail})]),
                             media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", **(headers or {})})


def _charge(request: Request) -> bool:
    """Count one fetch against this caller; True when that is one too many."""
    limit = requests_per_minute()
    if not limit:
        return False
    caller = _caller(request)
    if _over_limit(caller, limit, time.monotonic()):
        record_refusal("rate_limit", caller, _route_path(request), f"over {limit}/min")
        return True
    return False


@app.middleware("http")
async def cross_origin_guard(request: Request, call_next):
    """Refuse state-changing requests that did not come from this app's own pages.

    Without this, any site the operator visits can drive the scanner: push
    forged corrections into the feedback queue, and -- because `/api/scan` and
    `/result` are state-changing GETs -- make the instance fetch an address of
    the attacker's choosing from inside the operator's network. None of it needs
    a click; an image tag is enough.

    Same-origin requests carry an Origin (fetch and form POSTs) or a same-site
    Referer (our own pages' GETs). A cross-origin image or form carries the
    attacker's origin, or none at all, and both are refused.
    """
    path = _route_path(request)
    if request.method in ("GET", "HEAD"):
        # A GET of `/submit` only sends the browser to the front page -- it is
        # what a reload or a typed address does after a refused check -- so it
        # starts nothing and needs no same-site proof.
        guarded = path in _GUARDED_PATHS and path != "/submit"
    else:
        guarded = True
    if guarded:
        host = request.headers.get("host", "")
        source = request.headers.get("origin") or request.headers.get("referer") or ""
        # A browser that sends no Referer at all (a privacy setting, an
        # extension) gave its own pages' GETs neither header: the form posted,
        # `/scan` answered "press Check", and pressing it led back there for
        # ever. `Sec-Fetch-Site` is sent whatever the referrer settings, and no
        # page can set it; a link from elsewhere arrives as "none" or
        # "cross-site" and is still refused.
        fetched_by_us = request.headers.get("sec-fetch-site", "") == "same-origin"
        if not fetched_by_us and not _same_site(source, host):
            record_refusal("cross_origin", _caller(request), path,
                           source[:80] or "no origin or referer")
            if request.method == "GET" and path in _CONFIRM_FIRST_PATHS:
                return _confirm_first(request)
            return PlainTextResponse("cross-origin request refused", status_code=403)
    return await call_next(request)


# Pages a person opens, as opposed to endpoints a page calls. A link to one of
# these arrives from a chat, an email or a bookmark with no same-site Referer,
# and so does every visit from a browser that strips Referer altogether. Those
# are refused all the same -- no scan starts -- but with the front page and the
# address already in the box, one click from checking it, rather than a line
# of plain text that reads like the site is broken.
_CONFIRM_FIRST_PATHS = frozenset({"/scan", "/result"})


def _confirm_first(request: Request):
    url = request.query_params.get("url", "").strip()
    problem = _input_problem(url) if url else None
    return _refuse_input(
        request, url, problem, status_code=403,
        confirm_note=None if (problem or not url) else "Press Check to look at this address.")


@app.middleware("http")
async def trusted_host(request: Request, call_next):
    """Answer only to the hostnames this instance was told it has.

    The cross-origin guard compares Origin against the Host header, and Host is
    whatever the caller sent. A request carrying `Host: evil.example` and
    `Origin: http://evil.example` therefore agrees with itself and passes the
    guard. Pinning the acceptable values closes that, and does it in the app
    rather than in a proxy config that may or may not have been written.
    """
    hosts = allowed_hosts()
    if hosts:
        raw = request.headers.get("host", "")
        # Split off the port, then require what is left to be a plain hostname.
        # `split(":")[0]` alone accepted `scan.example.com:/` -- the allowed name
        # with a path glued on, which passed here and then reappeared inside
        # `url.path`.
        sent, _, port = raw.rpartition(":")
        if not sent or not port.isdigit():      # no port, or not a port at all
            sent, port = raw, ""
        sent = sent.lower()
        if not _HOSTNAME.fullmatch(sent) or sent.rstrip(".") not in hosts:
            record_refusal("bad_host", _caller(request), request.url.path, raw[:80])
            return PlainTextResponse("unrecognised host", status_code=421)
    return await call_next(request)


def _over_https(request: Request) -> bool:
    """Whether the visitor reached this over HTTPS.

    On Vercel always: the edge redirects plain HTTP before a function sees it,
    and the scheme in the ASGI scope is the platform's internal hop, not the
    visitor's. Elsewhere the scope is all there is. Loopback development is
    plain HTTP, where HSTS and `upgrade-insecure-requests` would break the page.
    """
    return on_vercel() or request.url.scheme == "https"


def _csp(nonce: str, https: bool = False) -> str:
    """The content security policy, which is mostly about one thing.

    Scan history lives in `localStorage` now, so script injection on this origin
    would read every link the visitor has checked. Nothing here is known to be
    injectable -- the templates autoescape, there is no `|safe` outside the
    `tojson` history blob, and the history tray builds its rows with
    `textContent` -- so this is the layer under those, not a fix for a known
    hole.

    A nonce rather than `unsafe-inline`, because `unsafe-inline` would permit
    exactly the injected `<script>` this exists to stop. Inline *styles* keep
    `unsafe-inline`: the templates use style attributes for layout, and a
    style injection cannot read localStorage.
    """
    directives = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",          # the scan progress EventSource
        "form-action 'self'",
        "base-uri 'none'",             # no <base> rewriting where forms post
        "object-src 'none'",
        "frame-ancestors 'none'",
    ]
    if https:
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


# Browser features no page here uses. Denying them means an injected script or
# a future embed cannot prompt the visitor for any of them under this origin.
_PERMISSIONS_POLICY = ", ".join(f"{feature}=()" for feature in (
    "camera", "microphone", "geolocation", "payment", "usb", "serial",
    "bluetooth", "hid", "midi", "magnetometer", "gyroscope", "accelerometer",
    "display-capture", "browsing-topics",
))


def _secure(response, request: Request):
    """The headers every response carries, errors included."""
    nonce = getattr(request.state, "csp_nonce", None) or secrets.token_urlsafe(16)
    # Framing this app is only useful for tricking the operator into clicking
    # its buttons, so refuse it outright.
    response.headers["X-Frame-Options"] = "DENY"
    https = _over_https(request)
    response.headers.setdefault("Content-Security-Policy", _csp(nonce, https))
    if https:
        # Two years, the figure preload lists ask for. No `preload`: that is a
        # commitment about the whole domain, and the operator's to make.
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
    # No other origin gets a handle on this window, or may embed its responses.
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # A result URL carries the scanned address in its query string. Nothing
    # rendered today links off-site, but this is what keeps that URL at home
    # if something ever does -- and it still sends the same-site Referer the
    # cross-origin guard reads on `/result`.
    response.headers["Referrer-Policy"] = "same-origin"
    # Assets are served with their declared type; refuse to let a browser
    # second-guess one into a script.
    response.headers["X-Content-Type-Options"] = "nosniff"
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    """A fault's 500, with the same headers as any other response.

    Starlette answers an unhandled exception from outside every middleware, so
    this page was the one response without them. The text says nothing about
    the fault; the log has it.
    """
    _errors.error("unhandled error on %s", _log_token(request.url.path), exc_info=exc)
    return _secure(PlainTextResponse(SCAN_FAILED, status_code=500), request)


@app.middleware("http")
async def no_cache_html(request: Request, call_next):
    """Never let a browser cache a page of this app.

    Every page here is a live verdict or a live queue, so a
    cached copy is always wrong. It also made development quietly confusing:
    edited markup kept rendering from cache, and the fix — a hard reload — is a
    different keystroke in every browser and is not something a user should
    need to know. Static assets keep their own cache-busting query.
    """
    # A fresh nonce per response, generated before the templates render so they
    # can carry it on their inline scripts.
    request.state.csp_nonce = secrets.token_urlsafe(16)

    response = await call_next(request)
    _secure(response, request)
    return response


app.mount("/static", _VersionedStatic(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.filters["plain_failure"] = plain_failure


# Plain-English names for the sub-collectors, used everywhere a person who is
# not an engineer can see them: the progress list while a scan runs, and the
# per-source record on a result. The technical name stays the key, so a source
# added upstream without an entry here still renders — under its own name.
SOURCE_NAMES = {
    "HTTP chain":     "Page and redirects",
    "TLS certificate": "Its security certificate",
    "DNS A / AAAA":   "Which computer it points to",
    "DNS MX / NS":    "Its mail and name servers",
    "RDAP":           "Who registered the address",
    "WHOIS fallback": "Registration records, second source",
    "ASN / geo":      "Who hosts it, and where",
    "CT log history": "When its certificates were first issued",
    "Favicon":        "The little icon in the tab",
    "JS render":      "The page with its own scripts run",
}


# (id, what the reader picks, what it means). A list of triples rather than a
# mapping because the form renders all three columns: the template was already
# unpacking three values and a two-column mapping made the page 500.
FEEDBACK_KINDS = [
    ("false_positive", "This site is fine, and you flagged it",
     "A legitimate page that should have scored below the line."),
    ("false_negative", "This is a scam, and you missed it",
     "A phishing page the score treated as ordinary."),
    ("bad_evidence", "The evidence itself is wrong",
     "A source returned something incorrect, so the details are wrong rather "
     "than the judgement. Logged, never trained on."),
]
FEEDBACK_KIND_IDS = {kind for kind, _, _ in FEEDBACK_KINDS}

# Longest submitted address this service will carry. Past any real URL, and
# short of the length at which a `Location` header built from it starts being
# refused by whatever proxy sits in front.
MAX_SUBMITTED_URL = 2000
# What may be pasted around the address -- a sentence, a wrapped email line --
# is longer than the address, but not without bound: the field is read and
# split before the address in it is known, and the form parser alone allows a
# megabyte per field.
MAX_PASTED = 10 * MAX_SUBMITTED_URL
PASTED_TOO_LONG = "That is too much text to check. Paste just the link."


def _tone(decision: str, probability: float | None, threshold: float) -> tuple[str, str]:
    """The single rule that turns a verdict into a colour and a word.

    Keyed off the crosscheck decision rather than the raw score, because the
    decision is what the headline is written from and it can legitimately
    overrule the score: a decisive known-good rule clears a domain the model
    scored high. Colouring from the score meant wikipedia.org flooded the page
    in oxblood under a headline reading "Nothing suspicious found" - a
    contradiction that either frightens someone about a safe site or teaches
    them the colour means nothing.

    Note the known-good rule is no longer granted on a host that publishes
    strangers' pages (`user_content_on_brand_domain`), so "the brand's own
    domain" no longer means "a page the brand wrote".

    A decisive rule decision (CONFIRMED_PHISH/CONFIRMED_BENIGN) always wins,
    however the raw score came out - that is what keeps a decisive known-good
    rule able to clear a domain the model scored at 0.88 in the first place.

    An abstention (NEEDS_REVIEW) is itself a conclusion and reads as one, at
    any score. It used to fall through to the score, which inverted the point
    of the cross-check: the engine declined to back the number and the number
    won anyway, so a legitimate brand page at 0.909 against a 0.90 threshold
    came out as "Looks dangerous". An abstention is now always amber, in both
    directions - it no longer reads green on a low score either.

    Only a scan that reached no rule decision at all falls through to the
    score, where a value within `crosscheck.MID_BAND_RATIO` of the operating
    line reads as unsure and anything further reads as dangerous or safe.

    Every surface that shows a state calls this, so the tray, the result page
    and the page title cannot drift apart.
    """
    if decision == crosscheck.CONFIRMED_PHISH:
        return "risk", "Looks dangerous"
    if decision == crosscheck.CONFIRMED_BENIGN:
        return "safe", "Looks safe"
    if decision == crosscheck.NEEDS_REVIEW:
        # An abstention is a conclusion, not an absence of one: the rule engine
        # looked at the evidence and declined to back the score. Falling through
        # to the score here let the model overrule the very check that exists to
        # overrule the model -- real google.com scores 0.909 against a 0.90
        # threshold (model/score.py), so a legitimate brand page came out as
        # "Looks dangerous" while the cross-check was saying it could not tell.
        # Whatever the score, an abstention renders as an abstention.
        return "unsure", "Not sure"
    if probability is not None:
        if threshold * crosscheck.MID_BAND_RATIO <= probability < threshold:
            return "unsure", "Not sure"
        if probability >= threshold:
            return "risk", "Looks dangerous"
    return "safe", "Looks safe"


def _corrections(limit: int = 100) -> dict:
    """Reports of a wrong verdict, newest first, plus the summary line above them.

    Read on every page because the tray that shows them slides over whatever
    page is open rather than living at its own route, so there is no request
    left where fetching it separately would help.

    A database that is locked, unreadable or on a full disk used to fail every
    page this way, not just the tray; the tray is shown empty instead.
    """
    try:
        with store.connect() as conn:
            rows = store.feedback_queue(conn, limit=limit)
            summary = store.feedback_summary(conn)
    except (sqlite3.Error, OSError):
        _errors.exception("corrections could not be read")
        return {"rows": [], "summary": {"from_abstentions": 0}}
    return {"rows": rows, "summary": summary}


_BIDI_CONTROLS = dict.fromkeys(
    [0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])


def _visible(text: str) -> str:
    return text.translate(_BIDI_CONTROLS)


def _url_parts(url: str) -> dict:
    """An address split into the pieces a reader needs to tell apart.

    Only the registrable domain says who owns the site; a brand sitting in the
    subdomain or the path is free for anyone to write. Splitting it here rather
    than in the browser means the public suffix list decides where the
    boundary falls, so `a.b.co.uk` is cut in the right place instead of by a
    guess about how many labels a suffix has.
    """
    try:
        p = urlparse_mod.parse(url)
    except Exception:  # noqa: BLE001 - a display aid must never break the page
        return {"hostname": url, "registrable": "", "rest": ""}
    rest = p.path or ""
    if p.query:
        rest += "?" + p.query
    if p.fragment:
        rest += "#" + p.fragment
    subdomain, registrable, provider = p.subdomain, p.registrable, p.hosting_provider
    platform = "" if provider else tenant_platform(p.hostname, CLOUD_HOSTS)
    if platform:
        # A customer's site on a platform the suffix list does not cover: the
        # customer's own label is what they control, so it is what is marked.
        labels = p.hostname[: -(len(platform) + 1)].split(".")
        subdomain, registrable, provider = ".".join(labels[:-1]), f"{labels[-1]}.{platform}", platform
    return {
        "scheme": p.scheme,
        # Direction controls are removed from the parts a reader skims: a
        # decoded U+202E in the userinfo could reorder the grey text around
        # the host so it read as a different address.
        "userinfo": _visible(p.userinfo),
        "subdomain": subdomain,
        "hostname": p.hostname,
        "registrable": registrable,
        "port": p.port,
        "rest": _visible(rest),
        # A free subdomain nobody had to register is worth saying out loud:
        # registration evidence then describes the provider, not this site.
        "provider": provider,
    }


def _context(request: Request, **kw) -> dict:
    js_ok, _ = render_mod.available()
    return {
        "request": request,
        "envelope": ENVELOPE.as_rows(),
        "js_available": js_ok,
        "asset_version": _asset_version(),
        "feedback_kinds": FEEDBACK_KINDS,
        "source_names": SOURCE_NAMES,
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        # For the link-preview tags, which need absolute addresses. Locally the
        # request's own origin; Host is pinned on a shared instance.
        "site_origin": production_origin() or str(getattr(request, "base_url", "")).rstrip("/"),
        # The corrections tray renders on every page, so this cannot stay
        # local to one route. `kw` still wins, so a caller may override it.
        # History is not here: it lives in the visitor's own browser. See
        # `_history_entry` and the tray script in base.html.
        #
        # Corrections are withheld on a shared instance -- the queue holds the
        # notes and URLs everyone has submitted, and showing each visitor
        # everyone else's reports is the same mistake history used to make.
        # `feedback_cli.py` is the review path there.
        #
        # A stateless instance has no queue to show either: opening the
        # database on a read-only tree would fail, and take every page with it.
        "corrections": None if (shared_instance() or stateless()) else _corrections(),
        "shared_instance": shared_instance(),
        # A stateless instance has nowhere to put a correction, so the form is
        # not offered rather than offered and then failed.
        "feedback_enabled": not stateless(),
        **kw,
    }


def _render_permitted(url: str) -> tuple[bool, str]:
    """Whether JavaScript execution has been earned for this URL.

    Rendering is the one operation that runs attacker-controlled code, so it is
    not a default-available toggle. It unlocks only after a scan *without* it
    has already come back inconclusive, which is the case it actually exists to
    solve: a client-side kit that returns an empty body and leaves the evidence
    too thin to decide.

    Enforced here rather than in the template. Removing a checkbox from the page
    does not stop anyone appending &render=true by hand.
    """
    try:
        with store.connect() as conn:
            prior = store.last_scan(conn, url)
    except Exception:  # noqa: BLE001 - a store failure must not unlock rendering
        return False, "the previous result for this URL could not be read"
    if prior is None:
        return False, "this URL has not been scanned yet"
    if not prior["abstained"]:
        return False, "the scan without JavaScript already reached a verdict"
    return True, ""


def _render_requested(url: str, requested: bool) -> bool:
    """A render flag from the query string, silently dropped unless earned."""
    return bool(requested and _render_permitted(url)[0])


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _remember(url: str, verdict) -> None:
    """Record that this URL was scanned, for the earned-render gate only.

    This used to be the backing store for the history list, which meant one
    shared table held every visitor's scanned URLs and showed them to each
    other. History moved into the browser (`_history_entry`), and the row's only
    remaining reader is `_render_permitted`: it needs to know whether a previous
    scan of this URL abstained, and that question cannot be answered by the
    client, because the client is exactly the party that benefits from lying
    about it.

    So the row is written only when rendering is possible at all. With
    PHISHING_DETECTOR_ALLOW_JS unset -- the public default -- nothing can consult
    it, and nothing is stored.
    """
    if not javascript_permitted():
        return
    try:
        with store.connect() as conn:
            store.record_scan(
                conn, url=url, host=verdict.bundle.parsed.hostname,
                scanned_at=verdict.bundle.collected_at, label=verdict.label,
                decision=verdict.review.decision if verdict.review else "",
                probability=None if verdict.untrained else verdict.probability,
                abstained=bool(verdict.review and verdict.review.abstained),
            )
    except Exception:  # noqa: BLE001 - a bookkeeping failure must not break the page
        pass


def _history_entry(url: str, verdict) -> dict:
    """What the browser saves to its own history list for this scan.

    Assembled here rather than in JavaScript because `_tone` decides both the
    badge colour and the wording from the decision and the threshold. Computing
    it twice, once per language, is how the tray would come to disagree with the
    page it was opened from.
    """
    probability = None if verdict.untrained else verdict.probability
    if probability is None:
        tone, state = "unsure", "Scoring unavailable"
    else:
        manifest = Manifest.load()
        threshold = manifest.threshold if manifest else 0.5
        tone, state = _tone(verdict.review.decision if verdict.review else "",
                            probability, threshold)
    return {
        # The browser files the page's markup under this and opens it from the
        # history tray by it. Random rather than derived from the URL, so a
        # history link says nothing about what was checked.
        "id": secrets.token_urlsafe(9),
        "url": url,
        "host": verdict.bundle.parsed.hostname,
        "when": str(verdict.bundle.collected_at),
        "tone": tone,
        "state": state,
        "score": None if probability is None else round(probability * 100),
    }


def _is_checkable(url: str) -> bool:
    """Whether this is a web address worth scanning, before any network work."""
    # `mailto:a@b.com` has no "://", so the line below would read it as
    # `https://mailto:a@b.com` -- user "mailto:a", host "b.com" -- and accept
    # it, while `urls.parse` reads it as the mail link it is and the scan then
    # ran every collector against nothing.
    if url.strip().lower().startswith(urlparse_mod.HOSTLESS_SCHEMES):
        return False
    try:
        parsed = urlsplit(url if "://" in url else "https://" + url)
        # `urlsplit` takes "a b.com" as a hostname; the browser's URL parser,
        # which the form checks with, does not, and nothing could resolve it.
        if parsed.hostname and any(ch.isspace() or ord(ch) < 32 for ch in parsed.hostname):
            return False
        if not (parsed.scheme in ("http", "https") and parsed.hostname
                and ("." in parsed.hostname or ":" in parsed.hostname
                     or parsed.hostname == "localhost") and parsed.port != 0):
            return False
    except ValueError:
        return False
    # And the scanner's own parser has to find a host too. `urlsplit` accepts
    # `http://%25.com/`; the scanner, like a browser, does not -- so it was
    # accepted here and then scanned as an address with no host at all. A host
    # with no name in it -- `www.`, `.com` -- is no more checkable.
    p = urlparse_mod.parse(url)
    # Structural rather than by the suffix list: on Vercel that list is a
    # bundled snapshot, and a TLD delegated since must not be refused.
    labels = p.hostname.strip(".").split(".")
    return bool(p.hostname) and (p.is_ip_host or p.hostname == "localhost"
                                 or (len(labels) >= 2 and all(labels)))


NOT_A_WEB_ADDRESS = ("Enter a web address, such as example.com. "
                     "Only HTTP and HTTPS links can be checked.")


def _input_problem(url: str) -> str | None:
    """Why this address will not be checked, in the form's words, or None.

    Every route that starts or shows a scan asks this, not only `/submit`: the
    others take the address from the query string, so a link to
    `/scan?url=javascript:...` would otherwise send DNS, RDAP and CT lookups
    after a host called "javascript" and then present a verdict on it.

    Too long is refused rather than cut to length. Truncating would check a
    different address from the one pasted, and say nothing about it.
    """
    if len(url) > MAX_SUBMITTED_URL:
        return (f"That address is too long to check. Addresses of up to "
                f"{MAX_SUBMITTED_URL} characters can be checked.")
    if not _is_checkable(url):
        return NOT_A_WEB_ADDRESS
    if _names_private_network(url):
        return PRIVATE_ADDRESS
    return None


PRIVATE_ADDRESS = ("That address points to a private network or to this computer, not to a "
                   "public website. This checker only looks at public websites.")


def _names_private_network(url: str) -> bool:
    """Whether the address is *written* as a private one: an IP or localhost.

    Only what can be told without a lookup. A name that resolves somewhere
    private is still refused, by the fetch guard; this just saves the visitor
    a scan that could only end in "we could not load the page".
    """
    host = urlparse_mod.parse(url).hostname.strip("[]").rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return not is_public_address(ipaddress.ip_address(host))
    except ValueError:
        return False


ONE_AT_A_TIME = "That looks like more than one address. Paste one at a time."
_SCHEME_TOKEN = re.compile(r"(?i)^https?://")
# A name with a dot and a final label of letters (or an IDN "xn--" label), or
# a dotted IPv4 address, optionally with a port and a path.
_NAME_TOKEN = re.compile(
    r"(?i)^(?:(?:[^\s/@:.]+\.)+(?:[^\W\d_]{2,}|xn--[a-z0-9-]+)\.?"
    r"|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/?#]\S*)?$")
# A word of a sentence: letters, perhaps an apostrophe or hyphen inside, and
# the punctuation a sentence puts around it.
_WORD_TOKEN = re.compile(r"^[(\"'\u201c\u2018]*[^\W\d_]+(?:['\u2019-][^\W\d_]+)*[.,!?;:)\"'\u201d\u2019]*$")
_LEADING_PUNCT = "(<[\"'\u201c\u2018"
_TRAILING_PUNCT = ".,;:!?>]\"'\u201d\u2019"
# Where a wrapped link's line can break mid-query, so the next piece joins
# even when it reads as a word or a name (`?to=` + `evil.com/x`). After a `/`
# or a `.` only a piece that is not a word joins: "https://x.example/ is it
# ok?" and "paypal.com. Thanks" are sentences.
_BREAK_AFTER = tuple("?&=#%+-_~")
_BREAK_BEFORE = tuple("/?&=#.%-_")
_SCHEME_ONLY = re.compile(r"(?i)^https?:/{0,2}$")


def _trim(token: str) -> str:
    """A token without the sentence punctuation around it, as autolinkers do:
    a `)` stays only when it closes a `(` inside the address."""
    token = token.lstrip(_LEADING_PUNCT)
    while token:
        if token[-1] in _TRAILING_PUNCT:
            token = token[:-1]
        elif token[-1] == ")" and token.count(")") > token.count("("):
            token = token[:-1]
        else:
            break
    return token


def _is_address(token: str) -> bool:
    t = _trim(token)
    return bool(_SCHEME_TOKEN.match(t) or _NAME_TOKEN.match(t))


def _one_address(raw: str) -> tuple[str, str | None]:
    """The address in what was pasted, and a reason it cannot be used, if any.

    A long link wrapped across two lines in an email has to come back whole,
    so a piece is joined to the one before when the line could have broken
    there: after a `/`, `?`, `&`, `=` and the like, or before one, or when the
    piece is not a plain word. Plain words around the address are a sentence
    -- "is https://... safe?" -- and are dropped; joining them made
    `https://paypal.complease`. A second address anywhere is refused rather
    than glued onto the first. Mirrored in `static/site.js`.
    """
    tokens = raw.split()
    first = next((i for i, t in enumerate(tokens) if _is_address(t)), None)
    if first is None:
        return "".join(tokens), None
    address = tokens[first].lstrip(_LEADING_PUNCT)
    i = first + 1
    while i < len(tokens):
        nxt = tokens[i]
        if (_SCHEME_ONLY.match(address) or address.endswith(_BREAK_AFTER)
                or nxt.startswith(_BREAK_BEFORE)
                or not (_WORD_TOKEN.match(nxt) or _is_address(nxt))):
            address += nxt
            i += 1
        else:
            break
    rest = tokens[i:]
    if any(_is_address(t) for t in rest):
        return "".join(tokens), ONE_AT_A_TIME
    # Trailing punctuation is a sentence's only when a sentence was there, or
    # when the address came wrapped in brackets: a lone `https://x.example/a.`
    # is left as typed.
    wrapped = tokens[first][:1] in _LEADING_PUNCT
    return (_trim(address) if rest or first or wrapped else address), None


def _refuse_input(request: Request, url: str, problem: str | None, status_code: int = 422,
                  confirm_note: str | None = None):
    """The front page again, with the address kept and the reason under it."""
    return templates.TemplateResponse(request, "index.html", _context(
        request, url=url[:MAX_SUBMITTED_URL], input_error=problem, confirm_note=confirm_note,
    ), status_code=status_code)


# Scanning is what the other routes do, and a crawler following a shared
# `/scan?url=...` link would only ever reach the confirm-first page -- but
# there is no reason to invite it. The front page is the only thing worth
# indexing.
ROBOTS = "User-agent: *\nDisallow: /scan\nDisallow: /result\nDisallow: /api/\nDisallow: /history\nDisallow: /submit\nDisallow: /feedback\nAllow: /\n"


@app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
async def robots():
    return PlainTextResponse(ROBOTS)


@app.get("/submit", include_in_schema=False)
async def submit_get():
    """The address bar shows `/submit` after a refused address; reloading or
    returning to it is a GET, which is the front page."""
    return RedirectResponse("/", status_code=303)


_ERROR_WORDS = {
    404: ("There is no page here", "The address may have been mistyped, or the page it pointed "
          "to has been moved."),
    405: ("That page cannot be used this way", "Open it from the home page instead."),
    413: ("That is too much text to check", "Paste just the link."),
}


# Both forms hold an address and a short note. Starlette's own bounds are a
# thousand fields of a megabyte each, and an urlencoded body is buffered
# whole before any of them applies, so a self-hosted instance (Vercel stops
# at 4.5 MB) could be made to hold a gigabyte per request.
MAX_FORM_BYTES = 256 * 1024


async def _read_form(request: Request):
    """The posted form, refused with 413 once its body passes MAX_FORM_BYTES."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_FORM_BYTES:
        raise StarletteHTTPException(413)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FORM_BYTES:
            raise StarletteHTTPException(413)
    # Request.form reads a body already set here instead of the spent stream.
    request._body = bytes(body)
    return await request.form(max_files=0, max_fields=20)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    """HTML for people, JSON for the API routes that were always JSON."""
    if request.url.path.startswith("/api/") or exc.status_code not in _ERROR_WORDS:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))
    heading, explanation = _ERROR_WORDS[exc.status_code]
    return templates.TemplateResponse(request, "error.html", _context(
        request, status_code=exc.status_code, heading=heading,
        explanation=explanation), status_code=exc.status_code,
        headers=getattr(exc, "headers", None))


@app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
async def favicon():
    """Browsers request this path directly regardless of the <link rel=icon>.

    Left as a 404 it does not just add log noise: a failed fetch here leaves
    whatever icon the browser already cached for the origin in place, which is
    how a superseded icon keeps appearing long after the markup changed. It
    is a real ICO, not the SVG: Safari cannot draw an SVG here and shows a
    grey letter tile instead.
    """
    return FileResponse(HERE / "static" / "favicon.ico", media_type="image/x-icon")


@app.api_route("/apple-touch-icon.png", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/apple-touch-icon-precomposed.png", methods=["GET", "HEAD"], include_in_schema=False)
async def apple_touch_icon():
    """Safari and iOS probe these root paths whatever the markup says."""
    return FileResponse(HERE / "static" / "apple-touch-icon.png", media_type="image/png")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _context(request))


@app.get("/api/parts")
async def api_parts(url: str):
    """The address broken up, so the landing page can show it as you type.

    The split has to happen here rather than in the browser: telling
    `a.b.co.uk` apart from `a.b.example.com` needs the public suffix list, and
    a page that confidently boxed the wrong slice would be teaching the exact
    misreading this tool exists to correct. Pure string work over a cached
    list, so it costs nothing to call on every keystroke.

    Bounded like every other route that takes an address: unbounded, it was the
    one place a caller could hand the parser a megabyte of query string.
    """
    if len(url) > MAX_SUBMITTED_URL:
        return JSONResponse({"error": "too long"}, status_code=422)
    return JSONResponse(_url_parts(url))


_warm_started = threading.Event()


def _warm_models() -> None:
    """Load the fitted models while a check is still gathering its evidence.

    Nothing touched them until the first `/result`, so that request paid for
    importing scikit-learn and unpickling 44 MB of models while the page sat on
    "Preparing your result": 2.2 s against 0.18 s for every check after it, and
    more on a cold disk. Under `--reload` each edit starts a new worker and the
    first check paid again.

    Started from `/scan`, not at startup. Unpickling holds the GIL, and on a
    fresh Vercel instance the first request is nearly always the landing page:
    warmed at startup, that page stalled for up to a second behind the load.
    From `/scan` it overlaps the collectors instead, which spend their time
    waiting on the network. A check that reaches `/result` first waits on the
    loaders' lock rather than loading a second copy, and a failure here is only
    a missed head start -- the request path loads them again and reports it.
    """
    try:
        load_pipeline()
        load_base_pipeline()
        interval_mod.load()
    except Exception:  # noqa: BLE001 - a warm-up must never fail the page that started it
        _errors.warning("model warm-up failed; the first check will load them", exc_info=True)


def _warm_once() -> None:
    if not _warm_started.is_set():
        _warm_started.set()
        threading.Thread(target=_warm_models, name="model-warmup", daemon=True).start()


@app.get("/scan", response_class=HTMLResponse)
async def scanning(request: Request, url: str = "", render: bool = False, failed: bool = False):
    if problem := _input_problem(url):
        return _refuse_input(request, url, problem)
    _warm_once()
    render = _render_requested(url, render)
    return templates.TemplateResponse(
        request, "scanning.html",
        _context(request, url=url, parts=_url_parts(url),
                 collectors=COLLECTOR_ORDER, render=render, failed=failed),
    )


# Scans run on their own threads, not the event loop's default pool, which
# Starlette also uses for file responses and sync work -- a burst of slow scans
# there stalled every page. And each caller may have only a few running at
# once: the per-minute limit counts starts, not how many are still going.
_SCAN_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="scan")
_RUNNING: dict[str, int] = {}
_RUNNING_LOCK = threading.Lock()
MAX_CONCURRENT_SCANS = 3
TOO_MANY_RUNNING = "You already have several checks running. Wait for one to finish."


def _start_scan(caller: str) -> bool:
    with _RUNNING_LOCK:
        if _RUNNING.get(caller, 0) >= MAX_CONCURRENT_SCANS:
            return False
        _RUNNING[caller] = _RUNNING.get(caller, 0) + 1
        return True


def _end_scan(caller: str) -> None:
    with _RUNNING_LOCK:
        left = _RUNNING.get(caller, 1) - 1
        if left > 0:
            _RUNNING[caller] = left
        else:
            _RUNNING.pop(caller, None)


@app.get("/api/scan")
async def api_scan(request: Request, url: str = "", render: bool = False):
    """Server-sent events: one message per sub-collector as it lands.

    Always a live scan. A check from the front page is a question about the
    site *now*, and an answer from last week dressed as one is worse than a
    slow answer. What a previous check found is the browser's to keep, in
    its history, and it is opened from there as what it is: a saved result.
    """
    if problem := _input_problem(url):
        # Still a stream, so the progress page shows the reason rather than
        # the "connection lost" it would report for an error status.
        return _sse_error(problem)
    render = _render_requested(url, render)
    owner = _caller(request)

    async def stream():
        # Counted here, inside the stream, so the slot is released by the same
        # `finally` that ends it: a stream the client abandoned before it began
        # would otherwise hold its slot for good.
        if not _start_scan(owner):
            record_refusal("concurrency", owner, "/api/scan", f"{MAX_CONCURRENT_SCANS} running")
            yield _sse({"type": "error", "detail": TOO_MANY_RUNNING})
            return
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        SENTINEL = object()
        # Set when the visitor goes away. The scan stops at the next collector
        # boundary instead of running to the end for nobody.
        gone = threading.Event()

        def produce():
            """Runs on a worker thread; the collectors are blocking I/O."""
            events = scan_events(url, use_cache=False,
                                 render_mode=RENDER_FORCE if render else RENDER_AUTO)
            try:
                token = ""
                for kind, payload in events:
                    if gone.is_set():
                        return
                    if kind == "collector":
                        loop.call_soon_threadsafe(queue.put_nowait, {
                            "type": "collector",
                            "name": payload.name,
                            "status": payload.status,
                            "detail": payload.detail,
                            "elapsed": payload.elapsed_s,
                        })
                    elif kind == "bundle":
                        token = _stash(payload, owner)
                loop.call_soon_threadsafe(queue.put_nowait,
                                          {"type": "done", "url": url, "token": token})
            except HostScanRefused as exc:
                # Written for the operator to read, and says nothing internal.
                loop.call_soon_threadsafe(queue.put_nowait, {"type": "error", "detail": str(exc)})
            except Exception:  # noqa: BLE001
                # Anything else is a fault, and its text -- paths, internal
                # names -- is for the log, not the visitor.
                _errors.exception("scan failed")
                loop.call_soon_threadsafe(queue.put_nowait,
                                          {"type": "error", "detail": SCAN_FAILED})
            finally:
                events.close()
                loop.call_soon_threadsafe(queue.put_nowait, SENTINEL)

        # Kick the producer off and drain concurrently. Awaiting the executor
        # first would collect every event before emitting any of them, which
        # renders the whole progress view pointless — the user would watch a
        # blank list and then see it fill in all at once at the end.
        try:
            task = loop.run_in_executor(_SCAN_POOL, produce)
        except BaseException:
            _end_scan(owner)
            raise
        try:
            while True:
                event = await queue.get()
                if event is SENTINEL:
                    break
                yield _sse(event)
        finally:
            gone.set()
            try:
                await task
            finally:
                _end_scan(owner)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/result", response_class=HTMLResponse)
async def result(request: Request, url: str = "", t: str = "",
                 render: bool = False, feedback: bool = False, thanks: bool = False,
                 unsaved: bool = False, live: bool = False):
    """The verdict for a scan that just finished.

    `t` is the handoff token the progress stream issued. Without one this is
    a bookmark, a retyped address or a back button, and none of those is a
    request for an old answer: it goes through `/scan` and gets a fresh one,
    with the progress page in front of it. A token that misses costs one live
    scan here instead, never another redirect, so two processes disagreeing
    about who holds the bundle cannot bounce a visitor between the two pages.
    """
    if problem := _input_problem(url):
        return _refuse_input(request, url, problem)
    q = quote(url, safe="")
    # `live` is the progress page's <noscript> link: without scripts there is
    # no stream to hand over a token, and the check could never finish. It
    # takes the token-miss path below -- one charged, live scan, here.
    if not t and not live:
        return RedirectResponse(f"/scan?url={q}" + ("&render=true" if render else ""),
                                status_code=303)
    render_note = ""
    if render:
        allowed, why = _render_permitted(url)
        if not allowed:
            render, render_note = False, why

    handed = _take(t, url)
    if handed is None and _charge(request):
        return _refuse_input(request, url, TOO_MANY_CHECKS, status_code=429)
    # A live scan here -- the no-script path, or a token that missed -- counts
    # against the same per-caller limit as the progress stream's, which it
    # used to skip: twenty of them could run at once where the stream allows three.
    owner = _caller(request)
    if handed is None and not _start_scan(owner):
        record_refusal("concurrency", owner, "/result", f"{MAX_CONCURRENT_SCANS} running")
        return _refuse_input(request, url, TOO_MANY_RUNNING, status_code=429)
    try:
        if handed is not None:
            verdict = await asyncio.get_running_loop().run_in_executor(
                None, lambda: score_bundle(handed, url=url))
        else:
            try:
                verdict = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: score(url, use_cache=False,
                                  render_mode=RENDER_FORCE if render else RENDER_AUTO),
                )
            finally:
                _end_scan(owner)
    except Exception:  # noqa: BLE001 - e.g. HostScanRefused
        # The progress stream turns this into a readable in-page message; a
        # raw 500 here would not. Send it through that path instead -- except
        # when it was the evidence the stream just handed over that could not
        # be scored: a fresh scan would hand over more of the same, and the
        # two pages sent a visitor round in a loop, one full scan a lap, while
        # scoring kept failing. That lands on the stopped state instead.
        _errors.exception("scoring failed on /result")
        failed = "&failed=true" if handed is not None else ""
        return RedirectResponse(f"/scan?url={q}{failed}", status_code=303)
    bundle = verdict.bundle
    _remember(url, verdict)

    # Offer the JavaScript re-run only where it can help: the scan was
    # inconclusive and did not already execute scripts.
    try:
        js_used = bool(bundle.get("JS render").ok)
    except Exception:  # noqa: BLE001
        js_used = False
    can_rerun_js = bool(verdict.review and verdict.review.abstained) and not js_used

    low, high = verdict.interval_low, verdict.interval_high
    tone, tone_word = _tone(
        verdict.review.decision if verdict.review else "",
        verdict.probability, verdict.threshold)
    return templates.TemplateResponse(request, "result.html", _context(
        request,
        v=verdict,
        tone=tone,
        tone_word=tone_word,
        url=url,
        parts=_url_parts(url),
        destination_parts=_url_parts(verdict.final_url),
        render_note=render_note,
        can_rerun_js=can_rerun_js,
        pct=_clamp01(verdict.probability or 0) * 100,
        threshold_pct=verdict.threshold * 100,
        band_left=_clamp01(low) * 100 if low is not None else None,
        band_width=((_clamp01(high) - _clamp01(low)) * 100
                    if low is not None and high is not None else None),
        bundle_size_kb=bundle.size_bytes() // 1024,
        bundle_hash=bundle.url_hash[:8],
        from_cache=bundle.from_cache,
        feedback_open=feedback,
        feedback_thanks=thanks,
        feedback_unsaved=unsaved,
        report_token=("" if stateless() else
                      _park(_REPORTABLE, _REPORTABLE_TTL_S, _REPORTABLE_MAX,
                            _REPORTABLE_PER_CALLER, bundle, owner)),
        # Handed to the page so its own script can add this scan to the
        # browser's history list. The server keeps no copy. Passed as a dict,
        # not a JSON string: the template renders it with `tojson`, which
        # escapes `<` so an address containing `</script>` cannot close the
        # element it sits in.
        history_entry=_history_entry(url, verdict),
        **result_details(verdict, tone),
    ))


@app.get("/history", response_class=HTMLResponse)
async def history_view(request: Request, id: str = ""):
    """A result the browser saved, shown again exactly as it was.

    The server has no copy: the page's markup was filed in the visitor's own
    `localStorage` with the history entry, and this route is the frame it is
    put back into. Nothing is fetched, nothing is scored, and an entry that
    has been removed from the list is simply not there to show.
    """
    return templates.TemplateResponse(
        request, "history.html", _context(request, entry_id=id[:64]))


# HEAD as well as GET on the pages that only render: uptime monitors default
# to HEAD, and a 405 there reads as the site being down. Not on `/scan` or
# `/result`, where even a HEAD would start a scan. Registered as separate
# routes kept out of the schema, which would otherwise list each page twice
# under one operation ID.
app.add_api_route("/", index, methods=["HEAD"], include_in_schema=False)
app.add_api_route("/history", history_view, methods=["HEAD"], include_in_schema=False)


@app.post("/feedback")
async def submit_feedback(request: Request):
    """Log a disagreement against the cached evidence bundle.

    The bundle hash is stored alongside the label, so the example can be
    re-derived later without re-fetching a site that will almost certainly be
    gone by then.
    """
    if stateless():
        return PlainTextResponse("corrections are not collected on this instance", status_code=404)
    form = await _read_form(request)
    # Bounded before anything is done with it. The note already was; the URL
    # was not, and it is echoed straight back into a `Location` header on both
    # exits below -- so an unauthenticated caller could make this service emit
    # a response header of any size they liked, which a proxy in front of it
    # will reject with a 502 rather than pass on. It is also a column in the
    # feedback table, which a public instance lets anyone write to.
    #
    # 2000 characters is past any real URL and short of anything that causes
    # trouble; browsers have historically baulked around 2048.
    url = str(form.get("url", "")).strip()[:MAX_SUBMITTED_URL]
    kind = str(form.get("kind", "")).strip()[:40]
    note = str(form.get("note", "")).strip()[:500]

    if not url:
        return RedirectResponse("/", status_code=303)
    # Scoring below fetches the address on a cache miss, so it gets the same
    # refusal every scan route gives: no `javascript:`, no bare words.
    if problem := _input_problem(url):
        return _refuse_input(request, url, problem)
    q = quote(url, safe="")

    # The bundle the result page was showing, when it is still parked; a live
    # scan otherwise. Never the disk cache: that can hold a bundle from any
    # time at all, and the report must be about the verdict that was seen.
    shown = _collect_parked(_REPORTABLE, str(form.get("r", ""))[:64], url)
    try:
        if shown is not None:
            verdict = await asyncio.get_running_loop().run_in_executor(
                None, lambda: score_bundle(shown, url=url))
        else:
            verdict = await asyncio.get_running_loop().run_in_executor(
                None, lambda: score(url, use_cache=False))
    except Exception:  # noqa: BLE001 - as on /result: the progress page explains it
        _errors.exception("scoring failed on /feedback")
        failed = "&failed=true" if shown is not None else ""
        return RedirectResponse(f"/scan?url={q}{failed}", status_code=303)
    # The page this returns to needs the bundle the report was about; without
    # a token `/result` would start a fresh scan and lose the message.
    back = f"/result?url={q}&t={_stash(verdict.bundle, _caller(request))}"
    if kind not in FEEDBACK_KIND_IDS:
        return RedirectResponse(f"{back}&feedback=true#feedback", status_code=303)

    # A locked, read-only or full database used to end in the generic error
    # page, the report gone without a word about it. The result comes back
    # with the form still open and a line saying it was not saved.
    try:
        with store.connect() as conn:
            store.record_feedback(
                conn, url=url, url_hash=verdict.bundle.url_hash, kind=kind,
                submitted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                verdict_label=verdict.label, probability=verdict.probability,
                threshold=verdict.threshold,
                abstained=bool(verdict.review and verdict.review.abstained),
                note=note,
            )
    except (sqlite3.Error, OSError):
        _errors.exception("feedback could not be saved")
        return RedirectResponse(f"{back}&unsaved=true#feedback", status_code=303)
    return RedirectResponse(f"{back}&thanks=true#feedback", status_code=303)


@app.post("/submit")
async def submit(request: Request):
    form = await _read_form(request)
    # The dock posts "message", not "url": the field is a textarea with that
    # name so password managers stop treating a lone box plus a submit button
    # as a credential form. Both names are accepted so the rename cannot
    # silently break submission again.
    raw = str(form.get("url") or form.get("message") or "")
    # A textarea can carry newlines (Shift+Enter) and pasted URLs often bring
    # trailing whitespace. No URL contains whitespace, so strip all of it.
    #
    # Bounded for the same reason as /feedback: this value is echoed into a
    # `Location` header below, and an unbounded one makes this service emit a
    # response header no proxy will forward. `_input_problem` refuses anything
    # past MAX_SUBMITTED_URL, so nothing that long reaches the redirect.
    if len(raw) > MAX_PASTED:
        return _refuse_input(request, "", PASTED_TOO_LONG)
    url, problem = _one_address(raw)
    if problem:
        # What was pasted, not the joined string that could not be used.
        return _refuse_input(request, " ".join(raw.split()), problem)
    if not url:
        return RedirectResponse("/", status_code=303)
    if problem := _input_problem(url):
        return _refuse_input(request, url, problem)
    # No render option here by design. The first scan of a URL is always
    # script-free; rendering is offered on the result page, and only once that
    # scan has come back inconclusive.
    # Percent-encode. Interpolating raw meant a URL containing "&" was cut at
    # the first one - the query string swallowed the rest as separate params.
    q = quote(url, safe="")

    # Always the progress page, always a live scan. It used to skip straight
    # to a cached result, which answered "has anyone here scanned this?" for
    # any URL a stranger named, and showed a week-old verdict as if it were
    # today's. A previous result is the browser's, in its history.
    return RedirectResponse(f"/scan?url={q}", status_code=303)
