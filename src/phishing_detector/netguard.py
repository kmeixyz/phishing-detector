"""Refuse to fetch anything that is not a public internet address.

Every URL this scanner fetches is chosen by the party under investigation: the
submitted URL, each redirect target the host returns, and the icon its HTML
declares. Without a guard those choices reach the scanner's own loopback
interface, the private network around it, and the cloud metadata endpoint at
169.254.169.254 -- and the body comes back on the result page, so it is a read
primitive rather than a blind one.

The rule here is deliberately crude: resolve the hostname, and refuse if *any*
address it resolves to is not globally routable. A legitimate page to scan
never lives on a loopback or RFC1918 address, so nothing of value is lost.

Rebinding is covered, which it was not at first. `check_url` on its own
validates at check time while the client resolves again at connect time, and a
hostname whose DNS answer changes in between is checked as one address and
fetched at another. `PinnedTransport` closes that by making the check and the
connection one act: it resolves once, requires every answer to be public, and
sends the request to that address, keeping the name for the Host header and for
the TLS handshake. Callers that fetch anything the scanned party chose should
build their client with `guarded_client`.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import contextmanager

import httpcore
import httpx

from .urls import browser_join, parse


# How long to wait for a name to resolve before refusing it.
#
# `socket.getaddrinfo` is a blocking call into the system resolver and takes no
# timeout: `socket.setdefaulttimeout` does not touch it. So the wait is however
# long the resolver is willing to try, which on a typical configuration is
# seconds per nameserver and several attempts. The hostname is chosen by the
# party under investigation, and pointing it at a nameserver that accepts
# queries and never answers costs them nothing -- while it holds one of this
# service's four concurrent slots for the duration.
#
# Resolution therefore happens on a pool thread and the *wait* is bounded here.
# An abandoned lookup keeps running until the resolver gives up, which is why
# the pool has room for several: what matters is that the request stops waiting.
RESOLVE_TIMEOUT_S = 5.0
_RESOLVER = ThreadPoolExecutor(max_workers=16, thread_name_prefix="netguard-dns")

# Lookups still running, by hostname, and how many each registrable domain has
# *abandoned*. An abandoned lookup -- one nobody waited for past
# RESOLVE_TIMEOUT_S -- keeps its thread, so a domain whose nameserver never
# answers could fill every thread with random subdomains and leave no scan
# able to resolve anything. A name already being looked up shares that lookup,
# and a domain with several lookups stuck is refused new ones until they end.
# Only stuck lookups count: ordinary concurrent scans of one site, which
# resolve its names many times at once, must never be turned away.
_INFLIGHT: dict[str, object] = {}
_STALLED: dict[str, int] = {}
_INFLIGHT_LOCK = threading.Lock()
MAX_STALLED_PER_DOMAIN = 4


def _domain_of(hostname: str) -> str:
    return parse("https://" + hostname + "/").registrable or hostname


def _lookup(hostname: str):
    """A future for `getaddrinfo(hostname)`, shared with any lookup already running."""
    domain = _domain_of(hostname)
    with _INFLIGHT_LOCK:
        running = _INFLIGHT.get(hostname)
        if running is not None:
            return running
        if _STALLED.get(domain, 0) >= MAX_STALLED_PER_DOMAIN:
            raise BlockedAddress(f"{hostname} did not resolve: its domain's lookups are stalled")
        started: dict[str, float] = {}

        def run():
            started["at"] = time.monotonic()
            return socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)

        future = _RESOLVER.submit(run)
        future.stalled = False
        future.started = started
        _INFLIGHT[hostname] = future

    def done(_):
        with _INFLIGHT_LOCK:
            _INFLIGHT.pop(hostname, None)
            if future.stalled:
                left = _STALLED.get(domain, 1) - 1
                if left > 0:
                    _STALLED[domain] = left
                else:
                    _STALLED.pop(domain, None)
    future.add_done_callback(done)
    return future


def _await_lookup(future):
    """The lookup's answer, allowing RESOLVE_TIMEOUT_S from when it *started*.

    Timing from submission meant a name queued behind other scans' lookups was
    refused as "did not resolve" without ever being asked about. Queue time is
    still bounded -- three windows in all -- so a flooded resolver answers
    late rather than never.
    """
    begun = time.monotonic()
    cap = begun + 3 * RESOLVE_TIMEOUT_S
    while True:
        at = future.started.get("at")
        limit = min(cap, at + RESOLVE_TIMEOUT_S) if at is not None else cap
        left = limit - time.monotonic()
        if left <= 0:
            raise FutureTimeout()
        try:
            # Short waits while it is still queued, to notice when it starts.
            return future.result(timeout=left if at is not None else min(left, 0.1))
        except FutureTimeout:
            continue


def _mark_stalled(hostname: str, future) -> None:
    """Count a lookup its caller gave up on, once, until it finally ends."""
    with _INFLIGHT_LOCK:
        if future.done() or future.stalled:
            return
        future.stalled = True
        domain = _domain_of(hostname)
        _STALLED[domain] = _STALLED.get(domain, 0) + 1


class BlockedAddress(Exception):
    """A hostname resolved somewhere the scanner must not fetch."""


# Logged here rather than raised into the page, because the two audiences want
# opposite things. The caller gets a message that names no address -- they may
# be the one who chose the hostname, and telling them what it resolved to
# answers their question for them. The operator's log gets the address, because
# "someone aimed this at 169.254.169.254" is the whole signal.
_log = logging.getLogger("phishing_detector.refused")


# Ranges `ipaddress` is happy to call global but which do not belong to the
# public internet, and which therefore reach something the scanner should not
# be able to reach from wherever it is hosted.
_NOT_REALLY_PUBLIC = (
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT: the ISP's own subscribers
    ipaddress.ip_network("192.88.99.0/24"),   # deprecated 6to4 relay anycast
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("fec0::/10"),        # deprecated IPv6 site-local
    ipaddress.ip_network("2002::/16"),        # 6to4, which wraps any v4 address
)


# NAT64's well-known prefix (RFC 6052). On an IPv6-only network with DNS64 --
# mobile carriers, IPv6-only cloud subnets, this Mac on some Wi-Fi -- the
# resolver answers *only* with these, each wrapping the site's IPv4 address in
# its last 32 bits, and the translator connects to that. The prefix is
# "reserved", so every scan from such a host failed with "does not resolve
# to a public address". The wrapped address is what gets reached, so it is
# what is judged: 64:ff9b::7f00:1 is still 127.0.0.1. The operator-chosen
# local-use prefix 64:ff9b:1::/48 (RFC 8215) can place the address anywhere
# and stays refused.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for addresses that belong to the public internet."""
    if ip.version == 6 and ip in _NAT64:
        return _is_public(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if any(ip in net for net in _NOT_REALLY_PUBLIC if net.version == ip.version):
        return False
    # An IPv4 address smuggled in as ::ffff:127.0.0.1 is still loopback.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _is_public(mapped)
    return True


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """`_is_public`, for callers outside this module."""
    return _is_public(ip)


def resolve_public(hostname: str) -> list[str]:
    """Resolve `hostname`, returning its addresses.

    Raises BlockedAddress if the name does not resolve, or if any address it
    resolves to is not globally routable. Every address must pass: a name with
    one public and one loopback answer is a rebinding attempt, not a mixed
    result to average out.

    IPv4 addresses come first. The callers dial the first one, and sorting the
    strings put IPv6 ahead of any IPv4 whose first octet was 3 or more --
    `34.x` sorts after `2600:` -- so a dual-stack site on AWS or GCP was
    dialled at its IPv6 address from hosts with no IPv6 route at all, which is
    most containers and every serverless function. The fetch failed in a
    millisecond with "No route to host" and the scan quietly lost the page.
    """
    if not hostname:
        raise BlockedAddress("no hostname to resolve")

    try:
        pending = _lookup(hostname)
        infos = _await_lookup(pending)
    except FutureTimeout:
        # Only a lookup that ran and hung counts against its domain; one that
        # never left the queue says nothing about the domain.
        if pending.started.get("at") is not None:
            _mark_stalled(hostname, pending)
        _log.warning("refused kind=slow_dns caller=- path=- "
                     f"detail='{hostname} did not resolve in {RESOLVE_TIMEOUT_S:.0f}s'")
        raise BlockedAddress(
            f"{hostname} did not resolve within {RESOLVE_TIMEOUT_S:.0f}s") from None
    except (OSError, UnicodeError) as exc:
        # `gaierror` is the usual answer, but not the only one: in a Linux
        # container `getaddrinfo("data")` raised a bare OSError (EBUSY), and an
        # over-long IDNA label raises UnicodeError. Anything the resolver
        # throws means "no address this guard approved".
        raise BlockedAddress(f"{hostname} does not resolve: {exc}") from exc

    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in sorted({info[4][0] for info in infos}):
        try:
            parsed.append(ipaddress.ip_address(address))
        except ValueError as exc:
            raise BlockedAddress(f"{hostname} resolved to {address!r}") from exc
    if not parsed:
        raise BlockedAddress(f"{hostname} resolved to nothing")
    parsed.sort(key=lambda ip: (ip.version, ip.packed))
    addresses = [str(ip) for ip in parsed]

    for ip, address in zip(parsed, addresses):
        if not _is_public(ip):
            _log.warning(
                "refused kind=blocked_address caller=- path=- "
                f"detail='{hostname} -> {address}'")
            # Deliberately not naming the address in the exception. That message
            # reaches the result page, and the person reading it may be the
            # person who chose the hostname -- reporting *which* internal
            # address it resolved to answers a question they should have to
            # answer themselves. The log above keeps it for the operator.
            raise BlockedAddress(f"{hostname} does not resolve to a public address")
    return addresses


def check_url(url: str) -> list[str]:
    """Raise BlockedAddress unless `url` is http(s) on a public address.

    The hostname checked here is `ascii_hostname`, the same IDNA2008 form the
    HTTP client will connect to. Resolving `p.hostname` instead sent the
    unicode string through `getaddrinfo`, which applies IDNA2003: `faß.example`
    was checked as `fass.example` and fetched as `xn--fa-hia.example`. An
    attacker who registers both points the checked name at a public address and
    the fetched one at 127.0.0.1, and the guard approves a request it never saw.
    """
    p = parse(url)
    if p.scheme not in ("http", "https"):
        raise BlockedAddress(f"refusing non-HTTP scheme: {p.scheme!r}")
    return resolve_public(p.ascii_hostname)


def is_public_url(url: str) -> bool:
    """check_url as a predicate, for callers that only want to skip."""
    try:
        check_url(url)
    except BlockedAddress:
        return False
    return True


def _time_left(deadline: float, timeout: float | None, error: type[Exception]) -> float:
    """`timeout`, cut to what is left before `deadline`; `error` once none is."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise error("the fetch ran past its deadline")
    return left if timeout is None else min(timeout, left)


class _DeadlineStream(httpcore.NetworkStream):
    """A socket whose every read and write shares one wall-clock deadline.

    httpx's timeouts are per operation: a read timeout of 15 s means 15 s
    without a byte, so a server that sends one byte every 14 s is never timed
    out -- through the headers, the TLS handshake or the body alike. The party
    choosing that pace is the party under investigation, and the thread it
    holds outlives the scan that started it. Each operation here gets whatever
    is left of the deadline at most, and none starts once it has passed.
    """

    def __init__(self, inner: httpcore.NetworkStream, deadline: float):
        self._inner = inner
        self._deadline = deadline

    def _left(self, timeout: float | None, error: type[Exception]) -> float:
        return _time_left(self._deadline, timeout, error)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, self._left(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, self._left(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        inner = self._inner.start_tls(ssl_context, server_hostname,
                                      self._left(timeout, httpcore.ConnectTimeout))
        return _DeadlineStream(inner, self._deadline)

    def get_extra_info(self, info: str):
        return self._inner.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self, deadline: float):
        self._inner = httpcore.SyncBackend()
        self._deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        timeout = _time_left(self._deadline, timeout, httpcore.ConnectTimeout)
        stream = self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return _DeadlineStream(stream, self._deadline)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("unix sockets are never dialled")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class PinnedTransport(httpx.HTTPTransport):
    """Connect only to an address this guard resolved and approved.

    `check_url` validates at check time and the client resolves again when it
    connects, so a hostname whose DNS answer changes between the two is checked
    as one address and fetched at another. That is DNS rebinding, and against a
    scanner it is not exotic: the party choosing the hostname is the party under
    investigation, and a 30-second TTL is enough.

    This closes it by making the check and the connection the same act. The
    hostname is resolved once, here, at the moment of connecting; every address
    it returns must be public; and the request is then sent to that address
    rather than to the name, so there is no second lookup to poison.

    The name is preserved where it still matters. The `Host` header keeps it, so
    virtual hosts serve the right site, and `sni_hostname` keeps it in the TLS
    handshake, so a verified connection is still verified against the hostname
    and not against the address it happens to live on.

    With `deadline_s`, every socket this transport opens shares one wall-clock
    deadline counted from its creation (see `_DeadlineStream`).
    """

    def __init__(self, *args, deadline_s: float | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if deadline_s is not None:
            # httpx does not expose the backend, so it is set on the pool it
            # built. `test_security_round_4` fails loudly if an upgrade moves it.
            self._pool._network_backend = _DeadlineBackend(time.monotonic() + deadline_s)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # `raw_host`, not `host`. httpx's `.host` gives the IDNA-*decoded* name,
        # so resolving it puts the unicode form through `getaddrinfo`, which
        # applies IDNA2003 -- `xn--fa-hia.example` would be dialled at
        # `fass.example`'s address, a different registrable domain. That is the
        # exact divergence this project fixed in `urls.idna_ascii`, reintroduced
        # by reading the convenient attribute. `raw_host` is the ASCII form
        # httpx itself puts on the wire.
        host = request.url.raw_host.decode("ascii")
        addresses = resolve_public(host)
        # This scanner never logs in anywhere. A pasted address with a
        # `user:password@` part became an `Authorization: Basic` header --
        # httpx builds one from the URL -- so the visitor's credentials went to
        # the very site being checked, which may be the one phishing for them.
        request.headers.pop("authorization", None)
        if request.url.userinfo:
            request.url = request.url.copy_with(username=None, password=None)

        try:
            ipaddress.ip_address(host.strip("[]"))
            return super().handle_request(request)   # already an address
        except ValueError:
            pass

        original = request.url
        request.extensions = {**request.extensions, "sni_hostname": host}
        request.headers["Host"] = original.netloc.decode("ascii")
        try:
            # Every address here passed the public check, so any of them may
            # be dialled. Fall through to the next only when this host could
            # not reach the one before -- an unroutable family, a dead
            # anycast node -- and let every other failure surface as is.
            failure: Exception | None = None
            for address in addresses:
                request.url = original.copy_with(host=address)
                try:
                    return super().handle_request(request)
                except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                    failure = exc
            raise failure  # type: ignore[misc]  # addresses is never empty
        finally:
            # Put the name back before anything downstream reads it. The client
            # attaches this request to the response, so `Response.url` is this
            # object -- and `guarded_stream` joins a relative `Location` against
            # it. Left rewritten, hop two would be requested at the pinned
            # address with the wrong Host, and `final_url` would name an IP
            # instead of the site the verdict is about.
            request.url = original


def guarded_client(*, deadline_s: float | None = None, **kwargs) -> httpx.Client:
    """An httpx client that cannot be talked into reaching a private address.

    Every caller that fetches something the scanned party chose should build its
    client here rather than with `httpx.Client` directly, and should pass
    `deadline_s`: the per-operation timeouts alone let the scanned server set
    how long the fetch takes.
    """
    kwargs.setdefault("follow_redirects", False)
    verify = kwargs.pop("verify", True)
    transport = PinnedTransport(verify=verify, deadline_s=deadline_s)
    return httpx.Client(transport=transport, **kwargs)


@contextmanager
def guarded_stream(client: httpx.Client, url: str, max_redirects: int = 5):
    """Stream `url`, checking the address of every hop, redirects included.

    Checking the submitted URL and then handing it to a client with
    `follow_redirects=True` guards nothing: the check passes on a public
    address and the client then follows a 302 to wherever the same attacker
    points it. This follows the chain by hand so each hop is checked before it
    is requested, the same way `http_chain` records its chain.

    The client passed in MUST have `follow_redirects=False`, or the redirects
    happen inside `client.stream` where this cannot see them.
    """
    if client.follow_redirects:
        raise ValueError("guarded_stream requires a client with follow_redirects=False")

    current = url
    for _ in range(max_redirects + 1):
        check_url(current)
        with client.stream("GET", current) as response:
            location = response.headers.get("location", "")
            if response.is_redirect and location:
                # Joined as a browser joins it; see `urls.browser_join`.
                current = browser_join(str(response.url), location)
                if not current:
                    raise BlockedAddress("redirected to something that is not a web address")
                continue
            yield response
            return
    raise BlockedAddress(f"redirect cap reached after {max_redirects} hops")
