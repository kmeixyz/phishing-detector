"""Optional JS rendering for client-side phishing kits.

WHY THIS EXISTS

A growing share of kits ship an empty <body> and build the whole credential
form from JavaScript after load. To the plain fetch collector those pages look
like nothing at all: no password field, no forms, no assets — every content
feature reads as innocent for reasons that have nothing to do with safety. The
static collector already flags the shape of that (`render_empty`), but cannot
see inside it.

WHY IT IS OFF BY DEFAULT

Rendering means executing attacker-controlled code. Every other collector in
this project refuses to do that, and turning it on genuinely widens the attack
surface — especially outside a container. So it is gated twice: the
environment must set PHISHING_DETECTOR_ALLOW_JS=1, *and* the caller must ask for it.
Neither alone is enough.

WHAT IS LOCKED DOWN

  * headless, fresh incognito context per scan, disposed afterwards
  * downloads refused at the context level; an attempted download is recorded
    as evidence rather than followed
  * navigation confined to http/https — file:, blob: and friends are aborted
  * Chromium reaches the network only through `_GuardedProxy`, a forward
    proxy on loopback that resolves each host once with `netguard`, refuses
    any non-public answer and dials the address it approved. A check in the
    request route alone guarded only the first hop -- Playwright does not
    route the hops of a redirect, so a public page answering 302 to
    169.254.169.254 was followed and the internal body rendered as evidence --
    and Chromium's own DNS lookup could answer differently from the check's
    (rebinding). Through the proxy, every hop and every lookup is the guard's
  * every permission denied; no geolocation, camera, mic, clipboard, notifications
  * dialogs auto-dismissed, because alert() would otherwise hang the page
  * popups closed immediately
  * on the host, the Chromium sandbox is ON and required — it is the only
    boundary there, and a render that cannot start it fails rather than
    proceeding without it. Inside the container it is OFF because it cannot
    start under `cap_drop: ALL`, and the container is the boundary instead
  * the DOM is truncated inside the browser before it is transferred
  * nothing is typed, filled, clicked or submitted — the page is read, never driven

The byte cap counts every byte the proxy receives for the page, across all of
its requests, and cuts the connection that crosses it, so neither one large
response nor many small ones gets past it. The DOM truncation above bounds
what is transferred back.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from urllib.parse import urlsplit

from ..config import ENVELOPE, containerised, javascript_permitted
from ..netguard import BlockedAddress, check_url, resolve_public
from ..urls import parse, without_credentials
from .base import FAILED, SKIPPED, TIMEOUT, CollectorResult, timed

_BLOCKED_SCHEMES = ("file:", "blob:", "data:text/html", "chrome:", "devtools:")
_REFUSED = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
_MAX_HEAD = 64 * 1024


class _GuardedProxy:
    """The only way the rendering browser reaches the network.

    A forward proxy on an ephemeral loopback port, for one render. For each
    connection it reads the request head, resolves the host with
    `netguard.resolve_public` -- which refuses the lot if any answer is not
    public -- and dials the address it approved, so there is no second lookup
    for a rebinding name to answer. HTTPS arrives as CONNECT and is tunnelled
    as is: Chromium still does TLS end to end and checks the certificate
    against the name. Plain HTTP is forwarded with `Connection: close`; a
    server that keeps the connection open anyway only ever receives requests
    for its own host and port over it, because Chromium opens a new proxy
    connection for any other.

    Every connection shares the render's wall-clock deadline and byte cap.
    """

    def __init__(self, deadline: float, cap: int, blocked: list[str]):
        self._deadline, self._cap, self._blocked = deadline, cap, blocked
        self.bytes = 0
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._server = socket.create_server(("127.0.0.1", 0))
        self.port = self._server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True, name="render-proxy").start()

    def close(self) -> None:
        self._server.close()
        with self._lock:
            open_now, self._sockets = list(self._sockets), set()
        for sock in open_now:
            sock.close()

    def _left(self) -> float:
        return self._deadline - time.monotonic()

    def _track(self, sock: socket.socket) -> socket.socket:
        with self._lock:
            self._sockets.add(sock)
        return sock

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                return   # closed: the render is over
            threading.Thread(target=self._serve, args=(self._track(client),), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(max(self._left(), 0.1))
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk or len(head) + len(chunk) > _MAX_HEAD:
                    return
                head += chunk
            head, _, rest = head.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            try:
                method, target, version = lines[0].decode("latin-1").split(" ", 2)
                if method == "CONNECT":
                    host, _, port_text = target.rpartition(":")
                    port, first = int(port_text), b""
                else:
                    parts = urlsplit(target)
                    if parts.scheme != "http" or not parts.hostname:
                        client.sendall(_BAD_REQUEST)
                        return
                    host, port = parts.hostname, parts.port or 80
                    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                    headers = [line for line in lines[1:] if not line.lower().startswith(
                        (b"proxy-", b"connection:", b"keep-alive:"))]
                    first = b"\r\n".join([f"{method} {path} {version}".encode("latin-1"),
                                           *headers, b"Connection: close", b"", b""]) + rest
            except ValueError:
                client.sendall(_BAD_REQUEST)
                return
            host = host.strip("[]")
            try:
                addresses = resolve_public(host)
            except BlockedAddress:
                self._blocked.append(f"non-public address: {host[:60]}")
                client.sendall(_REFUSED)
                return
            for address in addresses:
                try:
                    upstream = self._track(socket.create_connection(
                        (address, port), timeout=max(self._left(), 0.1)))
                    break
                except OSError:
                    continue
            else:
                return
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                upstream.sendall(first)
            self._pipe(client, upstream)
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    sock.close()

    def _pipe(self, client: socket.socket, upstream: socket.socket) -> None:
        peers = {client: upstream, upstream: client}
        while (left := self._left()) > 0:
            ready, _, _ = select.select(list(peers), [], [], left)
            if not ready:
                return
            for sock in ready:
                data = sock.recv(65536)
                if not data:
                    return
                if sock is upstream:
                    with self._lock:
                        self.bytes += len(data)
                        over = self.bytes > self._cap
                    if over:
                        self._blocked.append("size cap reached")
                        return
                peers[sock].settimeout(max(self._left(), 0.1))
                peers[sock].sendall(data)


def available() -> tuple[bool, str]:
    """(usable, why not). Kept separate so the interface can explain itself."""
    if not javascript_permitted():
        return False, "PHISHING_DETECTOR_ALLOW_JS is not set"
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, "playwright is not installed"
    return True, ""


def collect(url: str) -> CollectorResult:
    res = CollectorResult(name="JS render")
    with timed(res):
        ok, why = available()
        if not ok:
            res.status = SKIPPED
            res.detail = why
            return res

        p = parse(url)
        if p.scheme not in ("http", "https"):
            res.status = SKIPPED
            res.detail = "not an HTTP URL"
            return res

        # Chromium resolves and connects on its own, so nothing the HTTP
        # collector checked carries over to it. Without this the one collector
        # that executes attacker code was also the one collector that would
        # fetch any address the page named.
        try:
            check_url(url)
        except BlockedAddress as exc:
            res.status = SKIPPED
            res.detail = f"refusing to render: {exc}"
            return res

        from playwright.sync_api import Error as PWError
        from playwright.sync_api import TimeoutError as PWTimeout
        from playwright.sync_api import sync_playwright

        budget = int(ENVELOPE.render_timeout_s * 1000)
        cap = ENVELOPE.max_response_bytes
        blocked: list[str] = []
        dialogs: list[str] = []
        downloads: list[str] = []
        request_hosts: set[str] = set()

        # One deadline for every connection the render opens, so a slow server
        # cannot stretch it past its budget.
        proxy = _GuardedProxy(
            time.monotonic() + ENVELOPE.render_timeout_s + ENVELOPE.render_settle_ms / 1000 + 5,
            cap, blocked)
        try:
            with sync_playwright() as pw:
                # Which boundary is doing the work decides this, and the two
                # deployments have different answers.
                #
                # On the host there is no other boundary: Chromium's own sandbox
                # is the only thing between a scanned page and the machine, so it
                # is required, and rendering fails loudly if it cannot start.
                #
                # Inside the container it cannot start at all. `cap_drop: ALL`
                # plus `no-new-privileges` leaves no usable namespace sandbox,
                # and Chromium aborts with "No usable sandbox!" -- verified by
                # running it, which is how this was found. Restoring it would
                # mean granting SYS_ADMIN back, weakening the boundary that
                # protects the *host* in order to strengthen one that protects a
                # disposable container from a page. That is the wrong trade, so
                # the container runs unsandboxed on purpose and the container is
                # the boundary.
                #
                # The original defect here was never that the sandbox was off.
                # It was that the docstring, an inline comment, the README and
                # the operator banner all said it was on. Saying which boundary
                # applies, in each mode, is the actual fix.
                sandboxed = not containerised()
                browser = pw.chromium.launch(
                    headless=True,
                    chromium_sandbox=sandboxed,
                    # --disable-dev-shm-usage only avoids the small /dev/shm in
                    # containers; it has nothing to do with the sandbox.
                    args=["--disable-dev-shm-usage", "--disable-background-networking",
                          "--no-first-run", "--no-default-browser-check",
                          # WebRTC talks UDP to whatever ICE candidates the
                          # page supplies, outside any route below.
                          "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                          "--dns-prefetch-disable"],
                    # Everything, loopback included, goes through the proxy.
                    # Chromium skips the proxy for loopback unless told not to.
                    proxy={"server": f"http://127.0.0.1:{proxy.port}", "bypass": "<-loopback>"},
                )
                try:
                    context = browser.new_context(
                        accept_downloads=False,
                        java_script_enabled=True,
                        user_agent=ENVELOPE.user_agent,
                        permissions=[],           # deny everything
                        bypass_csp=False,
                        service_workers="block",
                        viewport={"width": 1280, "height": 900},
                    )
                    context.set_default_timeout(budget)
                    context.set_default_navigation_timeout(budget)

                    # Dialogs would block the page forever in headless mode.
                    context.on("dialog", lambda d: (dialogs.append(d.type), d.dismiss()))

                    def route(route_obj, request):
                        target = request.url
                        if target.startswith(_BLOCKED_SCHEMES):
                            blocked.append(target[:80])
                            return route_obj.abort()
                        if proxy.bytes >= cap:
                            blocked.append("size cap reached")
                            return route_obj.abort()
                        # Where it may go is the proxy's call; see _GuardedProxy.
                        try:
                            request_hosts.add(parse(target).registrable)
                        except Exception:  # noqa: BLE001
                            pass
                        return route_obj.continue_()

                    context.route("**/*", route)
                    # `route` never sees a WebSocket: the handshake went straight
                    # to the network, and a rendered page reached a server on
                    # 127.0.0.1 that every fetch, image and beacon to it had been
                    # refused. A render needs the page's DOM, not its sockets:
                    # a route that never calls `connect_to_server()` is answered
                    # by Playwright itself, so no socket reaches the network.
                    # (Not `ws.close()` -- the sync API deadlocks waiting on the
                    # browser from inside its own callback.) WebRTC and
                    # WebTransport are removed for the same reason: no route
                    # covers them either.
                    context.route_web_socket("**/*", lambda ws: None)
                    context.add_init_script(
                        "for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', "
                        "'RTCDataChannel', 'WebTransport']) { try { delete window[k]; } catch (e) {} "
                        "try { Object.defineProperty(window, k, {value: undefined}); } catch (e) {} }")

                    page = context.new_page()
                    # A kit that opens a popup does not get one. This must be
                    # the page-level "popup" event, not the context-level
                    # "page" event: the latter also fires for the page created
                    # here, which closed it out from under the navigation.
                    page.on("popup", lambda pg: pg.close())
                    page.on("download", lambda d: downloads.append(d.suggested_filename))

                    try:
                        # Without any `user:password@`: see PinnedTransport.
                        page.goto(without_credentials(url), wait_until="domcontentloaded",
                                  timeout=budget)
                    except PWTimeout:
                        res.status = TIMEOUT
                        res.detail = f"navigation exceeded {ENVELOPE.render_timeout_s:.0f}s"
                        return res

                    # Let client-side rendering settle, then stop. No clicking,
                    # no typing, no scrolling into lazy-loaded traps.
                    try:
                        page.wait_for_timeout(ENVELOPE.render_settle_ms)
                    except PWError:
                        pass

                    # Truncate inside the browser, not after. `page.content()`
                    # serialises the whole DOM and ships it over the driver
                    # channel into this process, so a JS-built multi-gigabyte
                    # document exhausts the scanner before any Python-side
                    # slice runs. Chromium has its own memory ceiling; this
                    # keeps the transfer bounded by our cap instead.
                    try:
                        html = page.evaluate(
                            "(cap) => document.documentElement.outerHTML.slice(0, cap)",
                            cap,
                        )
                    except PWError:
                        html = ""
                    final_url = page.url
                    title = (page.title() or "")[:200]

                    # Cheap post-render structure, read straight from the DOM.
                    counts = page.evaluate(
                        """() => ({
                            passwords: document.querySelectorAll('input[type=password]').length,
                            inputs: document.querySelectorAll('input').length,
                            forms: document.querySelectorAll('form').length,
                            iframes: document.querySelectorAll('iframe').length,
                            text: (document.body ? document.body.innerText.length : 0)
                        })"""
                    )

                    res.data = {
                        "html": html[:cap],
                        "final_url": final_url,
                        "title": title,
                        "rendered_password_inputs": counts.get("passwords", 0),
                        "rendered_input_count": counts.get("inputs", 0),
                        "rendered_form_count": counts.get("forms", 0),
                        "rendered_iframe_count": counts.get("iframes", 0),
                        "rendered_text_length": counts.get("text", 0),
                        "js_redirected": parse(final_url).registrable != p.registrable,
                        "third_party_hosts": sorted(h for h in request_hosts if h and h != p.registrable),
                        "dialogs_dismissed": dialogs,
                        "downloads_blocked": downloads,
                        "requests_blocked": blocked[:10],
                        "bytes_seen": proxy.bytes,
                    }
                    res.detail = (
                        f"{counts.get('text', 0)} chars text, "
                        f"{counts.get('passwords', 0)} password field(s), "
                        f"{len(res.data['third_party_hosts'])} third-party host(s)"
                    )
                    if downloads:
                        res.detail += f", {len(downloads)} download blocked"
                finally:
                    browser.close()
        except PWError as exc:
            res.status = FAILED
            res.detail = f"render failed: {str(exc).splitlines()[0][:120]}"
        except Exception as exc:  # noqa: BLE001
            res.status = FAILED
            res.detail = f"{type(exc).__name__}: {exc}"
        finally:
            proxy.close()
    return res


def warning_banner() -> str:
    """What the interface shows while rendering is enabled.

    The container and host cases get different text. Saying "running inside a
    container ... but this still runs attacker-controlled code on this machine"
    was both alarming and self-contradictory: inside a container that code is
    exactly what the container is for.
    """
    if not javascript_permitted():
        return ""
    if containerised():
        return (
            "Pages are executed headless inside the container, with downloads, "
            "dialogs, popups and non-HTTP navigation blocked, and nothing is ever "
            "typed or submitted. Execution is confined to the container and its "
            "evidence volume, and does not touch the host filesystem. The "
            "container is the boundary here: Chromium's own sandbox cannot start "
            "with capabilities dropped, so the container's restrictions do that "
            "job instead."
        )
    return (
        "Running OUTSIDE a container. Pages are executed headless with downloads, "
        "dialogs, popups and non-HTTP navigation blocked, nothing is ever typed "
        "or submitted, and Chromium's own sandbox is required -- it is the only "
        "boundary here, so a render that cannot start it fails instead of "
        "proceeding. Even so, this runs attacker-controlled code directly on "
        "this machine and stores the fetched page on its filesystem. Unset "
        "PHISHING_DETECTOR_ALLOW_JS to disable rendering."
    )
