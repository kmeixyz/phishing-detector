"""HTTP evidence. This is the hostile-input boundary.

What this does: issues GET requests, follows redirects by hand so the chain
can be recorded, and reads at most 2 MB of the final response body.

What this deliberately never does:

  * execute anything — no JavaScript engine is involved at any point
  * submit a form, or supply credentials real or fake
  * follow a redirect to a non-HTTP scheme, or into a download
  * request any URL other than the one submitted and the hops it returns
  * retry aggressively, brute-force paths, or probe beyond the given URL

Certificate verification is off for the fetch specifically because phishing
hosts frequently have broken chains and the page still needs to be read. That
makes the bytes unauthenticated, so `tls_verified` is recorded on the result:
anything consuming this evidence -- the rule engine, and the batch scripts that
write training rows -- can then see that an on-path attacker could have chosen
it. Whether the certificate *would* verify is recorded separately and honestly
by the TLS collector, which is where that fact belongs.

The submitted URL and every redirect target are checked against `netguard`
before they are fetched: the host under investigation chooses those addresses,
and without the check it can point them at this machine's own loopback
interface or its private network.

The client is `netguard.guarded_client`, which resolves the hostname itself at
connect time and sends the request to the address it approved. Checking a name
and then handing it to a client that looks it up again is a check with a hole
in it -- the answer can change in between, and the party choosing the name is
the party under investigation.
"""

from __future__ import annotations

import codecs
import re
from time import monotonic

import httpx

from ..config import ENVELOPE
from ..netguard import BlockedAddress, check_url, guarded_client
from ..urls import browser_join, https_upgrade, parse
from .base import FAILED, CollectorResult, read_capped, timed

# Content that is a file to save rather than a page to read. The collector
# stops at the headers for these — it records that the URL serves a download
# and never pulls the bytes.
_DOWNLOAD_TYPES = (
    "application/octet-stream", "application/zip", "application/x-msdownload",
    "application/vnd.microsoft.portable-executable", "application/x-msi",
    "application/x-apple-diskimage", "application/java-archive",
    "application/x-rar", "application/x-7z-compressed", "application/gzip",
    "application/x-tar", "application/pdf",
)


# Bot-mitigation vendors, by the markers their interstitials carry. Matched
# only on a refusal status: sites embed these vendors' tags on ordinary pages
# too, and a 200 that merely loads DataDome's script is the page, not a wall.
_CHALLENGE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("DataDome", ("datadome", "dd={'rt'", "ads-dd-captcha")),
    ("Cloudflare", ("cf-browser-verification", "challenge-platform", "_cf_chl_opt",
                    "just a moment...", "cf_chl_")),
    ("Akamai", ("errors.edgesuite.net", "akamai", "reference&#32;#", "reference #")),
    ("HUMAN/PerimeterX", ("_pxappid", "px-captcha", "perimeterx", "human challenge")),
    ("Imperva", ("_incapsula_resource", "incapsula incident", "imperva")),
    ("Kasada", ("kasada", "kpsdk")),
)
_CHALLENGE_STATUSES = frozenset({401, 403, 405, 406, 429, 503})


def _blocked_by(status: int | None, headers: httpx.Headers, body: str) -> str:
    """Who refused to serve the page, or "" when the response is the page.

    A bot-detection interstitial is not the site: scoring its markup reported
    "no password field, one form, nothing suspicious" about paypal.com's
    sign-in page, which the scanner had never seen. The refusal is recorded as
    what it is so content features can be marked absent rather than describing
    a CAPTCHA wall. Kits block scanners too, so this is a fact about the
    response, not a clearance.
    """
    # A server error is the server failing to produce a page: there is nothing
    # to judge, and scoring its error page called a failing site "an ordinary
    # website". A 404 is different -- the site answered, about a page that is
    # not there -- and stays content.
    if status is not None and status >= 500 and status not in _CHALLENGE_STATUSES:
        return f"HTTP {status}"
    if status not in _CHALLENGE_STATUSES:
        return ""
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare"
    if "x-datadome" in headers or "x-dd-b" in headers:
        return "DataDome"
    if headers.get("server", "").lower().startswith("akamaighost"):
        return "Akamai"
    low = body[:65536].lower()
    for vendor, markers in _CHALLENGE_MARKERS:
        if any(m in low for m in markers):
            return vendor
    return f"HTTP {status}"


def _is_download(headers: httpx.Headers) -> tuple[bool, str]:
    disposition = headers.get("content-disposition", "").lower()
    if "attachment" in disposition:
        return True, "content-disposition: attachment"
    ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype in _DOWNLOAD_TYPES:
        return True, f"content-type: {ctype}"
    return False, ""


# Encoding labels a browser honours, from the WHATWG Encoding standard, mapped
# to the codec that decodes them the way a browser does. A label that is not
# here is ignored by browsers -- and must be ignored here too, because Python
# knows many that browsers do not: a page served as `charset=cp037` renders
# normally for its victim and decoded here as EBCDIC it read as noise, with no
# password field, no form and no inputs, recorded as present and benign.
_WEB_ENCODINGS: dict[str, str] = {}
for _codec, _labels in (
    ("utf-8", "utf-8 utf8 unicode-1-1-utf-8 unicode11utf8 unicode20utf8 x-unicode20utf8"),
    ("cp1252", "windows-1252 cp1252 x-cp1252 latin1 l1 iso-8859-1 iso8859-1 iso88591 "
               "iso_8859-1 iso_8859-1:1987 iso-ir-100 ibm819 cp819 csisolatin1 "
               "ascii us-ascii ansi_x3.4-1968"),
    ("iso8859-2", "iso-8859-2 iso8859-2 latin2 l2 csisolatin2"),
    ("iso8859-4", "iso-8859-4 iso8859-4 latin4 l4"),
    ("iso8859-5", "iso-8859-5 iso8859-5 cyrillic csisolatincyrillic"),
    ("iso8859-6", "iso-8859-6 iso8859-6 arabic"),
    ("iso8859-7", "iso-8859-7 iso8859-7 greek greek8"),
    ("iso8859-8", "iso-8859-8 iso8859-8 hebrew visual iso-8859-8-i logical"),
    ("iso8859-13", "iso-8859-13 iso8859-13"),
    ("iso8859-15", "iso-8859-15 iso8859-15 latin9 l9"),
    ("cp1250", "windows-1250 cp1250 x-cp1250"),
    ("cp1251", "windows-1251 cp1251 x-cp1251"),
    ("cp1253", "windows-1253 cp1253"),
    ("cp1254", "windows-1254 cp1254 iso-8859-9 iso8859-9 latin5 l5"),
    ("cp1255", "windows-1255 cp1255"),
    ("cp1256", "windows-1256 cp1256"),
    ("cp1257", "windows-1257 cp1257"),
    ("cp1258", "windows-1258 cp1258"),
    ("cp874", "windows-874 tis-620 iso-8859-11 dos-874"),
    ("koi8-r", "koi8-r koi8_r koi8 cskoi8r"),
    ("koi8-u", "koi8-u koi8-ru"),
    ("cp866", "ibm866 866 cp866 csibm866"),
    ("mac-roman", "macintosh mac x-mac-roman csmacintosh"),
    ("shift_jis", "shift_jis shift-jis sjis ms_kanji ms932 windows-31j x-sjis csshiftjis"),
    ("euc_jp", "euc-jp x-euc-jp cseucpkdfmtjapanese"),
    ("iso2022_jp", "iso-2022-jp csiso2022jp"),
    ("cp949", "euc-kr ks_c_5601-1987 ks_c_5601-1989 ksc5601 korean windows-949 cseuckr"),
    ("gbk", "gbk gb2312 gb_2312 gb_2312-80 chinese x-gbk csgb2312 iso-ir-58"),
    ("gb18030", "gb18030"),
    ("big5hkscs", "big5 big5-hkscs cn-big5 x-x-big5 csbig5"),
    ("utf-16-le", "utf-16le utf-16 ucs-2 unicode unicodefeff iso-10646-ucs-2 csunicode"),
    ("utf-16-be", "utf-16be unicodefffe"),
):
    for _label in _labels.split():
        _WEB_ENCODINGS[_label] = _codec

_META_CHARSET = re.compile(rb"""<meta[^>]*?charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.I)


def _web_encoding(label: str | None) -> str | None:
    return _WEB_ENCODINGS.get((label or "").strip().strip("\"'").lower())


def decode_html(raw: bytes, content_type: str) -> str:
    """Decode a page the way a browser picks its encoding.

    A byte-order mark wins, then a charset label from the header that browsers
    recognise, then one from a `<meta>` near the top, then UTF-8. The BOM
    coming first matters as much as the label list: a page served as
    `charset=utf-16le` that starts with a UTF-8 BOM is UTF-8 to a browser.
    """
    for bom, codec in ((codecs.BOM_UTF8, "utf-8"), (codecs.BOM_UTF16_LE, "utf-16-le"),
                       (codecs.BOM_UTF16_BE, "utf-16-be")):
        if raw.startswith(bom):
            return raw[len(bom):].decode(codec, "replace")
    header = ""
    for param in content_type.split(";")[1:]:
        key, _, value = param.partition("=")
        if key.strip().lower() == "charset":
            header = value
    codec = _web_encoding(header)
    if codec is None:
        found = _META_CHARSET.search(raw[:1024])
        codec = _web_encoding(found.group(1).decode("ascii", "replace")) if found else None
        # A <meta> can only be read if the page is ASCII-compatible, so a
        # browser treats one naming UTF-16 as UTF-8.
        if codec and codec.startswith("utf-16"):
            codec = "utf-8"
    return raw.decode(codec or "utf-8", "replace")


def is_bare(url: str) -> bool:
    """Whether the address was given without a scheme, leaving it to us."""
    return "://" not in (url or "").strip()


# Hop-zero failures that mean "HTTPS is not really there", the case where a
# browser given a bare name tries plain http instead: nothing listening, no
# TLS, or -- neverssl.com -- a TLS socket that hangs up without answering.
# A read timeout is not here: that is a slow site that does serve HTTPS, and
# retrying it over http would only double the wait.
_NO_HTTPS = tuple(f"fetch failed: {name}" for name in (
    "ConnectError", "ConnectTimeout", "RemoteProtocolError", "ReadError"))
# The subset that means nothing answered at all. A socket that hangs up after
# connecting is a server that does speak TLS -- often one that drops
# datacenter addresses like this scanner's -- and is no evidence the site
# lacks HTTPS.
_NO_LISTENER = ("fetch failed: ConnectError", "fetch failed: ConnectTimeout")


def collect(url: str) -> CollectorResult:
    """Fetch the page and record the redirect chain, over HTTPS where a browser would.

    A bare name, and a written `http://` on the default port, are tried over
    HTTPS first (see `urls.https_upgrade`). A bare name falls back to http
    only when HTTPS cannot connect at all; a written `http://` falls back
    whenever HTTPS fails, since plain http is what its author asked for. An
    `https://` address is fetched as written and never downgraded.
    """
    secure_url = https_upgrade(url)
    if secure_url is None:
        return _collect(url)
    # One deadline across both attempts: given one each, a server trickling
    # its TLS handshake on 443 held the fetch for twice the deadline, past the
    # whole scan's budget. The fallback always keeps a usable share.
    began = monotonic()
    secure = _collect(secure_url)
    written_http = not is_bare(url)
    if secure.ok and written_http:
        secure.data["https_upgraded"] = True
        secure.detail += ", over https (browsers open this address that way)"
    if secure.ok or secure.status != FAILED:
        return secure
    if not written_http and not secure.detail.startswith(_NO_HTTPS):
        return secure

    left = max(ENVELOPE.fetch_deadline_s - (monotonic() - began), 10.0)
    plain = _collect(url if written_http else "http://" + url.strip(), deadline_s=left)
    plain.elapsed_s += secure.elapsed_s
    if not plain.ok:
        return plain if written_http else secure
    landed_on_https = str(plain.data.get("final_url", "")).startswith("https://")
    if secure.detail.startswith(_NO_LISTENER) and not landed_on_https:
        plain.data["https_unavailable"] = True
        plain.detail += ", over http (the site does not serve HTTPS)"
    else:
        # HTTPS is there -- it refused this scanner, or the http address
        # redirected straight back to it -- so nothing here may say otherwise.
        plain.detail += f", over http after HTTPS refused the scanner ({secure.detail})"
    return plain


def _collect(url: str, deadline_s: float = ENVELOPE.fetch_deadline_s) -> CollectorResult:
    res = CollectorResult(name="HTTP chain")
    with timed(res):
        start = parse(url)
        if start.scheme not in ("http", "https"):
            res.status = FAILED
            res.detail = f"refusing non-HTTP scheme: {start.scheme!r}"
            return res

        try:
            check_url(start.raw)
        except BlockedAddress as exc:
            res.status = FAILED
            res.detail = f"refusing to fetch: {exc}"
            return res

        hops: list[dict] = []
        current = start.raw
        # The last URL that actually answered. `hops` also records addresses we
        # refused to fetch and hops that errored, and those must never end up
        # naming the site the verdict is about -- a redirect to a host that does
        # not resolve was becoming `final_url`, so the scanned page could pick
        # any domain it liked to be judged as.
        last_fetched = ""
        unreached = ""
        body, body_bytes, truncated = "", 0, False
        final_status: int | None = None
        server = ""
        downgraded = False
        is_download, download_reason = False, ""
        blocked_by = ""

        # `guarded_client` pins each connection to an address the guard resolved
        # itself, so the name cannot resolve to something else between the check
        # and the socket.
        client = guarded_client(
            deadline_s=deadline_s,
            timeout=httpx.Timeout(ENVELOPE.per_collector_timeout_s, connect=8.0),
            follow_redirects=False,          # the chain is the evidence
            verify=False,                    # see module docstring
            headers={"User-Agent": ENVELOPE.user_agent, "Accept": "text/html,*/*"},
        )
        try:
            for hop_index in range(ENVELOPE.max_redirects + 1):
                p = parse(current)
                if p.scheme not in ("http", "https"):
                    hops.append({"url": current, "status": None, "note": "non-HTTP scheme, not followed"})
                    break

                try:
                    with client.stream("GET", current) as response:
                        final_status = response.status_code
                        last_fetched = current
                        server = response.headers.get("server", "")
                        location = response.headers.get("location", "")
                        is_download, download_reason = _is_download(response.headers)

                        hops.append({
                            "url": current,
                            "status": response.status_code,
                            "location": location,
                            "content_type": response.headers.get("content-type", ""),
                        })

                        if response.is_redirect and location:
                            # Joined the way a browser joins it. httpx keeps a
                            # backslash in the authority as userinfo, so
                            # `https://kit.example\@www.paypal.com/` was
                            # fetched at PayPal while the browser went to the kit.
                            nxt = browser_join(str(response.url), location)
                            if not nxt:
                                hops.append({"url": location[:200], "status": None,
                                             "note": "redirected to something that is not a web address"})
                                unreached = "the site redirected to something that is not a web address"
                                break
                            # The host under investigation chose this address.
                            try:
                                check_url(nxt)
                            except BlockedAddress as exc:
                                hops.append({"url": nxt, "status": None,
                                             "note": f"not followed: {exc}"})
                                unreached = f"the chain ended at an address that was not fetched ({exc})"
                                break
                            if p.scheme == "https" and parse(nxt).scheme == "http":
                                downgraded = True
                            current = nxt
                            continue

                        if is_download:
                            # Headers only. The bytes are never pulled.
                            break

                        raw, body_bytes, truncated = read_capped(
                            response, ENVELOPE.max_response_bytes
                        )
                        body = decode_html(raw, response.headers.get("content-type", ""))
                        blocked_by = _blocked_by(final_status, response.headers, body)
                        break
                except BlockedAddress as exc:
                    # Raised by the pinned transport at connect time, which is
                    # where a rebinding attempt shows up: the name passed the
                    # check above and then resolved somewhere else.
                    hops.append({"url": current, "status": None,
                                 "note": f"not fetched: {exc}"})
                    unreached = f"an address in the chain was refused at connect time ({exc})"
                    if hop_index == 0:
                        res.status = FAILED
                        res.detail = f"refusing to fetch: {exc}"
                        res.data = {"hops": hops}
                        return res
                    break
                except httpx.InvalidURL:
                    # httpx builds the next request for a redirect even with
                    # following off, and a `Location` it cannot parse -- a
                    # `javascript:` URL, a malformed authority -- raises here
                    # rather than in our join. The server did answer; the
                    # address it sent the visitor to is simply not one.
                    hops.append({"url": current, "status": None,
                                 "note": "redirected to something that is not a web address"})
                    unreached = "the site redirected to something that is not a web address"
                    break
                except httpx.HTTPError as exc:
                    hops.append({"url": current, "status": None, "note": str(exc)})
                    if hop_index == 0:
                        res.status = FAILED
                        res.detail = f"fetch failed: {type(exc).__name__}"
                        res.data = {"hops": hops}
                        return res
                    unreached = f"the last redirect target could not be fetched ({type(exc).__name__})"
                    break
            else:
                hops.append({"url": current, "status": None, "note": "redirect cap reached"})
                unreached = "the redirect chain did not end within the hop limit"
        finally:
            client.close()

        final_url = last_fetched or start.raw
        final_parsed = parse(final_url)
        hop_count = max(len(hops) - 1, 0)
        cross = sum(
            1 for a, b in zip(hops, hops[1:])
            if parse(a["url"]).registrable != parse(b["url"]).registrable
        )

        res.data = {
            "hops": hops,
            "hop_count": hop_count,
            "cross_domain_hops": cross,
            "final_url": final_url,
            "final_registrable": final_parsed.registrable,
            "final_status": final_status,
            "destination_unreached": unreached,
            "server": server,
            "https_downgrade": downgraded,
            "tls_verified": False,   # the fetch client runs with verify=False

            "body_bytes": body_bytes,
            "truncated": truncated,
            "is_download": is_download,
            "download_reason": download_reason,
            # The site answered with a refusal or a bot challenge instead of
            # the page. The body is kept for the record; feature extraction
            # treats it as no page at all.
            "blocked_by": blocked_by,
            "html": body,
        }
        res.detail = (
            f"{hop_count} hop(s), {cross} cross-domain, "
            f"{body_bytes // 1024} KB of "
            f"{ENVELOPE.max_response_bytes // (1024 * 1024)} MB cap"
        )
        if blocked_by.startswith("HTTP "):
            res.detail += f", page withheld ({blocked_by})"
        elif blocked_by:
            res.detail += f", page withheld by {blocked_by} (HTTP {final_status})"
        if is_download:
            res.detail = f"download refused ({download_reason})"
    return res
