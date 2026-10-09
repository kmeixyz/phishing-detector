"""URL parsing shared by the feature layer and the collector.

Hostnames are split against the Public Suffix List via tldextract rather than
by counting dots. Splitting on dots gets `paypal.com.secure-login.ru` wrong in
exactly the way that matters: the registrable domain is `secure-login.ru`, and
`paypal.com` is just a subdomain the attacker chose to look reassuring.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

import httpx
import idna
import tldextract

from .config import CORPUS

# Characters that end the authority for a browser but not for `urlsplit`, and
# characters that cannot appear in a host at all. Both lists come from the
# WHATWG URL standard, and both matter for the same reason: this parser decides
# which site the verdict is about, so any string a browser reads as one host
# and this reads as another is a way to have the wrong site cleared.
_AUTHORITY_END = "/\\?#"
# The standard's forbidden domain code points that can survive `urlsplit`.
# `%` matters most: `http://%25.com/` decoded to a host of `%.com`, which no
# browser opens and which crt.sh reads as a wildcard for every .com name.
_FORBIDDEN_HOST = set("/\\?#@ \t\r\n%<>^|\x7f") | {chr(c) for c in range(0x20)}

# Cached PSL. Warm it once (scripts/warm_cache.py) so a deployed run
# never makes an unexpected outbound request mid-scan.
#
# PRIVATE DOMAINS ARE ON, and that is the single most consequential setting in
# this file. With ICANN-only suffixes, `kit-abc.vercel.app` has a registrable
# domain of `vercel.app` — which means every phishing page hosted on Vercel
# becomes the *same site* as far as the rest of the pipeline is concerned.
# Measured on this corpus, 49% of phishing URLs collapsed onto seven names
# (pages.dev, blogspot.com, vercel.app, github.io, ...). The damage:
#
#   * domain age reported Vercel's 2020 registration as the scanned site's age
#   * the TLD risk table learned ".dev = 91% phishing", which is not a fact
#     about .dev but about who offers free subdomains on it
#   * the group-aware split put all 91 pages.dev phish in one group
#
# With private domains enabled the registrable unit becomes the thing the
# attacker actually controls, and the suffix becomes the hosting provider —
# which is a genuinely useful signal in its own right.
# One copy of the list, shipped in the repository and read from disk
# everywhere: no network and no write at runtime. A stateless instance used to
# fall back to the snapshot bundled inside tldextract, months older than the
# list everything else (and the training data) used -- so on Vercel
# `gh-post.us.cc` was a page on `us.cc`, dated by that registry's 2006
# registration and called safe, while every local run saw its own site.
# `scripts/warm_cache.py` refreshes the file. tldextract's bundled snapshot
# remains the fallback if the file is missing.
PSL_FILE = CORPUS / "public_suffix_list.dat"
_PSL_SOURCE = {"suffix_list_urls": (PSL_FILE.as_uri(),), "cache_dir": None,
               "fallback_to_snapshot": True}
_extract = tldextract.TLDExtract(include_psl_private_domains=True, **_PSL_SOURCE)
# The ICANN-level view is kept alongside it: RDAP has a record for
# `vercel.app` and none for `kit-abc.vercel.app`, so registration lookups have
# to be issued against this one.
_extract_icann = tldextract.TLDExtract(include_psl_private_domains=False, **_PSL_SOURCE)


def _registrable(domain: str, suffix: str) -> str:
    """domain + public suffix, lowercased. Either part may be empty."""
    return ".".join(part for part in (domain, suffix) if part).lower()


def _normalise_authority(url: str) -> str:
    r"""End the authority where a browser ends it.

    `urlsplit` treats a backslash as an ordinary character, so in
    `http://evil.example\@www.paypal.com/login` it reads `evil.example\` as
    userinfo and `www.paypal.com` as the host. Every browser reads the
    backslash as a path separator, so the host is `evil.example` and the rest
    is path. The scanner would therefore fetch, analyse and clear PayPal while
    the victim's browser opened the attacker's page.
    """
    sep = url.find("://")
    if sep == -1:
        return url
    head, rest = url[: sep + 3], url[sep + 3 :]
    cuts = [i for i in (rest.find(c) for c in _AUTHORITY_END) if i != -1]
    if cuts:
        cut = min(cuts)
        if rest[cut] == "\\":
            rest = rest[:cut] + "/" + rest[cut + 1 :]
    return head + rest


def browser_join(base: str, location: str) -> str:
    r"""Resolve a redirect's `Location` against `base` as a browser does.

    httpx joins by RFC 3986, where a backslash is an ordinary character: it
    turned `https://kit.example\@www.paypal.com/signin` into
    `https://kit.example%5C@www.paypal.com/signin`, a URL whose host is PayPal,
    and the percent-encoding hid the backslash from `_normalise_authority`.
    A browser reads the same header as a path on `kit.example`. So the
    reference is first cleaned the way the WHATWG parser cleans it -- outer
    whitespace and controls trimmed, tabs and newlines removed, backslashes
    before the query read as slashes -- and only then joined.
    """
    ref = location.strip("".join(map(chr, range(0x21))))
    ref = ref.translate({9: None, 10: None, 13: None})
    cuts = [i for i in (ref.find("?"), ref.find("#")) if i != -1]
    cut = min(cuts) if cuts else len(ref)
    ref = ref[:cut].replace("\\", "/") + ref[cut:]
    # Total, like `parse`: every caller hands it text the scanned page chose,
    # and httpx rejects hosts it cannot encode -- a lone surrogate, an
    # over-long label -- by raising. "" means "not a web address".
    try:
        return str(httpx.URL(base).join(ref))
    except (httpx.InvalidURL, ValueError, UnicodeError):
        return ""


def _is_ip_literal(host: str) -> bool:
    """Whether `host` is an IPv4 or IPv6 address, brackets allowed."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


_DNS_NAME = re.compile(r"[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_.])?")


def is_dns_name(host: str) -> bool:
    """Whether `host` (ASCII form) is safe to hand to a lookup service as a name."""
    return bool(host) and len(host) <= 253 and bool(_DNS_NAME.fullmatch(host.lower()))


def https_upgrade(url: str) -> str | None:
    """The HTTPS address a browser opens first for `url`, or None if it opens `url` as is.

    A typed bare name gets HTTPS. So, now, does a written `http://` on the
    default port: Chrome upgrades it (HTTPS-Upgrades), Firefox and Safari go
    HTTPS-first, and each falls back to http only when HTTPS fails. So the
    page a visitor sees for `http://paypal.com` is the HTTPS one, and checking
    the plain-HTTP answer instead -- or skipping the certificate because the
    address said http -- described something they would not be shown.
    An explicit port is left alone, as browsers leave it.
    """
    raw = (url or "").strip()
    if "://" not in raw:
        return None if raw.lower().startswith(HOSTLESS_SCHEMES) else "https://" + raw
    if raw[:7].lower() != "http://":
        return None
    port = parse(raw).port
    if port == 80:
        # The default port written out is still the default port: browsers
        # drop it and upgrade as usual.
        rest = raw[7:]
        host_end = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1] or [len(rest)])
        return "https://" + rest[:host_end].replace(":80", "", 1) + rest[host_end:]
    return "https://" + raw[7:] if port is None else None


def _clean_host(host: str) -> str:
    """Percent-decode a host, or reject it if it cannot be one.

    Browsers percent-decode the host before anything else, so `kit%2Eevil.example`
    is three labels to them and one label to a parser that skips the step. That
    difference decides whether `userinfo_deception` reads as decisive.

    A decoded host containing a character no host may hold is rejected outright
    rather than truncated at it. Truncating looked tidier and was worse: the
    decoded form of `paypal.com%2f.evil.example` is `paypal.com/.evil.example`,
    and cutting at the slash yields `paypal.com` -- a real, reassuring domain
    that nothing would ever connect to. The guard would then approve PayPal
    while the client dialled the attacker, and the verdict would name PayPal.
    Browsers reject such a host; so does this.
    """
    decoded = unquote(host)
    if any(ch in _FORBIDDEN_HOST for ch in decoded):
        return ""
    return decoded.lower()


def idna_ascii(host: str) -> str:
    """The ASCII form an HTTP client actually connects to (IDNA2008 + UTS46).

    Everything that opens a socket or checks an address must agree on one
    encoding of the hostname. `socket.getaddrinfo` and `ssl` apply IDNA2003,
    where `faß.example` becomes `fass.example`; httpx applies IDNA2008, where
    it becomes `xn--fa-hia.example`. Those are two separately registrable
    domains, so a guard that resolves one while the client connects to the
    other is not a guard at all -- which is exactly how the SSRF fix was
    bypassed. `dns_records` learned this first; this is that lesson made
    canonical so every caller inherits it.
    """
    if not host:
        return host
    if host.isascii():
        return host.lower()
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Not encodable at all. Return it unchanged so the caller's own
        # resolution fails, rather than silently substituting another name.
        return host.lower()


def idna_unicode(host: str) -> str:
    """The human-visible form of a punycode host, for the features a reader sees."""
    if "xn--" not in host:
        return host
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


@dataclass(frozen=True)
class ParsedURL:
    raw: str
    scheme: str
    userinfo: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    subdomain: str
    domain: str          # the label the registrant controls, e.g. "secure-login"
    suffix: str          # public suffix, e.g. "co.uk" or "vercel.app"
    registrable: str     # domain + suffix, e.g. "secure-login.ru"
    icann_registrable: str = ""   # the billable domain, e.g. "vercel.app"
    icann_suffix: str = ""        # the ICANN suffix, e.g. "app"
    ascii_hostname: str = ""      # what a client connects to: "xn--fa-hia.example"
    unicode_hostname: str = ""    # what a person sees: "faß.example"

    @property
    def unicode_domain(self) -> str:
        """The registrable label as a reader sees it, not as punycode.

        Brand and typosquat matching has to run on this. `xn--80ak6aa92e.com`
        is not one edit from "apple" by any string metric; `аpple.com` is the
        same word to the eye, and the eye is what the attack targets.
        """
        return idna_unicode(self.domain)

    @property
    def on_shared_hosting(self) -> bool:
        """True when the site lives on someone else's domain.

        `kit-abc.vercel.app` is registrable in its own right but nobody paid a
        registrar for it, so registration evidence describes the provider
        rather than this site.
        """
        return bool(self.icann_registrable) and self.registrable != self.icann_registrable

    @property
    def hosting_provider(self) -> str:
        return self.suffix if self.on_shared_hosting else ""

    @property
    def is_ip_host(self) -> bool:
        return _is_ip_literal(self.hostname)

    @property
    def subdomain_labels(self) -> list[str]:
        return [p for p in self.subdomain.split(".") if p]

    def hash(self) -> str:
        """Cache key for the evidence bundle."""
        return hashlib.sha256(self.raw.encode("utf-8", "replace")).hexdigest()


# Schemes written without "//" that name no host. `data:text/html,hi` has no
# "://", so it used to be taken for a bare `host:port` and parsed as
# `https://data:...` -- hostname "data", scheme "https" -- and the address guard,
# satisfied with the scheme, went on to resolve a host called "data". A fixed
# list rather than "anything before a colon": that would also swallow bare
# deceptions like `paypal.com:login@evil.example`, which must still parse as
# the address a browser would open.
HOSTLESS_SCHEMES = ("data:", "javascript:", "vbscript:", "mailto:", "tel:", "sms:",
                     "about:", "blob:")


def parse(url: str) -> ParsedURL:
    url = (url or "").strip()
    if url and "://" not in url and not url.lower().startswith(HOSTLESS_SCHEMES):
        # A typed bare hostname gets HTTPS, as a browser gives it: HTTPS-first
        # is every major browser's default for a typed address, and nearly
        # every site serves it. Defaulting to http meant `chase.com` was
        # checked without its certificate ever being read. The HTTP collector
        # falls back to http for bare input when HTTPS cannot connect, the
        # same way a browser does.
        url = "https://" + url
    url = _normalise_authority(url)

    # `urlsplit` raises on a malformed IPv6 authority -- a bare `http://[` is
    # enough. This function is the single front door: the address guard, every
    # collector, the feature layer and the templates all call it, and a great
    # many of those call sites have no sensible way to handle an exception. So
    # it is total. An address that cannot be parsed comes back with an empty
    # hostname, which is a state every caller already handles, because it is
    # the same state a host of forbidden characters produces.
    #
    # Found by fuzzing: 2,381 of 8,051 adversarial inputs raised here, and the
    # one that reached a route made `POST /feedback` answer 500 -- an
    # unauthenticated, public, state-changing endpoint returning a server error
    # on a string anybody could send.
    try:
        sp = urlsplit(url)
    except ValueError:
        return ParsedURL(raw=url, scheme="", userinfo="", hostname="",
                         ascii_hostname="", unicode_hostname="", port=None,
                         path="", query="", fragment="", subdomain="",
                         domain="", suffix="", registrable="")
    netloc = sp.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")

    host_for_psl = _clean_host(sp.hostname or netloc)
    ext = _split(_extract(host_for_psl), host_for_psl)
    icann = _split(_extract_icann(host_for_psl), host_for_psl)

    try:
        port = sp.port
    except ValueError:
        port = None

    return ParsedURL(
        raw=url,
        scheme=sp.scheme.lower(),
        # Percent-decoded, because the deception test downstream asks whether
        # this reads as a hostname and `kit%2Eevil%2Eexample` reads as one.
        userinfo=unquote(userinfo).lower(),
        hostname=host_for_psl,
        ascii_hostname=idna_ascii(host_for_psl),
        unicode_hostname=idna_unicode(host_for_psl),
        port=port,
        path=sp.path,
        query=sp.query,
        fragment=sp.fragment,
        subdomain=ext[0].lower(),
        domain=ext[1].lower(),
        suffix=ext[2].lower(),
        registrable=_registrable(ext[1], ext[2]),
        icann_registrable=_registrable(icann[1], icann[2]),
        icann_suffix=icann[2].lower(),
    )


def _split(ext, host: str) -> tuple[str, str, str]:
    """(subdomain, domain, suffix), with the Public Suffix List's default rule.

    The list's algorithm treats a TLD it does not know as a one-label suffix
    (the implicit "*" rule); tldextract instead returns no suffix and makes the
    TLD itself the domain. So `a.b.newtld` was the site `newtld`, and on Vercel
    -- which then read a bundled snapshot of the list -- every site on a TLD
    delegated since would have been described, and looked up, as its TLD.
    """
    if ext.suffix or not host or "." not in host.strip(".") or _is_ip_literal(host):
        return ext.subdomain, ext.domain, ext.suffix
    labels = host.strip(".").split(".")
    return ".".join(labels[:-2]), labels[-2], labels[-1]


def decoded_path_query(p: ParsedURL) -> str:
    """Percent-decoded path+query, lowercased, for keyword matching."""
    return unquote(f"{p.path}?{p.query}" if p.query else p.path).lower()


def without_credentials(url: str) -> str:
    """`url` without any `user:password@` part.

    Nothing this scanner sends anywhere -- the page fetch, the renderer, a
    reputation lookup -- may carry credentials someone pasted along with a link.
    """
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))
