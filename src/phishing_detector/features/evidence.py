"""Features derived from the network evidence, and the full assembly.

Pure functions over an EvidenceBundle. The only rule that matters here: when a
sub-collector did not answer, the features it would have produced are marked
absent, never defaulted. A domain whose RDAP lookup timed out does not have an
age of zero.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from functools import lru_cache
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from ..collector.base import UNREADABLE, EvidenceBundle
from ..collector.run import registration
from ..config import MODELS
from ..urls import ParsedURL, parse
from . import content, detectors, lexical
from .base import FeatureSet
from .brands import COMPANY_SHORTENERS, company_labels, owner_of, serves_brand
from .user_content import serves_user_content

_log = logging.getLogger("phishing_detector.features")


@lru_cache(maxsize=1)
def _asn_risk_table() -> dict[str, float]:
    path = MODELS / "asn_risk.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def from_registration(bundle: EvidenceBundle) -> FeatureSet:
    f = FeatureSet()
    reg = registration(bundle)

    rdap_ok = bundle.get("RDAP").ok
    whois_ok = bundle.get("WHOIS fallback").ok
    f.add("whois_lookup_failed", not (rdap_ok or whois_ok))

    if not reg:
        why = "no registration record returned"
    elif not reg.get("describes_site", True):
        # The record is the hosting provider's. Reporting Vercel's 2020
        # registration as this page's age would be worse than reporting
        # nothing: it makes a site created this morning look established.
        why = f"registration belongs to {reg.get('lookup_domain', 'the host')}, not this site"
    else:
        why = ""
    if why:
        for name in ("domain_age_days", "days_to_expiry", "registration_period_days",
                     "registrar_privacy"):
            f.add_missing(name, why)
        return f

    f.add("domain_age_days", reg.get("domain_age_days"), detail=reg.get("created", "")[:10])
    f.add("days_to_expiry", reg.get("days_to_expiry"))
    f.add("registration_period_days", reg.get("registration_period_days"))
    f.add("registrar_privacy", bool(reg.get("privacy_enabled")))
    return f


def from_dns(bundle: EvidenceBundle) -> FeatureSet:
    f = FeatureSet()
    addr = bundle.get("DNS A / AAAA")
    mail = bundle.get("DNS MX / NS")

    if addr.ok:
        d = addr.data
        f.add("a_record_count", len(d.get("a_records", [])) + len(d.get("aaaa_records", [])))
        ttl = d.get("min_ttl")
        f.add("min_ttl", ttl, detail=f"{ttl}s" if ttl is not None else "")
        # Sub-five-minute TTLs are the fingerprint of fast-flux hosting.
        f.add("low_ttl", ttl is not None and ttl < 300)
    else:
        for n in ("a_record_count", "min_ttl", "low_ttl"):
            f.add_missing(n, addr.detail)

    if mail.ok:
        f.add("has_mx", bool(mail.data.get("has_mx")))
        f.add("ns_count", len(mail.data.get("ns_records", [])))
    else:
        f.add_missing("has_mx", mail.detail)
        f.add_missing("ns_count", mail.detail)

    a = bundle.get("ASN / geo")
    f.add("asn_known", a.ok, detail=a.data.get("as_name", "") if a.ok else a.detail)

    # Learned per-network phishing rate, same shape as the TLD table.
    table = _asn_risk_table()
    if a.ok and table:
        asn = a.data.get("asn", "")
        f.add("asn_risk_score", table.get(asn, table.get("__default__", 0.0)),
              detail=f"{asn} {a.data.get('as_name','')}".strip())
    else:
        f.add_missing("asn_risk_score",
                      "ASN unavailable" if not a.ok else "risk table not fitted yet")
    return f


def from_tls(bundle: EvidenceBundle) -> FeatureSet:
    f = FeatureSet()
    cert = bundle.get("TLS certificate")
    if not cert.ok:
        for n in ("cert_age_days", "cert_validity_days", "tls_hostname_match",
                  "tls_self_signed", "san_count", "tls_chain_trusted"):
            f.add_missing(n, cert.detail)
        f.add("tls_present", False)
        return f

    d = cert.data
    f.add("tls_present", True)
    f.add("cert_age_days", d.get("cert_age_days"), detail=str(d.get("not_before", ""))[:10])
    f.add("cert_validity_days", d.get("validity_days"))
    f.add("tls_hostname_match", bool(d.get("hostname_match")))
    f.add("tls_self_signed", bool(d.get("self_signed")))
    f.add("tls_chain_trusted", bool(d.get("chain_trusted")))
    f.add("san_count", d.get("san_count"))
    # Not a model column. The certificate facts above were recorded and then
    # read by nothing: expired.badssl.com and self-signed.badssl.com came back
    # "Nothing suspicious found" while a browser would stop the visitor with a
    # full-page warning. Not a phishing signal -- kits carry valid certificates
    # -- but a result page has to say it, in the words of what is wrong.
    problem = _tls_problem(d)
    f.add("tls_problem", bool(problem), detail=problem)
    return f


def _tls_problem(d: dict) -> str:
    """What is wrong with the certificate, as a reader would put it, or ""."""
    if d.get("self_signed"):
        return "it is self-signed, so no authority vouches for it"
    if d.get("hostname_match") is False:
        return "it was issued for a different website"
    days_left = d.get("days_to_expiry")
    if days_left is not None and days_left < 0:
        return f"it expired {-int(days_left)} days ago"
    if d.get("chain_trusted") is False:
        return "it is not issued by an authority browsers trust"
    return ""


def from_http(bundle: EvidenceBundle) -> FeatureSet:
    f = FeatureSet()
    http = bundle.get("HTTP chain")
    if not http.ok:
        for n in ("redirect_hops", "redirect_cross_domain", "https_downgrade",
                  "final_status_ok", "final_domain_changed", "serves_download",
                  "evidence_follows_redirect"):
            f.add_missing(n, http.detail)
        f.add("fetch_failed", True)
        return f

    d = http.data
    f.add("fetch_failed", False)
    f.add("redirect_hops", d.get("hop_count", 0))
    f.add("redirect_cross_domain", bool(d.get("cross_domain_hops", 0)))
    f.add("https_downgrade", bool(d.get("https_downgrade")))
    status = d.get("final_status")
    f.add("final_status_ok", status is not None and 200 <= int(status) < 300,
          detail=str(status or ""))
    f.add("final_domain_changed", d.get("final_registrable", "") != bundle.parsed.registrable,
          detail=d.get("final_registrable", ""))
    # Not a model column. Set when registration, DNS, TLS and CT were looked
    # up again for the destination, so they describe the page after all.
    f.add("evidence_follows_redirect", bool(d.get("evidence_follows_final")),
          detail=d.get("final_registrable", ""))
    f.add("serves_download", bool(d.get("is_download")), detail=d.get("download_reason", ""))
    # The server answered, but with a refusal or a bot-detection wall rather
    # than the page. Distinct from `fetch_failed`: the site is up and chose
    # not to serve a scanner. Content features are absent for this scan, and
    # the interstitial's own markup is never scored as though it were the site.
    f.add("fetch_blocked", bool(d.get("blocked_by")), detail=d.get("blocked_by", ""))
    # The chain stopped somewhere we did not go: a refused address, a hop that
    # errored, or the hop limit. The page evidence then describes an earlier
    # hop rather than the destination, which is a caveat the verdict has to
    # carry rather than a detail to bury in the record.
    unreached = d.get("destination_unreached", "")
    f.add("destination_unreached", bool(unreached), detail=unreached)
    # The body cap is a real limit on what was seen, and every content feature
    # is computed from the part that fit. A credential form pushed past 2 MB of
    # padding produced "no password field" -- an absence of evidence read as
    # evidence of absence, on a page that chose where the cut fell.
    f.add("body_truncated", bool(d.get("truncated")),
          detail=f"{d.get('body_bytes', 0)} bytes, cut at the cap" if d.get("truncated") else "")
    return f


def from_render(bundle: EvidenceBundle, static_text_len: int) -> FeatureSet:
    """Features that only exist by comparing the rendered DOM to the raw fetch.

    The comparison is the point. A page that arrives as 8 characters of markup
    and becomes 1,490 after its scripts run is describing its own construction,
    and a password field that exists only post-render is a credential form the
    static collector could not see at all.
    """
    f = FeatureSet()
    r = bundle.get("JS render")

    if not r.ok:
        f.add("js_rendered", False, detail=r.detail)
        for n in ("js_dom_growth", "js_injected_password", "js_injected_inputs",
                  "js_redirected", "js_third_party_hosts", "js_download_attempt",
                  "js_dialog_attempt"):
            f.add_missing(n, r.detail or "page was not rendered")
        return f

    d = r.data
    rendered_text = int(d.get("rendered_text_length", 0) or 0)
    f.add("js_rendered", True)
    # Ratio rather than difference, and capped: a long page that grows a little
    # is not the same phenomenon as a shell that materialises entirely.
    f.add("js_dom_growth", min(rendered_text / max(static_text_len, 1), 50.0),
          detail=f"{static_text_len} -> {rendered_text} chars")
    f.add("js_injected_password", bool(d.get("rendered_password_inputs", 0)))
    f.add("js_injected_inputs", d.get("rendered_input_count", 0))
    f.add("js_redirected", bool(d.get("js_redirected")), detail=d.get("final_url", ""))
    hosts = d.get("third_party_hosts", []) or []
    f.add("js_third_party_hosts", len(hosts), detail=", ".join(hosts[:3]))
    # Both of these are blocked, not followed — recorded because attempting
    # them is itself evidence about the page.
    f.add("js_download_attempt", bool(d.get("downloads_blocked")),
          detail=", ".join(d.get("downloads_blocked", [])[:2]))
    f.add("js_dialog_attempt", bool(d.get("dialogs_dismissed")))
    return f


def from_ct(bundle: EvidenceBundle) -> FeatureSet:
    """Certificate Transparency history.

    Carries the age signal for sites where registration age does not exist.
    Nobody registered `kit-abc.vercel.app`, so `domain_age_days` is absent by
    definition — but a certificate was issued for that exact name, and the log
    records when. First-seen is the age of the site rather than of its host.
    """
    f = FeatureSet()
    r = bundle.get("CT log history")
    if not r.ok:
        for n in ("ct_age_days", "ct_cert_count", "ct_distinct_issuers", "ct_known"):
            f.add_missing(n, r.detail)
        return f

    d = r.data
    f.add("ct_known", True, detail=d.get("source", ""))
    f.add("ct_cert_count", d.get("cert_count", 0))
    f.add("ct_distinct_issuers", d.get("distinct_issuers", 0))
    age = d.get("ct_age_days")
    if age is None:
        f.add_missing("ct_age_days", "no timestamped certificate found")
    else:
        f.add("ct_age_days", age, detail=str(d.get("first_seen", ""))[:10])
    # Not a model column. Whether expired certificates were included: without
    # them the age is a lower bound, and cannot show that a site is young.
    f.add("ct_history_complete", bool(d.get("complete_history")), detail=d.get("source", ""))
    return f


def from_favicon(bundle: EvidenceBundle) -> FeatureSet:
    f = FeatureSet()
    r = bundle.get("Favicon")
    if not r.ok:
        f.add("favicon_present", False, detail=r.detail)
        f.add_missing("favicon_brand_impersonation", r.detail)
        f.add_missing("favicon_on_brand_named_domain", r.detail)
        return f
    brand = r.data.get("brand_match", "")
    f.add("favicon_present", True)
    f.add("favicon_brand_impersonation", bool(r.data.get("impersonates")), detail=brand)
    # Not a model column: the model was fitted on the flag above as it is, so
    # that stays. This tells the rules and the explanation when the "copied"
    # icon is in fact on one of its owner's own domains.
    owner_host = _icon_owner_host(bundle, brand)
    f.add("favicon_on_owner_domain", bool(owner_host), detail=owner_host)
    # Also not a model column. The flag above compares the icon's brand with
    # the page's *name*, so `paypal.cfd` serving PayPal's icon is "PayPal's own
    # name" to it. This asks the question that matters: whether the name that
    # matches is one of the domains the brand is actually served from.
    named = _icon_on_brand_named_domain(bundle, brand)
    f.add("favicon_on_brand_named_domain", bool(named), detail=named)
    return f


def _landing_page(bundle: EvidenceBundle) -> ParsedURL:
    """Where the HTTP chain ended, or the address itself when it did not answer."""
    return parse(bundle.data("HTTP chain").get("final_url") or bundle.url)


def _icon_on_brand_named_domain(bundle: EvidenceBundle, brand: str) -> str:
    """The page's domain when it carries the icon's brand name but is not the brand's."""
    if not brand:
        return ""
    page = _landing_page(bundle)
    if page.domain == brand and not serves_brand(brand, page.registrable):
        return page.registrable
    return ""


def _endorsing_company(bundle: EvidenceBundle) -> str:
    """The company whose own link shortener chose this page, or "".

    Only when the chain was followed to its end: an unfinished chain says
    nothing about where the company meant to send anyone.
    """
    http = bundle.data("HTTP chain")
    if not bundle.get("HTTP chain").ok or http.get("destination_unreached"):
        return ""
    return COMPANY_SHORTENERS.get(bundle.parsed.registrable, "")


def _icon_owner_host(bundle: EvidenceBundle, brand: str) -> str:
    """The page's host when it belongs to the brand whose icon it serves."""
    if not brand:
        return ""
    page = _landing_page(bundle)
    company = _endorsing_company(bundle)
    if company and brand in company_labels(company):
        return page.hostname
    if (page.registrable and serves_brand(brand, page.registrable)
            and not serves_user_content(page.hostname)):
        return page.hostname
    return ""


# Feature groups `_group` had to skip during the current `extract_all`, per thread:
# scans are scored on several threads at once.
_SKIPPED_GROUPS = threading.local()


def _group(name: str, fn, *args, **kwargs) -> FeatureSet:
    """One source's features, or none of them if its evidence is malformed.

    Each collector builds its answer from someone else's reply -- a registry,
    a certificate log, a web page -- and a bundle can come back from the disk
    cache damaged. One field of the wrong type (a list of mail servers that is
    a number) used to raise out of scoring altogether; now that source's
    features are simply missing, as if it had not answered.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:  # noqa: BLE001 - malformed evidence, any shape
        _log.warning("feature group %s skipped: malformed evidence", name, exc_info=True)
        getattr(_SKIPPED_GROUPS, "names", []).append(name)
        return FeatureSet()


# A page that is an error or a takedown notice, served with a success code:
# a reported kit a few days on often looks like this, and "nothing suspicious
# found" about an error page answers a question nobody asked.
_SOFT_ERROR = re.compile(
    r"(?i)\b(?:40[34]|50[0234])\b.*\b(?:error|not found|forbidden|unavailable)\b"
    r"|\b(?:page|site|file|app) (?:was )?not found\b|^not found$|internal server error|server error"
    r"|service (?:temporarily )?unavailable|account (?:has been )?suspended"
    r"|(?:site|account|website|page) (?:has been|is|was) (?:suspended|disabled|removed|taken down)"
    r"|^index of /|domain (?:has )?expired|website (?:has )?expired|bandwidth limit exceeded"
    r"|application error|deployment (?:not found|disabled)|no such app"
    r"|there isn.t a github pages site here|^error(?:\s*[-:|–]|\s+\d{3}\b|$)")
# Folders where a site's own pages do not live, and where kits planted on a
# hacked site usually do: a CMS's plugin, theme and upload directories, and
# /.well-known/ (bar the certificate-validation path).
_CMS_FOLDER = re.compile(
    r"(?i)/wp-(?:content|includes|admin)/"
    r"|/components/com_|/modules/mod_|/sites/default/files/"
    r"|/\.well-known/(?!acme-challenge/|pki-validation/)")


def _soft_error(html: str) -> str:
    """The error a page shows instead of content, or ""."""
    if not html:
        return ""
    soup = BeautifulSoup(html[:200_000], "lxml")
    for tag in (soup.title, soup.find(["h1", "h2"])):
        text = " ".join(tag.get_text(" ", strip=True).split()) if tag else ""
        if text and len(text) <= 120 and _SOFT_ERROR.search(text):
            return text
    return ""


def _text(value, default: str = "") -> str:
    return value if isinstance(value, str) else default


def extract_all(bundle: EvidenceBundle, brands: dict[str, str] | None = None,
                tld_risk: dict[str, float] | None = None) -> FeatureSet:
    """Every feature group, assembled in one set.

    Lexical features are computed against the *final* URL after redirects when
    one is available: a shortener's own hostname says nothing useful, the
    destination it lands on says everything.

    Content features prefer the rendered DOM when a render succeeded. For a
    client-side kit the raw markup is a shell, and scoring the shell means
    reporting "no password field, no forms, no foreign assets" about a page
    that has all three.
    """
    _SKIPPED_GROUPS.names = []
    http = bundle.data("HTTP chain")
    static_html = _text(http.get("html"))
    final_url = _text(http.get("final_url")) or bundle.url
    # A bot challenge or an access-denied page is a refusal, not the site.
    # Extracting "one form, no password field, 0 of 1 assets foreign" from a
    # CAPTCHA wall and calling that the page's content is how paypal.com's
    # sign-in got scored on DataDome's markup.
    withheld = _text(http.get("blocked_by"))
    if withheld:
        static_html = ""

    static_text_len = (
        len(BeautifulSoup(static_html, "lxml").get_text(strip=True)) if static_html else 0
    )

    render_result = bundle.get("JS render")
    from_rendered_dom = bool(render_result.ok and _text(render_result.data.get("html")))
    if from_rendered_dom:
        content_html = render_result.data["html"]
        # `final_url` deliberately stays the HTTP chain's destination, not the
        # renderer's `page.url`. A kit that navigates itself on load would
        # otherwise choose which domain every lexical feature describes -- it
        # could redirect to the real paypal.com after painting its form and be
        # scored as PayPal. The navigation is evidence in its own right and is
        # reported as `js_redirected`; it is not a correction to the address.
    else:
        content_html = static_html
    content_source = "rendered DOM" if from_rendered_dom else "static markup"

    fs = FeatureSet()
    fs.update(_group("lexical", lexical.extract, final_url, brands=brands, tld_risk=tld_risk))
    fs.update(_group("registration", from_registration, bundle))
    fs.update(_group("dns", from_dns, bundle))
    fs.update(_group("tls", from_tls, bundle))
    fs.update(_group("http", from_http, bundle))
    no_html_why = f"page withheld by {withheld}" if withheld else "no HTML retrieved"
    fs.update(_group("content", content.extract, content_html, final_url, brands=brands,
                     missing_why=no_html_why))
    fs.update(_group("detectors", detectors.extract, content_html, final_url, brands=brands,
                     missing_why=no_html_why))
    fs.update(_group("ct", from_ct, bundle))
    fs.update(_group("favicon", from_favicon, bundle))
    fs.update(_group("render", from_render, bundle, static_text_len))
    fs.add("content_from_render", from_rendered_dom, detail=content_source)
    # Not model columns: the page is an error or takedown notice, or it is
    # served from a CMS folder where a site's own pages do not live. Neither
    # clears a page on circumstantial evidence (see crosscheck.review).
    http_ok = bundle.get("HTTP chain").ok
    showing_page = http_ok and not withheld and not http.get("is_download")
    soft_error = _group("soft_error", _soft_error, content_html) if showing_page else ""
    soft_error = soft_error if isinstance(soft_error, str) else ""
    fs.add("soft_error_page", bool(soft_error), detail=soft_error[:80])
    folder = _CMS_FOLDER.search(urlsplit(final_url).path or "") if showing_page else None
    fs.add("served_from_cms_folder", bool(folder), detail=folder.group(0) if folder else "")
    # Not a model column. Evidence that was there but could not be read --
    # a feature group that raised, a source scoring had to set aside. Much of
    # it is the page's own doing, so it must not be a way to make a kit's
    # password form disappear and leave a clean-looking verdict: the review
    # will not call such a check safe on circumstantial evidence.
    unreadable = list(_SKIPPED_GROUPS.names) + [
        name for name, r in bundle.results.items() if r.detail == UNREADABLE]
    fs.add("evidence_unreadable", bool(unreadable), detail=", ".join(unreadable))
    page = parse(final_url)
    # Not a model column: the page the visitor lands on is plain HTTP. Said on
    # the result page because a browser marks it "Not secure", not because it
    # decides anything about phishing.
    fs.add("connection_unencrypted", http_ok and page.scheme == "http",
           detail=page.hostname)
    # Not a model column: the page was reached through a shortener only its
    # company can create links on (see brands.COMPANY_SHORTENERS).
    endorsed = _group("shortener", _endorsing_company, bundle)
    endorsed = endorsed if isinstance(endorsed, str) else ""
    fs.add("sent_by_company_shortener", bool(endorsed), detail=endorsed)
    # Also not model columns. Two ways the address leads nowhere, both common
    # for a reported kit a few days on: the page has been taken down (404,
    # 410), or a short link has been disabled and the service shows its own
    # home page instead. Either way nothing was seen that could clear the
    # link, and "Nothing suspicious found" about it read as "the message that
    # sent it was genuine".
    status = http.get("final_status")
    fs.add("page_missing", http_ok and status in (404, 410),
           detail=f"HTTP {status}" if status else "")
    fs.add("short_link_dead_end", http_ok and page.registrable in lexical.SHORTENERS,
           detail=page.registrable)
    # Also not a model column. `user_content_on_brand_domain` is only ever
    # set on a domain the brand list knows, so onedrive.live.com -- where
    # anyone shares a file -- was never marked, and the registration rules
    # read live.com's thirty years as the shared page's own.
    user_content = serves_user_content(page.hostname)
    fs.add("user_content_host", user_content, detail=page.hostname if user_content else "")
    # Not model columns. The brands of the company that owns this page's
    # domain, so the rules can tell a brand borrowed from a stranger from one
    # borrowed from the same company. Empty on hosts that publish strangers'
    # pages: a page on sites.google.com is not Google's to vouch for.
    # Who owns the *name* (cloud.microsoft is Microsoft's, forms or not) and
    # who answers for the *page* (nobody, on a host strangers publish to).
    domain_company, domain_owners = owner_of(page.registrable)
    fs.add("domain_owner_brands", bool(domain_owners), detail=",".join(sorted(domain_owners)))
    company, owners = ("", frozenset()) if user_content else (domain_company, domain_owners)
    fs.add("page_owner_brands", bool(owners), detail=",".join(sorted(owners)))
    fs.add("page_owner_company", bool(company),
           detail=f"{page.registrable} belongs to {company}" if company else "")
    # Not model columns, both for the review's benign side.
    named = _group("redirector", _redirector_names_brand, bundle, fs) if showing_page else ""
    named = named if isinstance(named, str) else ""
    fs.add("redirector_names_brand", bool(named), detail=named)
    fs.add("asks_for_nothing", showing_page and _asks_for_nothing(fs))
    # Not a model column: the address is a site's front door, `example.com/`
    # or `www.example.com/`, not a page somewhere inside it or a subdomain.
    # The page it ended on must be on the same site, so `/` redirecting
    # somewhere else does not count.
    start = bundle.parsed
    front = (start.registrable, f"www.{start.registrable}")
    fs.add("site_home_page", bool(start.registrable) and (urlsplit(bundle.url).path or "/") == "/"
           and not urlsplit(bundle.url).query
           and start.hostname in front and page.hostname in front)
    return fs


def _redirector_names_brand(bundle: EvidenceBundle, fs: FeatureSet) -> str:
    """How the address names the brand whose real site it redirected to, or "".

    A kit hides from scanners by answering them with a redirect to the real
    company -- `kit.myftpupload.com/Paypal-de/auth/login.php` sent this checker
    to paypal.com, the evidence described PayPal's own site, and the link was
    "an ordinary website". The tell is the brand's name in the path of an
    address on someone else's domain. Links the company makes itself start on
    its own domains or its own shorteners, and trackers and affiliate links
    carry the destination in the query, not the path.
    """
    if not (fs["is_known_brand_domain"].present and fs["is_known_brand_domain"].value):
        return ""
    start = bundle.parsed
    page = parse(_text(bundle.data("HTTP chain").get("final_url")) or bundle.url)
    if not start.registrable or start.registrable == page.registrable or _endorsing_company(bundle):
        return ""
    company, labels = owner_of(page.registrable)
    if company and owner_of(start.registrable)[0] == company:
        return ""
    names = set(labels) | {page.registrable.split(".")[0]}
    path = re.sub(r"[^a-z0-9]", "", unquote(urlsplit(bundle.url).path).lower())
    for name in sorted(names, key=len, reverse=True):
        if len(name) >= 4 and name in path:
            return f"{start.hostname} names {name} and redirects to {page.registrable}"
    return ""


def _asks_for_nothing(fs: FeatureSet) -> bool:
    """A served page full of working links with no field anywhere in it.

    What a credential page cannot be: it has to ask for something, or hide
    what it will ask (an empty shell for scripts to fill). A brand-new domain
    alone made the model certain about a cam site's mirror, 56 links and not
    one input.

    Never for a page that borrows anyone's brand -- in its address, title,
    icon or images -- or carries a kit's markers: a cloned bank home page
    whose sign-in form is built by script also shows no field to a checker
    that does not run scripts, and its links all work because they are the
    bank's.
    """
    def value(name):
        f = fs[name] if name in fs else None
        return f.value if f is not None and f.present else None

    if any(value(n) for n in ("form_count", "input_count", "has_password_input",
                              "sensitive_field_count", "js_injected_inputs",
                              "js_injected_password", "render_empty",
                              "asks_for_seed_phrase", "concealed_password_input",
                              "brand_cdn_asset_count", "title_domain_mismatch",
                              "favicon_brand_impersonation", "favicon_on_brand_named_domain",
                              "homograph_brand_match", "brand_embedded_in_domain",
                              "brand_in_wrong_position", "brand_sld_wrong_suffix",
                              "kit_marker_count", "client_redirect", "exfil_endpoint",
                              "iframe_count", "hidden_iframe_count")):
        return False
    return (value("form_count") == 0 and (value("anchor_count") or 0) >= 20
            and (value("dead_anchor_ratio") or 0) <= 0.1)
