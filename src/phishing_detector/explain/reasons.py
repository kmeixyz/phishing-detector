"""Turning a decision into ranked, plain-language reasons.

This module is the product. A probability of 0.96 tells a user nothing they
can act on; "the password field posts to a domain unrelated to the page" tells
them exactly what is wrong and lets them judge it themselves.

Each template renders a feature's *actual value* into a sentence. Templates
never restate the model's opinion ("this looks suspicious") — they state the
observation and let the ranked contribution carry the weight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..features.base import FeatureSet


@dataclass
class Reason:
    rank: int
    text: str
    feature: str
    contribution: float
    toward_phishing: bool


def _days(n: float) -> str:
    n = int(n)
    if n < 1:
        return "today"
    if n == 1:
        return "1 day ago"
    if n < 60:
        return f"{n} days ago"
    if n < 730:
        return f"{n // 30} months ago"
    return f"{n // 365} years ago"


def _plural(n: float, one: str, many: str) -> str:
    return one if int(n) == 1 else many


def _none(detail: str) -> bool:
    """Whether a "k of n" detail counts out of nothing."""
    return detail.strip().endswith(" of 0")


# value -> sentence. `d` is the feature's detail string, which carries the
# concrete particulars (which brand, which host, which date).
TEMPLATES: dict[str, Callable[[float, str], str]] = {
    "domain_age_days": lambda v, d: f"The registrable domain was registered {_days(v)}.",
    "registration_period_days": lambda v, d: (
        f"It was registered for {int(v) // 365} year(s). Phishers buy 12 months, not five years."
        if v else "Registration period is unavailable."),
    "days_to_expiry": lambda v, d: f"The registration expires in {int(v)} days.",
    "registrar_privacy": lambda v, d: (
        "Registrant details are hidden behind a privacy service."
        if v else "Registrant details are published rather than privacy-protected."),
    "favicon_brand_impersonation": lambda v, d: (
        f"The page serves {d}'s exact favicon without being {d}'s domain, so the icon "
        "was copied from the real site."
        if v else "The favicon does not match any known brand's icon."),
    "on_shared_hosting": lambda v, d: (
        f"The page is hosted on a free {d} subdomain, which requires no domain "
        "registration at all, so there is no registration history to check."
        if v else "The site is on its own registered domain."),
    "whois_lookup_failed": lambda v, d: (
        "Neither RDAP nor WHOIS returned a record, so domain age is unavailable. "
        "The failure itself carries weight: phishing sits disproportionately on "
        "TLDs with poor RDAP coverage."
        if v else "Registration records were retrieved successfully."),

    "has_mx": lambda v, d: (
        "The domain has mail records, so it receives email like a real organisation."
        if v else "The domain has no MX records, so it receives no mail at all."),
    "low_ttl": lambda v, d: (
        f"DNS records carry a very short TTL ({d}), which is characteristic of fast-flux hosting."
        if v else f"DNS TTLs are ordinary ({d})."),
    "a_record_count": lambda v, d: f"{int(v)} address {_plural(v, 'record', 'records')} resolved.",

    "cert_age_days": lambda v, d: (
        f"The TLS certificate was issued {_days(v)}"
        + (f" ({d})." if d else ".")),
    "cert_validity_days": lambda v, d: f"The certificate is valid for {int(v)} days.",
    "san_count": lambda v, d: (
        f"The certificate covers {int(v)} SAN entries, consistent with a bulk-issued wildcard."
        if v >= 50 else f"The certificate covers {int(v)} SAN {_plural(v, 'entry', 'entries')}."),
    "tls_hostname_match": lambda v, d: (
        "The certificate matches the hostname being served."
        if v else "The certificate does NOT match the hostname being served."),
    "tls_self_signed": lambda v, d: (
        "The certificate is self-signed." if v else "The certificate is not self-signed."),
    "tls_chain_trusted": lambda v, d: (
        "The certificate chain verifies against the public trust store."
        if v else "The certificate chain does not verify against the public trust store."),
    "tls_present": lambda v, d: (
        "The page is served over TLS." if v else "The page is not served over TLS."),

    "redirect_hops": lambda v, d: (
        f"The request passed through {int(v)} {_plural(v, 'redirect', 'redirects')}."
        if v else "The URL resolved directly, with no redirects."),
    "redirect_cross_domain": lambda v, d: (
        "The redirect chain crosses to a different registrable domain."
        if v else "No redirect left the original domain."),
    "https_downgrade": lambda v, d: (
        "The chain downgrades from HTTPS to plain HTTP."
        if v else "No HTTPS-to-HTTP downgrade occurred."),
    "final_domain_changed": lambda v, d: (
        f"The final page is served from {d}, not the domain submitted."
        if v else "The final page is on the domain that was submitted."),
    "fetch_failed": lambda v, d: (
        "The page could not be fetched, so no content evidence is available."
        if v else "The page was retrieved successfully."),
    "safe_browsing_listed": lambda v, d: (
        f"Google Safe Browsing lists this address ({d})."
        if v else "Google Safe Browsing does not list this address."),
    "fetch_blocked": lambda v, d: (
        (f"The site refused to serve the page ({d})" if d.startswith("HTTP ")
         else f"The site served a bot-detection page ({d}) instead of its content")
        + ", so the page itself was not seen."
        if v else "The site served its page rather than a refusal or a bot-detection wall."),
    "serves_download": lambda v, d: (
        f"The URL serves a file download rather than a page ({d}). It was not retrieved."
        if v else "The URL serves a page rather than a download."),

    "has_password_input": lambda v, d: (
        "The page contains a password field."
        if v else "The page has no password field, so it is not collecting credentials directly."),
    "form_action_cross_domain": lambda v, d: (
        "A form on this page posts to a different registrable domain than the page itself."
        if v else "Forms post back to the page's own domain."),
    "form_action_insecure": lambda v, d: (
        "A form posts over plain HTTP, so anything typed into it travels unencrypted."
        if v else "No form posts over plain HTTP."),
    "form_action_empty": lambda v, d: (
        "A form has an empty or javascript: action, so its destination is set at runtime."
        if v else "Form actions point at real destinations."),
    # "0 of 0 links are dead" was said about pages with no links at all.
    "foreign_asset_ratio": lambda v, d: (
        "The page loads no stylesheets, scripts or images." if _none(d)
        else f"{d} stylesheets, scripts and images load from a domain other than this one, "
        "the signature of a page that was saved and re-hosted."
        if v > 0.5 else f"{d} resources load from another domain."),
    "dead_anchor_ratio": lambda v, d: (
        "The page has no links." if _none(d)
        else f"{d} links go nowhere, which is what happens when a kit mirrors one page "
        "and drops the rest of the site."
        if v > 0.3 else f"{d} links are dead."),
    "favicon_foreign": lambda v, d: (
        f"The favicon is loaded from {d}, a domain this page does not own."
        if v else "The favicon is served from the page's own origin."),
    "title_domain_mismatch": lambda v, d: (
        f"The page title names {d}, which does not appear in the registrable domain."
        if v else "The page title is consistent with the domain."),
    "hidden_iframe_count": lambda v, d: (
        f"The page contains {int(v)} hidden or zero-dimension {_plural(v, 'iframe', 'iframes')}."
        if v else "No hidden iframes are present."),
    "meta_refresh": lambda v, d: (
        "The page uses a meta refresh redirect." if v else "No meta refresh redirect."),
    # Three wordings, not two. At zero the scripts are plain; a single marker
    # (one `atob(` or `\x` escape) is common in ordinary bundles, and calling
    # that "not obfuscated" beside a number pushing toward a scam read as a
    # contradiction.
    "obfuscation_score": lambda v, d: (
        f"Scripts on the page show obfuscation ({d})." if v > 0.2
        else f"Scripts show a trace of obfuscation ({d})." if v > 0
        else "Scripts are not obfuscated."),
    "right_click_disabled": lambda v, d: (
        "The page disables the right-click context menu."
        if v else "The context menu is not disabled."),
    "render_empty": lambda v, d: (
        f"The page returned almost no markup to a plain fetch ({d}), so it renders "
        "client-side. Content features are unreliable for this page."
        if v else "The page returned real markup without needing JavaScript."),

    "js_rendered": lambda v, d: (
        "The page was rendered with JavaScript, so content features reflect the "
        "live DOM rather than the raw markup."
        if v else f"The page was not rendered ({d})."),
    "js_dom_growth": lambda v, d: (
        f"JavaScript built most of this page ({d}). The raw response was close to empty."
        if v > 5 else f"JavaScript changed the page only marginally ({d})."),
    "js_injected_password": lambda v, d: (
        "A password field exists only after JavaScript runs, so a plain fetch "
        "would not see the credential form at all."
        if v else "No password field appears after rendering."),
    "js_redirected": lambda v, d: (
        f"JavaScript navigated the browser to {d}, a different registrable domain."
        if v else "JavaScript did not redirect off the domain."),
    "js_third_party_hosts": lambda v, d: (
        f"Rendering pulled resources from {int(v)} third-party host(s): {d}."
        if v else "Rendering pulled no third-party resources."),
    "js_download_attempt": lambda v, d: (
        f"The page tried to start a file download ({d}). It was blocked, not followed."
        if v else "The page did not attempt a download."),
    "js_dialog_attempt": lambda v, d: (
        "The page opened a JavaScript dialog, which was dismissed."
        if v else "The page opened no dialogs."),
    "content_from_render": lambda v, d: f"Content features were read from the {d}.",

    "brand_in_wrong_position": lambda v, d: (
        f"The brand name{'s' if int(v) > 1 else ''} {d} appear in the subdomain or path, "
        "but not in the registrable domain."
        if v else "No brand name appears outside the registrable domain."),
    "brand_embedded_in_domain": lambda v, d: (
        f"The registrable domain has the brand name {d} buried inside it."
        if v else "No brand name is embedded in the registrable domain."),
    "is_known_brand_domain": lambda v, d: (
        f"{d} is the brand's own registered domain, not a lookalike of it."
        if v else "The domain is not a known brand's own domain."),
    "user_content_on_brand_domain": lambda v, d: (
        f"The page is published on {d}, where anyone can put a page under the "
        "brand's name. The address belongs to the brand; the page does not."
        if v else "The page is not on a host that publishes strangers' pages."),
    "brand_sld_wrong_suffix": lambda v, d: (
        f"The domain uses a brand name on the wrong suffix ({d})."
        if v else "The domain does not put a brand name on an unexpected suffix."),
    "typosquat_distance": lambda v, d: (
        f"The domain is {d}, within edit distance of a well-known brand."
        if v <= 2 else "The domain is not close to any well-known brand name."),
    "domain_entropy": lambda v, d: (
        f"The domain name looks randomly generated (entropy {v:.2f})."
        if v > 3.5 else f"The domain name reads like words rather than random characters ({v:.2f})."),
    "num_digits_domain": lambda v, d: (
        f"The registrable domain contains {int(v)} digit(s)."
        if v else "The registrable domain contains no digits."),
    "digit_ratio_domain": lambda v, d: (
        f"{v:.0%} of the registrable domain is digits."
        if v > 0.2 else "The registrable domain is mostly letters."),
    "brand_cdn_asset_count": lambda v, d: (
        f"{int(v)} resource(s) load from {d}'s own infrastructure, which is what a "
        "saved and re-hosted copy of their page looks like."
        if v else "No resources load from a recognised brand's own infrastructure."),
    "brand_cdn_asset_ratio": lambda v, d: (
        f"{d}, served from the brand's infrastructure rather than this site's."
        if v else "No assets are served from another brand's infrastructure."),
    "external_link_ratio": lambda v, d: (
        "The page has no links to other websites, or to anywhere." if _none(d)
        else f"{v:.0%} of the page's links point off this domain."
        if v > 0.5 else f"Most links stay on this domain ({v:.0%} point elsewhere)."),
    "script_count": lambda v, d: (
        "The page runs no scripts." if int(v) == 0
        else "The page carries 1 script tag." if int(v) == 1
        else f"The page carries {int(v)} script tags."),
    "domain_token_count": lambda v, d: (
        f"The registrable domain is built from {int(v)} hyphen-separated words."
        if v > 1 else "The registrable domain is a single word."),
    "homograph_brand_match": lambda v, d: (
        f"The domain is a look-alike of a brand name once confusable characters are "
        f"normalised ({d})."
        if v else "The domain is not a character-level look-alike of any brand."),
    "exfil_endpoint": lambda v, d: (
        f"Credentials are posted to {d}. No legitimate sign-in form does this."
        if v else "No credential-exfiltration endpoint was found in the page."),
    "sensitive_field_count": lambda v, d: (
        f"The page asks for {int(v)} {_plural(v, 'category', 'categories')} "
        f"of sensitive data ({d})."
        if v else "The page asks for no card, identity or one-time-code fields."),
    "kit_marker_count": lambda v, d: (
        f"{int(v)} phishing-kit marker(s) present: {d}."
        if v else "No phishing-kit markers were found."),
    "asn_risk_score": lambda v, d: (
        f"The hosting network ({d}) carries a {v:.0%} phishing rate in the training "
        "data. Large clouds host both sides, so this is weak evidence on its own."),
    "ct_age_days": lambda v, d: (
        f"The oldest certificate found for this hostname was logged {_days(v)}"
        + (f" ({d})." if d else ".")),
    "ct_cert_count": lambda v, d: (
        f"{int(v)} certificate(s) recorded in Certificate Transparency logs."),
    "tld_risk_score": lambda v, d: (
        f"The .{d} TLD carries a {v:.0%} phishing rate in the training data."),
    "is_shortener": lambda v, d: (
        f"The URL uses the link shortener {d}." if v else "The URL is not shortened."),
    "is_ip_hostname": lambda v, d: (
        "The URL uses a raw IP address instead of a hostname."
        if v else "The URL uses a hostname rather than a raw IP."),
    "has_userinfo": lambda v, d: (
        f"The URL embeds '{d}@' before the real hostname, a classic way to make a link "
        "look like it points somewhere else."
        if v else "The URL contains no embedded userinfo."),
    "domain_is_punycode": lambda v, d: (
        "The domain is punycode-encoded, which can render as look-alike characters."
        if v else "The domain is not punycode-encoded."),
    "lure_word_count": lambda v, d: (
        f"The path contains {int(v)} urgency/credential {_plural(v, 'word', 'words')} ({d})."
        if v else "The path contains no credential-related keywords."),
    "domain_length": lambda v, d: f"The registrable domain is {int(v)} characters long.",
    "num_hyphens_domain": lambda v, d: (
        f"The domain contains {int(v)} {_plural(v, 'hyphen', 'hyphens')}." if v else
        "The domain contains no hyphens."),
}


# What each scored signal is, in words, for when it could not be measured.
# "domain age days could not be determined" was the column name with its
# underscores removed, shown to people who have never seen the column.
UNMEASURED: dict[str, str] = {
    "foreign_asset_ratio": "How much of the page loads from other websites",
    "brand_cdn_asset_ratio": "Whether the page loads pictures from a known brand's servers",
    "dead_anchor_ratio": "How many of the page's links go nowhere",
    "obfuscation_score": "Whether the page's scripts are disguised",
    "favicon_brand_impersonation": "Whether the site's icon is copied from a brand",
    "has_password_input": "Whether the page asks for a password",
    "form_action_cross_domain": "Where the page's forms send what is typed",
    "form_action_insecure": "Whether the page's forms send data unencrypted",
    "title_domain_mismatch": "Whether the page's title names another company",
    "hidden_iframe_count": "Whether the page hides embedded frames",
    "external_link_ratio": "How many links point to other websites",
    "script_count": "How many scripts the page runs",
    "render_empty": "Whether the page is an empty shell filled in by scripts",
    "domain_age_days": "How long ago the website's name was registered",
    "registrar_privacy": "Whether the owner's details are hidden",
    "has_mx": "Whether the website's name can receive email",
    "low_ttl": "How often the website's address records change",
    "a_record_count": "How many server addresses the name points to",
    "exfil_endpoint": "Whether typed details are sent to a messaging service",
    "sensitive_field_count": "What kinds of personal details the page asks for",
    "kit_marker_count": "Whether the page carries phishing-kit traces",
    "fetch_blocked": "Whether the site refused to show the page",
    "typosquat_distance": "How close the name is to a known brand",
}


def describe(name: str, fs: FeatureSet) -> str:
    """One sentence for one feature, or a readable fallback."""
    pretty = name.replace("_", " ")
    if name not in fs or not fs[name].present:
        what = UNMEASURED.get(name)
        return f"{what} could not be checked." if what else f"{pretty} could not be determined."
    feat = fs[name]
    if (name == "favicon_brand_impersonation" and feat.value
            and "favicon_on_owner_domain" in fs and fs["favicon_on_owner_domain"].value):
        # The model still weighs the icon match; the sentence must not claim a
        # copy when the icon is on its owner's own domain.
        return f"The page serves {feat.detail}'s favicon on one of {feat.detail}'s own domains."
    tmpl = TEMPLATES.get(name)
    if tmpl is None:
        return f"{pretty} = {feat.value:g}" + (f" ({feat.detail})" if feat.detail else "")
    try:
        return tmpl(feat.value, feat.detail)
    except Exception:  # noqa: BLE001 - a broken template must not break a scan
        return f"{pretty} = {feat.value:g}"


# Below this magnitude a contribution is numerical noise rather than evidence.
_NEGLIGIBLE = 1e-9


def rank(contributions: dict[str, float], fs: FeatureSet, top: int = 5) -> list[Reason]:
    """Top contributors by magnitude, both directions.

    Showing only the incriminating features would make every verdict read as
    guilty. The negatives are what make a low score legible.
    """
    ordered = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    picked = [kv for kv in ordered if abs(kv[1]) > _NEGLIGIBLE][:top]

    # Guarantee at least one counterweight when one exists.
    if picked and all(v > 0 for _, v in picked):
        counterweight = next((kv for kv in ordered if kv[1] < -_NEGLIGIBLE), None)
    elif picked and all(v < 0 for _, v in picked):
        counterweight = next((kv for kv in ordered if kv[1] > _NEGLIGIBLE), None)
    else:
        counterweight = None
    if counterweight:
        picked.append(counterweight)

    return [
        Reason(rank=i + 1, text=describe(name, fs), feature=name,
               contribution=value, toward_phishing=value > 0)
        for i, (name, value) in enumerate(picked)
    ]
