"""Page-structure features. Pure over the evidence bundle's HTML.

The strongest signal in the whole project lives here, and it is
`foreign_asset_ratio`. Building a credential phish usually means saving the
real login page and re-hosting it. The markup gets edited — the form action is
repointed at the attacker's collector — but the images, stylesheets and scripts
are left with absolute URLs pointing back at the brand's own CDN. A page that
loads 21 of its 24 assets from paypalobjects.com while being served from
secure-login-verify.ru is describing itself.

It is not free of false positives: large legitimate organisations serve
assets from a separate domain (wikipedia.org pulls from wikimedia.org, scoring
a foreign-asset ratio of 1.0). That is precisely why this is a weighted
feature and not a rule, and why legitimate login pages have to be represented
in the negative set — otherwise the model never learns the difference between
"assets live on our other domain" and "assets live on the brand we are
impersonating".

No JavaScript is executed to produce any of this. It is parsed markup only,
which means modern client-rendered kits return an almost-empty body — see
`render_empty`, which is itself the signal for that case.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ..urls import browser_join, parse
from .base import FeatureSet, sanitise_html
from .brands import load as load_brands

_OBFUSCATION_MARKERS = (
    "atob(", "eval(", "unescape(", "fromcharcode", "document.write(",
    "\\x", "\\u00", "btoa(",
)
_B64_BLOB = re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]")
_RIGHT_CLICK = re.compile(r"contextmenu|oncontextmenu|return\s+false", re.I)

# Asset hosts that belong to a specific brand's own infrastructure.
#
# `foreign_asset_ratio` cannot carry this signal: it counts assets served from
# any other domain, and large legitimate sites do that constantly —
# wikipedia.org pulls from wikimedia.org. A rule built on it scored 0.717
# precision. What the spec actually describes is narrower and much stronger:
# a page loading assets from *the brand it is impersonating*, which is what
# happens when someone saves a real login page and re-hosts it.
BRAND_CDNS: dict[str, str] = {
    "paypalobjects.com": "paypal",
    "cdn-apple.com": "apple", "apple.com": "apple", "icloud.com": "apple",
    "msftauth.net": "microsoft", "msauth.net": "microsoft",
    "microsoft.com": "microsoft", "office.net": "microsoft", "live.com": "microsoft",
    "media-amazon.com": "amazon", "ssl-images-amazon.com": "amazon",
    "nflxext.com": "netflix", "nflximg.net": "netflix",
    "fbcdn.net": "facebook",
    "twimg.com": "twitter",
    "licdn.com": "linkedin",
    "dropboxstatic.com": "dropbox",
    "coinbase.com": "coinbase",
    "binance.com": "binance",
    "chase.com": "chase", "wellsfargo.com": "wellsfargo",
    "bankofamerica.com": "bankofamerica", "citi.com": "citibank",
    "steamstatic.com": "steam",
    "dhl.com": "dhl", "fedex.com": "fedex", "ups.com": "ups", "usps.com": "usps",
}

# Shared infrastructure that says nothing about identity. Google Fonts alone
# would otherwise mark a large fraction of the web as impersonating Google.
GENERIC_CDNS = frozenset({
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "jsdelivr.net", "unpkg.com", "cloudflare.com", "cdnjs.com", "bootstrapcdn.com",
    "fontawesome.com", "jquery.com", "cloudfront.net", "akamaized.net",
    "typekit.net", "recaptcha.net", "hcaptcha.com", "gravatar.com",
})


# `content` of a refresh, per the HTML standard's parsing rules: a delay, then
# optionally `url=` and the address, quoted or not.
_REFRESH = re.compile(r"""^\s*(\d+)[^;,]*[;,]?\s*(?:url\s*=\s*)?["']?([^"']*)""", re.I)
# A navigation written in script with a literal address. Only matched on pages
# too thin to be anything but a doorway (see `_client_redirect`), because an
# ordinary page assigns `location` in click handlers all the time.
_SCRIPT_NAV = re.compile(
    r"""location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']""")


def _client_redirect(soup, page_url: str, own: str, text_len: int) -> tuple[str, str]:
    """(destination registrable, how) when the page sends its visitor elsewhere.

    The fetch follows HTTP redirects; a browser also follows these, and without
    JavaScript rendering nothing else here does. A one-line meta refresh on an
    aged, mail-enabled domain was scored as that domain -- "Nothing suspicious
    found" -- while every visitor landed on the kit it pointed at. The
    destination is named, not followed: following it would let a kit put a
    refresh to google.com where only the scanner sees it (inside `<noscript>`,
    or behind a script that navigates first) and be judged as Google.
    """
    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").strip().lower() != "refresh":
            continue
        if meta.find_parent(["noscript", "template"]):
            continue    # not honoured by a browser running script
        found = _REFRESH.match(meta.get("content") or "")
        if not found or not found.group(2).strip() or int(found.group(1)) > 30:
            continue
        dest = parse(browser_join(page_url, found.group(2).strip())).registrable
        if dest and dest != own:
            return dest, "meta refresh"
    if text_len < 200 and not soup.find("form"):
        for script in soup.find_all("script"):
            for m in _SCRIPT_NAV.finditer(script.get_text() or ""):
                target = (m.group(1) or m.group(2) or "").strip()
                if not target.lower().startswith(("http://", "https://", "//")):
                    continue
                dest = parse(browser_join(page_url, target)).registrable
                if dest and dest != own:
                    return dest, "script"
    return "", ""


_MASKED = re.compile(r"-webkit-text-security\s*:\s*(?:disc|circle|square)", re.I)
_TEXTUAL = ("", "text", "tel", "number", "search")


def _concealed_password(soup, depth: int = 0) -> str:
    """How a password field is hidden from a count of `type=password`, or "".

    Two ways a kit gets one past every password rule while the victim sees an
    ordinary masked field: a text input styled with `-webkit-text-security`,
    which draws dots exactly as a password field does, and a form inside an
    `<iframe srcdoc>`, whose markup is an attribute value rather than part of
    the page. Not a model column; the rules read it alongside the real field.
    """
    texts = [i for i in soup.find_all("input") if (i.get("type") or "").lower() in _TEXTUAL]
    if any(_MASKED.search(i.get("style") or "") for i in texts):
        return "a text field styled to hide what is typed"
    if texts and any(_MASKED.search(s.get_text() or "") for s in soup.find_all("style")):
        return "a text field styled to hide what is typed"
    if depth < 2:
        for frame in soup.find_all("iframe", srcdoc=True):
            inner = BeautifulSoup(frame["srcdoc"], "lxml")
            if any((i.get("type") or "").lower() == "password" for i in inner.find_all("input")) \
                    or _concealed_password(inner, depth + 1):
                return "a password field inside an inline frame"
    return ""


def _registrable(url: str) -> str:
    try:
        return parse(url).registrable
    except Exception:  # noqa: BLE001
        return ""


def _absolute(value: str) -> bool:
    return value.startswith(("http://", "https://", "//"))


def _with_scheme(value: str, scheme: str) -> str:
    """A protocol-relative URL given the page's own scheme; anything else as-is."""
    return f"{scheme}:{value}" if value.startswith("//") else value


def extract(html: str, page_url: str, brands: list[str] | None = None,
            missing_why: str = "no HTML retrieved") -> FeatureSet:
    f = FeatureSet()
    page = parse(page_url)
    own = page.registrable

    if not html:
        for name in (
            "has_password_input", "input_count", "form_count",
            "form_action_cross_domain", "form_action_insecure", "form_action_empty",
            "anchor_count", "dead_anchor_count", "dead_anchor_ratio",
            "external_link_ratio", "asset_count", "foreign_asset_count",
            "foreign_asset_ratio", "brand_cdn_asset_count", "brand_cdn_asset_ratio",
            "favicon_foreign", "title_domain_mismatch",
            "hidden_iframe_count", "meta_refresh", "script_count",
            "inline_script_bytes", "obfuscation_score", "right_click_disabled",
            "render_empty", "form_posts_over_http", "client_redirect",
            "concealed_password_input",
        ):
            f.add_missing(name, missing_why)
        return f

    html = sanitise_html(html)
    soup = BeautifulSoup(html, "lxml")
    brand_set = set(brands if brands is not None else load_brands())

    # --- forms and credentials -------------------------------------------
    inputs = soup.find_all("input")
    passwords = [i for i in inputs if (i.get("type") or "").lower() == "password"]
    forms = soup.find_all("form")

    cross, insecure, empty, over_http = 0, 0, 0, 0
    for form in forms:
        action = (form.get("action") or "").strip()
        scripted = action.lower().startswith("javascript:")
        if not scripted:
            # Where the browser actually sends it: an empty or relative action
            # posts to this page's own scheme. `form_action_insecure` only ever
            # counted absolute `http://` actions, so a password form on a plain
            # HTTP page posting to itself escaped the rule that exists for it.
            target = browser_join(page_url, action.split("#", 1)[0])
            over_http += target.lower().startswith("http://")
        if not action or action in ("#", "/") or scripted:
            empty += 1
            continue
        if _absolute(action):
            target = _with_scheme(action, page.scheme)
            if _registrable(target) != own:
                cross += 1
            if target.startswith("http://"):
                insecure += 1

    f.add("has_password_input", bool(passwords))
    concealed = "" if passwords else _concealed_password(soup)
    f.add("concealed_password_input", bool(concealed), detail=concealed)
    f.add("input_count", len(inputs))
    f.add("form_count", len(forms))
    f.add("form_action_cross_domain", cross > 0)
    f.add("form_action_insecure", insecure > 0)
    f.add("form_action_empty", empty > 0)
    # Not a model column: the model was fitted on `form_action_insecure` as it
    # is. This is what the rules read.
    f.add("form_posts_over_http", over_http > 0)

    # --- links -------------------------------------------------------------
    anchors = soup.find_all("a")
    hrefs = [(a.get("href") or "").strip() for a in anchors]
    dead = sum(1 for h in hrefs if h in ("", "#") or h.lower().startswith("javascript:"))
    external = sum(1 for h in hrefs if _absolute(h) and _registrable(h) != own)
    f.add("anchor_count", len(anchors))
    f.add("dead_anchor_count", dead)
    f.add("dead_anchor_ratio", dead / len(anchors) if anchors else 0.0,
          detail=f"{dead} of {len(anchors)}")
    f.add("external_link_ratio", external / len(anchors) if anchors else 0.0,
          detail=f"{external} of {len(anchors)}")

    # --- assets: the saved-and-rehosted signature ---------------------------
    assets: list[str] = []
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href"), ("source", "src")):
        for el in soup.find_all(tag):
            v = (el.get(attr) or "").strip()
            if v and _absolute(v):
                assets.append(_with_scheme(v, page.scheme))

    foreign_assets = [a for a in assets if _registrable(a) != own]
    f.add("asset_count", len(assets))
    f.add("foreign_asset_count", len(foreign_assets))
    f.add("foreign_asset_ratio", len(foreign_assets) / len(assets) if assets else 0.0,
          detail=f"{len(foreign_assets)} of {len(assets)}")

    # --- assets from a specific brand's own infrastructure -------------------
    # `own` is a registrable domain ("paypal.com") and BRAND_CDNS values are
    # labels ("paypal"), so comparing them directly never matched — and
    # paypal.com was flagged for loading PayPal's own images, "the signature of
    # a page copied from that brand". Compare against the page's own label, and
    # also treat any host mapping to the same brand as its own.
    own_label = page.domain
    brand_assets: dict[str, int] = {}
    for asset in assets:
        host = _registrable(asset)
        if not host or host == own or host in GENERIC_CDNS:
            continue
        brand = BRAND_CDNS.get(host)
        if not brand:
            continue
        if brand == own_label or BRAND_CDNS.get(own) == brand:
            continue
        brand_assets[brand] = brand_assets.get(brand, 0) + 1

    total_brand_assets = sum(brand_assets.values())
    top_brand = max(brand_assets, key=brand_assets.get) if brand_assets else ""
    f.add("brand_cdn_asset_count", total_brand_assets, detail=top_brand)
    f.add("brand_cdn_asset_ratio",
          total_brand_assets / len(assets) if assets else 0.0,
          detail=f"{total_brand_assets} of {len(assets)} from {top_brand}" if top_brand else "")

    favicon = ""
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel:
            favicon = (link.get("href") or "").strip()
            break
    favicon_host = _registrable(favicon) if favicon else ""
    f.add("favicon_foreign",
          bool(favicon and _absolute(favicon) and favicon_host != own),
          detail=favicon_host if favicon else "same origin or none")

    # --- identity claim vs domain -------------------------------------------
    title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
    claimed = sorted({b for b in brand_set if len(b) >= 5 and b in title and b not in own})
    f.add("title_domain_mismatch", bool(claimed), detail=", ".join(claimed[:3]))

    # --- concealment ---------------------------------------------------------
    iframes = soup.find_all("iframe")
    hidden = 0
    for frame in iframes:
        style = (frame.get("style") or "").lower().replace(" ", "")
        dims = f"{frame.get('width') or ''}x{frame.get('height') or ''}"
        if ("display:none" in style or "visibility:hidden" in style
                or dims in ("0x0", "1x1") or frame.get("hidden") is not None):
            hidden += 1
    f.add("hidden_iframe_count", hidden)
    # Not a model column: a frame can carry another page's form.
    f.add("iframe_count", len(iframes))

    refresh = any(
        (m.get("http-equiv") or "").lower() == "refresh" for m in soup.find_all("meta")
    )
    f.add("meta_refresh", refresh)

    # --- script character -----------------------------------------------------
    scripts = soup.find_all("script")
    inline = "".join(s.get_text() or "" for s in scripts)
    low = inline.lower()
    markers = sum(1 for m in _OBFUSCATION_MARKERS if m in low)
    blobs = len(_B64_BLOB.findall(inline))

    f.add("script_count", len(scripts))
    f.add("inline_script_bytes", len(inline))
    # Bounded 0-1 so the value stays comparable across page sizes.
    f.add("obfuscation_score",
          min((markers / len(_OBFUSCATION_MARKERS)) * 0.6 + min(blobs, 4) / 4 * 0.4, 1.0),
          detail=f"{markers} marker(s), {blobs} base64 blob(s)")
    f.add("right_click_disabled", bool(_RIGHT_CLICK.search(inline)))

    # Client-rendered kits return almost nothing to a plain fetch. Worth
    # knowing, because every other content feature above is then near-zero for
    # reasons that have nothing to do with the page being safe.
    text_len = len(soup.get_text(strip=True))
    f.add("render_empty", text_len < 200 and len(scripts) > 0,
          detail=f"{text_len} chars of visible text")

    dest, how = _client_redirect(soup, page_url, own, text_len)
    f.add("client_redirect", bool(dest), detail=f"{dest} ({how})" if dest else "")

    return f
