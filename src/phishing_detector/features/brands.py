"""The brand list used for typosquat distance and brand-position checks.

Built from data rather than typed out by hand: the registrable domains at the
head of the Tranco ranking, plus a small seed of names that are phished far
more often than their traffic rank would suggest (regional banks, delivery
firms, tax offices). The seed exists because popularity and phishing appeal
are different distributions — nobody visits their national tax portal daily,
but everyone falls for a letter from it.

Regenerate after a Tranco refresh:

    python -m phishing_detector.features.brands --build
"""

from __future__ import annotations

import argparse
import json
from functools import lru_cache

import tldextract

from ..config import CORPUS
from ..data import store
from ..urls import parse

BRANDS_PATH = CORPUS / "brands.json"
# A brand's other registrable domains: its name on another suffix, ranked in
# Tranco's top REGIONAL_RANK. brands.json holds one domain per brand, so
# hsbc.co.uk, dhl.de and amazon.de all read as "the brand's name on the wrong
# suffix" -- the shape of a kit -- and registration age could not rescue them
# where the registry publishes no dates. A name in the global top 100,000 is
# the brand's regional site, not a kit that registered it last week.
REGIONAL_PATH = CORPUS / "brand_regional.json"
REGIONAL_RANK = 100_000

# Heavily impersonated, independent of traffic rank.
SEED_BRANDS: tuple[str, ...] = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "dropbox", "adobe", "docusign", "coinbase", "binance", "metamask",
    "blockchain", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "barclays", "lloydsbank", "natwest", "santander", "revolut", "monzo", "n26",
    "scotiabank", "rbc", "tdcanadatrust", "desjardins", "usaa", "capitalone",
    "americanexpress", "discover", "visa", "mastercard", "stripe", "wise",
    "westernunion", "zelle", "venmo", "cashapp", "dhl", "fedex", "ups", "usps",
    "royalmail", "canadapost", "auspost", "correos", "poste", "hermes", "evri",
    "irs", "hmrc", "gov", "cra", "ato", "steam", "epicgames", "roblox", "discord",
    "twitch", "spotify", "hulu", "disneyplus", "ebay", "etsy", "shopify",
    "alibaba", "aliexpress", "walmart", "target", "costco", "bestbuy", "att",
    "verizon", "tmobile", "vodafone", "orange", "telstra", "comcast", "xfinity",
    "sparkasse", "postbank", "ing", "rabobank", "bbva", "unicredit",
)

# Where the seed brands actually live, for the ones the Tranco head does not
# reach. Banks, couriers and card networks are heavily impersonated and rarely
# in the top 600 by traffic, so the build below found no canonical domain for
# 66 of them -- and with none, the real bankofamerica.com read as "0 edits
# from bankofamerica" and tripped the typosquat rule, the same failure google
# once had before it was taken from Tranco. A Tranco row still wins when it
# exists; this fills the blanks. Brands with no single domain carrying their
# name (Steam, Zelle, OneDrive, T-Mobile, the tax offices) stay blank.
SEED_DOMAINS: dict[str, str] = {
    "americanexpress": "americanexpress.com",
    "ato": "ato.gov.au",
    "auspost": "auspost.com.au",
    "bankofamerica": "bankofamerica.com",
    "barclays": "barclays.co.uk",
    "bbva": "bbva.com",
    "bestbuy": "bestbuy.com",
    "binance": "binance.com",
    "blockchain": "blockchain.com",
    "canadapost": "canadapost-postescanada.ca",
    "capitalone": "capitalone.com",
    "cashapp": "cash.app",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "coinbase": "coinbase.com",
    "correos": "correos.es",
    "costco": "costco.com",
    "desjardins": "desjardins.com",
    "dhl": "dhl.com",
    "discover": "discover.com",
    "disneyplus": "disneyplus.com",
    "docusign": "docusign.com",
    "evri": "evri.com",
    "fedex": "fedex.com",
    "hermes": "hermes.com",
    "hsbc": "hsbc.com",
    "hulu": "hulu.com",
    "ing": "ing.com",
    "irs": "irs.gov",
    "lloydsbank": "lloydsbank.com",
    "mastercard": "mastercard.com",
    "metamask": "metamask.io",
    "monzo": "monzo.com",
    "n26": "n26.com",
    "natwest": "natwest.com",
    "orange": "orange.fr",
    "postbank": "postbank.de",
    "poste": "poste.it",
    "rabobank": "rabobank.nl",
    "rbc": "rbc.com",
    "revolut": "revolut.com",
    "royalmail": "royalmail.com",
    "santander": "santander.com",
    "scotiabank": "scotiabank.com",
    "sparkasse": "sparkasse.de",
    "tdcanadatrust": "tdcanadatrust.com",
    "telstra": "telstra.com.au",
    "unicredit": "unicredit.it",
    "ups": "ups.com",
    "usaa": "usaa.com",
    "usps": "usps.com",
    "venmo": "venmo.com",
    "verizon": "verizon.com",
    "visa": "visa.com",
    "vodafone": "vodafone.com",
    "wellsfargo": "wellsfargo.com",
    "westernunion": "westernunion.com",
    "wise": "wise.com",
    "xfinity": "xfinity.com",
}

# Registrable domains that are infrastructure or ad-tech rather than brands.
#
# These rank highly because browsers fetch them, not because people type them,
# and a phisher has no reason to impersonate one. Left in the list they are
# actively harmful: any legitimate domain sitting one edit away from "adnxs"
# or "3lift" would be scored as a typosquat of it.
_INFRA_HINTS = (
    # CDN / cloud / DNS
    "cloudfront", "akamai", "akadns", "akam", "fastly", "cloudflare", "amazonaws",
    "azureedge", "azurewebsites", "windowsazure", "googleusercontent", "gstatic",
    "googleapis", "googlesyndication", "gvt1", "gvt2", "aaplimg", "edgekey",
    "edgesuite", "llnwd", "cachefly", "stackpath", "jsdelivr", "unpkg", "cdn",
    "hwcdn", "cdn77", "bunnycdn", "sharethis",
    # ad tech / analytics / tracking
    "doubleclick", "adnxs", "adsrvr", "adsafeprotected", "adtrafficquality",
    "adriver", "addtoany", "aboutads", "2mdn", "360yield", "3lift", "adform",
    "criteo", "pubmatic", "rubiconproject", "openx", "taboola", "outbrain",
    "yieldmo", "smartadserver", "casalemedia", "bidswitch", "moatads",
    "scorecardresearch", "quantserve", "chartbeat", "newrelic", "segment",
    "mixpanel", "amplitude", "hotjar", "optimizely", "branch", "appsflyer",
    "adjust", "onetrust", "cookielaw", "trustarc", "demdex", "omtrdc",
    "adobedtm", "adobedc", "everesttech", "rlcdn", "crwdcntrl", "agkn",
    "bluekai", "exelator", "mathtag", "turn", "tapad", "eyeota", "adsymptotic",
    # telco / standards infrastructure
    "3gppnetwork", "gpp", "ipv6", "in-addr", "arpa", "root-servers",
)

# Ad-tech names cluster around these tokens even when the full string differs.
_INFRA_PREFIXES = ("ad", "ads", "adserv", "trk", "px", "pixel")

# Hyphen- or suffix-delimited tokens that mark a machine endpoint. "apple" is a
# brand; "apple-dns" is the resolver behind it and nobody phishes with it.
_INFRA_TOKENS = frozenset({
    "dns", "cdn", "api", "apis", "static", "assets", "analytics", "measurement",
    "adsystem", "trust", "telemetry", "metrics", "push", "sync", "cert", "ocsp",
    "crl", "ntp", "edge", "origin", "cache", "proxy", "gateway", "services",
    "service", "sdk", "log", "logs", "beacon", "collector", "ingest",
})
_INFRA_SUFFIXES = ("dns", "cdn", "cs", "api", "cloud", "aws", "sslb")


def _sld(domain: str) -> str:
    """Second-level label of the registrable domain, e.g. paypal.co.uk -> paypal."""
    return tldextract.extract(domain).domain.lower()


def build(top_n: int = 600) -> dict[str, str]:
    """Take the head of Tranco, strip infrastructure, union with the seed."""
    with store.connect() as conn:
        rows = conn.execute(
            """
            SELECT domain FROM tranco_ranks
            WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM tranco_ranks)
            ORDER BY rank ASC LIMIT ?
            """,
            (top_n,),
        ).fetchall()

    brands: dict[str, str] = {b: "" for b in SEED_BRANDS}
    for r in rows:
        sld = _sld(r["domain"])
        if sld in brands and brands[sld]:
            continue  # already have a canonical domain for this label
        if sld in SEED_BRANDS:
            # A seed brand that also appears in the Tranco head: take the
            # canonical domain and keep going. Skipping these left google,
            # paypal, apple and 94 others with no canonical domain at all,
            # so `is_known_brand_domain` could never fire for the brands that
            # matter most — and google.com tripped the typosquat rule instead.
            brands[sld] = r["domain"]
            continue
        if len(sld) < 5:
            continue  # too short for edit distance to carry meaning
        if any(ch.isdigit() for ch in sld):
            continue  # brand names people type rarely contain digits
        if any(h in sld for h in _INFRA_HINTS):
            continue
        if sld.startswith(_INFRA_PREFIXES) and len(sld) <= 9:
            continue
        if set(sld.split("-")) & _INFRA_TOKENS:
            continue
        if sld.endswith(_INFRA_SUFFIXES):
            continue
        # Keep the canonical registrable domain alongside the label. Without
        # it "paypal" cannot be distinguished from "paypal.tk": both have an
        # SLD equal to a brand, but one is PayPal and the other is a phish.
        brands[sld] = r["domain"]

    for label, domain in SEED_DOMAINS.items():
        if label in brands and not brands[label]:
            brands[label] = domain

    BRANDS_PATH.write_text(json.dumps(dict(sorted(brands.items())), indent=0), encoding="utf-8")
    build_regional(brands)
    return brands


def build_regional(brands: dict[str, str]) -> list[str]:
    """Write the brand-named domains on other suffixes that Tranco ranks highly."""
    with store.connect() as conn:
        rows = conn.execute(
            """
            SELECT domain FROM tranco_ranks
            WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM tranco_ranks)
              AND rank <= ?
            """,
            (REGIONAL_RANK,),
        ).fetchall()
    regional = set()
    for r in rows:
        p = parse("https://" + r["domain"] + "/")
        canonical = brands.get(p.domain)
        if canonical is not None and p.registrable != canonical:
            regional.add(p.registrable)
    out = sorted(regional)
    REGIONAL_PATH.write_text(json.dumps(out, indent=0), encoding="utf-8")
    load_regional.cache_clear()
    return out


# Brands that belong to one company, and the domains that company serves them
# from.
#
# Several rules accuse a page of borrowing a brand: its exact favicon, assets
# from its CDN, its name in the title over a password field. Each compares the
# brand with the page's own domain name, so a company with several brands and
# several domains looked like it was impersonating itself: Microsoft's real
# sign-in pages on login.live.com and login.microsoftonline.com were called
# phishing for serving Microsoft's icon, outlook.live.com for Outlook's, and
# accounts.google.com was "not sure" for being titled Gmail. None of those
# comparisons can connect live.com to Microsoft. `is_known_brand_domain`
# cannot either: it recognises a domain only when its name is itself a brand
# key, and "live" as a brand key would put livescore.com under suspicion.
#
# Deliberately absent: domains where the company hosts other people's content
# as a product -- windows.net (Azure storage), azurewebsites.net,
# googleusercontent.com, amazonaws.com -- which are among the commonest
# phishing hosts there are. Hosts on the listed domains that publish strangers'
# pages (forms.office.com, onedrive.live.com, *.sharepoint.com,
# sites.google.com) are excluded by the callers, through `serves_user_content`.
BRAND_OWNERS: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    ("Microsoft", frozenset({"microsoft", "microsoftonline", "office", "office365", "outlook", "onedrive",
                "azure", "skype", "windows", "xboxlive"}),
     frozenset({"microsoft.com", "live.com", "microsoftonline.com", "office.com", "office365.com",
                "outlook.com", "microsoft365.com", "cloud.microsoft", "bing.com", "msn.com",
                "azure.com", "skype.com", "xbox.com", "xboxlive.com", "windows.com"})),
    ("Amazon", frozenset({"amazon", "amazonalexa", "amazontrust", "amazonvideo"}),
     frozenset({"amazon.com", "primevideo.com", "amazontrust.com", "amazonalexa.com"})),
    ("Google", frozenset({"google", "gmail", "googleblog", "googledomains", "youtube"}),
     frozenset({"google.com", "youtube.com", "gmail.com", "blog.google", "domains.google",
                "googleblog.com", "pki.goog"})),
    ("Apple", frozenset({"apple", "icloud", "icloud-content", "mzstatic"}),
     frozenset({"apple.com", "icloud.com", "mzstatic.com"})),
    ("Meta", frozenset({"facebook", "instagram", "whatsapp"}),
     frozenset({"facebook.com", "instagram.com", "whatsapp.com", "whatsapp.net",
                "messenger.com", "meta.com", "fb.com"})),
    # Renamed, not replaced: x.com serves everything from twimg.com, which the
    # CDN rule knows as Twitter's, and read its own sign-in page as a copy.
    ("X (Twitter)", frozenset({"twitter"}),
     frozenset({"twitter.com", "x.com"})),
    # Steam's sign-in on store.steampowered.com loads Valve's own CDN,
    # steamstatic.com, which the CDN rule knows as "steam" -- a different word
    # from "steampowered", so the real page read as a copy of itself.
    ("Valve (Steam)", frozenset({"steam", "steampowered", "steamcommunity"}),
     frozenset({"steampowered.com", "steamcommunity.com", "steamstatic.com",
                "steam-chat.com", "steamgames.com"})),
    # yandex.net sends visitors to ya.ru, Yandex's own short name, which
    # carries Yandex's icon and read as a copy of it.
    ("Yandex", frozenset({"yandex"}),
     frozenset({"yandex.net", "yandex.ru", "yandex.com", "ya.ru"})),
    # The icon table knows VK by its old name; the site has been vk.com for years.
    ("VK", frozenset({"vkontakte", "vkuserphoto"}),
     frozenset({"vk.com", "vk.ru", "vk.me", "vkontakte.ru", "vkontakte.com",
                "vkuserphoto.ru", "userapi.com", "vkuser.net"})),
    ("Telegram", frozenset({"telegram"}),
     frozenset({"telegram.org", "t.me", "telegram.me"})),
    # One company, several icons: Alibaba's home page serves Aliyun's.
    ("Alibaba", frozenset({"alibaba", "aliyun", "aliexpress", "taobao"}),
     frozenset({"alibaba.com", "aliyun.com", "alibabacloud.com", "aliexpress.com",
                "taobao.com", "tmall.com", "1688.com", "alipay.com"})),
    ("AppsFlyer", frozenset({"appsflyer", "onelink"}),
     frozenset({"appsflyer.com", "onelink.me"})),
    ("AMP", frozenset({"ampproject"}),
     frozenset({"ampproject.org", "ampproject.net", "amp.dev"})),
    ("Liftoff", frozenset({"liftoff", "vungle"}),
     frozenset({"liftoff.io", "liftoff.ai", "vungle.com"})),
)


# Link shorteners only the company itself can create links on. A destination
# reached through one was chosen by that company: aka.ms sends visitors to
# Microsoft pages hosted on Azure static sites, with Microsoft's icon, and the
# scanner called Microsoft's own shortener a scam. Open shorteners (bit.ly,
# t.co, lnkd.in) and brands' open redirects carry no such meaning and must
# never be listed here -- anyone can point those anywhere.
COMPANY_SHORTENERS: dict[str, str] = {
    "aka.ms": "Microsoft",
    "g.co": "Google",
    "apple.co": "Apple",
}


def company_labels(company: str) -> frozenset[str]:
    """The brand labels BRAND_OWNERS lists for a company, or empty."""
    for name, labels, _ in BRAND_OWNERS:
        if name == company:
            return labels
    return frozenset()


# Never a company's own page, whatever `brands.json` or the regional list says:
# the canonical domain recorded for "windows" is windows.net, which is Azure
# storage, and icloud-content.com is where shared iCloud files are served.
# These are where the companies host other people's content.
NEVER_OWNED = frozenset({
    "windows.net", "azure.net", "azurewebsites.net", "icloud-content.com",
    "icloud-content.com.cn", "googleusercontent.com", "amazonaws.com", "cloudfront.net",
})


@lru_cache(maxsize=None)
def _owned(labels: frozenset[str], listed: frozenset[str]) -> frozenset[str]:
    """Listed domains, plus each brand's canonical domain and regional variants.

    Cached: both tables are read from disk, and a scan asks once per company.
    """
    known = load()
    regional = load_regional()
    owned = set(listed)
    for label in labels:
        if known.get(label):
            owned.add(known[label])
        owned.update(d for d in regional if d.split(".", 1)[0] == label)
    return frozenset(owned) - NEVER_OWNED


def owner_domains(brand: str) -> frozenset[str]:
    """Every registrable domain the company behind `brand` serves it from.

    A brand with no entry in BRAND_OWNERS owns just its canonical domain and
    its regional variants (amazon.co.uk for amazon).
    """
    for _, labels, listed in BRAND_OWNERS:
        if brand in labels:
            return _owned(labels, listed)
    return _owned(frozenset({brand}), frozenset())


def serves_brand(brand: str, registrable: str) -> bool:
    """Whether a page on `registrable` is served from one of the brand's domains.

    Also the `www.` host of one: a brand whose domain is on the Public Suffix
    List (myfritz.net, where every customer's router gets a name) has its own
    site at `www.myfritz.net`, which the list makes a registrable name of its
    own -- and AVM's icon there read as copied from AVM.
    """
    owned = owner_domains(brand)
    return registrable in owned or (registrable.startswith("www.")
                                    and registrable[4:] in owned & OPERATOR_WWW_SUFFIXES)


# Brand domains on the Public Suffix List whose `www.` name is the operator's
# own and cannot be claimed by a customer. Listed one by one: on a suffix
# where customers choose their names, `www.<suffix>` may be anyone's.
OPERATOR_WWW_SUFFIXES = frozenset({"myfritz.net"})


def owner_brands(registrable: str) -> frozenset[str]:
    """The brands of the company that owns `registrable`, or empty if none listed."""
    return owner_of(registrable)[1]


def owner_of(registrable: str) -> tuple[str, frozenset[str]]:
    """(company, its brands) for a listed company's domain, or ("", empty)."""
    for company, labels, listed in BRAND_OWNERS:
        if registrable in _owned(labels, listed):
            return company, labels
    return "", frozenset()


@lru_cache(maxsize=1)
def load_regional() -> frozenset[str]:
    """Registrable domains that belong to a brand despite not being its canonical one."""
    try:
        raw = json.loads(REGIONAL_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return frozenset()
    return frozenset(raw) if isinstance(raw, list) else frozenset()


def load() -> dict[str, str]:
    """{brand label: canonical registrable domain}. "" when the canonical
    domain is unknown, which is the case for the hand-seeded entries."""
    if BRANDS_PATH.exists():
        try:
            raw = json.loads(BRANDS_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = None
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, list):  # older format
            return {b: "" for b in raw}
    return {b: "" for b in SEED_BRANDS}


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the brand list from the Tranco head.")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--top", type=int, default=600)
    args = ap.parse_args()
    brands = build(args.top) if args.build else load()
    print(f"{len(brands)} brands -> {BRANDS_PATH}")
    known = sum(1 for v in brands.values() if v)
    print(f"{known} with a known canonical domain")
    print(", ".join(list(brands)[:20]) + " ...")


if __name__ == "__main__":
    main()
