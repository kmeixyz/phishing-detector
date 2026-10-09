"""URL lexical features. No network access.

This is the fallback tier: it works when the site is already dead, which is
the normal case for a phishing URL pulled from a feed more than a few hours
after it was reported. Every function here is pure, so the whole layer is
testable against string fixtures.
"""

from __future__ import annotations

import json
import re

from rapidfuzz.distance import DamerauLevenshtein

from ..config import MODELS
from ..urls import ParsedURL, decoded_path_query, idna_unicode, parse
from .base import FeatureSet, shannon_entropy
from .brands import NEVER_OWNED, load as load_brands, load_regional
from .user_content import serves_user_content, stranger_controls_host

TLD_RISK_PATH = MODELS / "tld_risk.json"  # fitted artifact, written by model.baseline

# A finite, knowable set — worth hardcoding, unlike a TLD risk list.
SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
    "lnkd.in", "t.ly", "bl.ink", "snip.ly", "shorte.st", "adf.ly", "bc.vc",
    "clck.ru", "v.gd", "qr.ae", "trib.al", "mcaf.ee", "su.pr", "chilp.it",
    "1url.com", "shrtco.de", "urlz.fr", "short.io", "bitly.com", "n9.cl",
    # Added when a disabled surl.li link -- which lands on the service's own
    # home page -- was judged as that home page and called safe.
    "surl.li", "tiny.one", "u.to", "qrco.de", "bit.do", "dub.sh", "short.gy",
    "urlr.me", "t2m.io", "zpr.io", "x.gd", "gg.gg", "cutt.us", "shorturl.gg",
})

# Registries only vetted institutions can register in.
RESTRICTED_SUFFIXES = frozenset({"gov", "mil", "edu", "int"})
# The same, one level down in a country code: gov.uk, ac.uk, edu.au, gouv.fr,
# go.jp, gob.mx, mil.br. Matched on the first label of a two-label suffix.
RESTRICTED_SECOND_LEVEL = frozenset({"gov", "gouv", "gob", "go", "govt", "mil", "ac", "edu"})

# Providers where the customer controls a subdomain but the registration
# belongs to the provider, and which the PSL private section does not list.
CLOUD_HOSTS = frozenset({
    "amazonaws.com", "backblazeb2.com", "azurefd.net", "azureedge.net",
    "azurewebsites.net", "trafficmanager.net", "cloudapp.azure.com",
    "cloudfront.net", "digitaloceanspaces.com", "linodeobjects.com",
    "storage.googleapis.com", "appspot.com", "run.app", "fly.dev",
    "railway.app", "koyeb.app", "deta.app", "cyclic.app", "ondigitalocean.app",
    "b-cdn.net", "r2.dev", "sitey.me", "000webhostapp.com", "temp.swtest.ru",
    "windows.net",   # Azure storage and static websites, *.core.windows.net
    # Tunnels: a laptop's local server published under the service's name. A
    # kit on xqqq.shares.zrok.io inherited zrok.io's registration age and was
    # called "an ordinary website". The PSL already covers some of these; they
    # are listed anyway for a deployment whose bundled snapshot predates that.
    "zrok.io", "loca.lt", "localtunnel.me", "serveo.net", "serveousercontent.com",
    "pinggy.link", "pinggy.online", "devtunnels.ms", "lhr.life", "localhost.run",
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev",
    "tunnelmole.net",
})

# Words that show up in credential-harvest paths far more than elsewhere.
LURE_WORDS = frozenset({
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure",
    "security", "account", "accounts", "update", "confirm", "confirmation",
    "billing", "payment", "invoice", "unlock", "suspended", "limited",
    "recover", "recovery", "reset", "password", "credential", "authenticate",
    "authorize", "validate", "wallet", "refund", "customer", "support",
    "webscr", "cmd", "session", "token", "activate", "restore",
})

_HEX_RUN = re.compile(r"[0-9a-f]{16,}")


def load_tld_risk() -> dict[str, float]:
    """Per-TLD phishing rate learned from the corpus.

    Deliberately not a hardcoded list of "bad TLDs". The risk of a TLD is an
    empirical property of the data you trained on, and it drifts — registries
    change pricing and abuse policy, and last year's dumping ground cleans up.
    Returns {} before the table has been fitted, which makes the feature
    absent rather than wrong.
    """
    if not TLD_RISK_PATH.exists():
        return {}
    try:
        return json.loads(TLD_RISK_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


# Short brand names ("ing", "att", "ato", "cra") are real phishing targets but
# are also common substrings: a plain `"ing" in "billing"` test fires on half
# the web. Anything under this length has to match at a token boundary.
_BOUNDARY_MATCH_BELOW = 5


def _brand_hit(brand: str, hay: str) -> bool:
    if len(brand) >= _BOUNDARY_MATCH_BELOW:
        # Long enough to be meaningful glued to other words, which is itself
        # the common pattern: "paypalverify", "secure-apple-id".
        return brand in hay
    return re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", hay) is not None


def _brand_embedded(p: ParsedURL, brands: dict[str, str]) -> tuple[int, list[str]]:
    """Brand names buried inside the registrable domain itself.

    `paypalverify.ru`, `secure-apple-id.com`, `dhl-parcel-track.top`. This sits
    in the gap between the other two brand features: the keyword is not in the
    "wrong position" (it *is* the registrable domain), and the edit distance to
    the bare brand is far past the typosquat cutoff because of the extra words.
    Without this, that whole family scores zero on brand evidence.
    """
    if not brands:
        return 0, []

    own = p.unicode_domain
    # Same boundary rule as elsewhere: long brands may be glued to other words
    # ("paypalverify"), short ones must be a whole hyphen-delimited token
    # ("dhl-parcel-track" yes, "billing" no).
    hits = [b for b in brands if b != own and _brand_hit(b, own)]
    return len(hits), sorted(hits)


def _brand_positions(p: ParsedURL, brands: dict[str, str]) -> tuple[int, list[str]]:
    """Count brand names appearing anywhere except the registrable domain.

    `paypal.com.secure-login.ru/webscr` scores 1: "paypal" is in the
    subdomain while the registrable domain is `secure-login.ru`. The same
    keyword inside the registrable domain scores 0, because that is what a
    genuine brand domain looks like.
    """
    if not brands:
        return 0, []

    own = p.unicode_domain
    haystacks = [idna_unicode(p.subdomain), decoded_path_query(p)]
    hits: list[str] = []
    for brand in brands:
        if brand == own or brand in own:
            continue  # the real thing, or a legitimate sub-brand
        if any(_brand_hit(brand, hay) for hay in haystacks):
            hits.append(brand)
    return len(hits), sorted(hits)


# Past four edits, "close to a brand" stops meaning anything: unrelated words
# of similar length drift into range and the feature turns into noise.
TYPOSQUAT_CUTOFF = 4


def _max_edits(brand: str) -> int:
    """Edits that still read as a lookalike of `brand`, by its length."""
    if len(brand) <= 3:
        return 0
    if len(brand) <= 5:
        return 1
    return TYPOSQUAT_CUTOFF


def _typosquat(domain: str, brands: dict[str, str]) -> tuple[int | None, str]:
    """Smallest Damerau-Levenshtein distance from the SLD to any brand.

    Catches `paypa1`, `arnazon`, `micros0ft` — transpositions and homoglyph
    substitutions that a substring check misses entirely. Distance 0 means the
    SLD *is* a brand name, which on an unrelated suffix is itself a signal.

    Returns (CUTOFF + 1, "") when nothing lands within range, rather than the
    nearest arbitrary string. Naming a "closest brand" 8 edits away would put
    a meaningless comparison in front of the user.
    """
    if not domain or not brands:
        return None, ""

    best, target = TYPOSQUAT_CUTOFF + 1, ""
    for brand in brands:
        # An edit distance only means something between comparable lengths.
        if abs(len(brand) - len(domain)) > 3:
            continue
        d = DamerauLevenshtein.distance(domain, brand, score_cutoff=TYPOSQUAT_CUTOFF)
        # Nor against a name too short to carry it. One edit turns "rbc" into
        # bbc, nbc and cbc, and "ing" into king: every one of them was read
        # as a lookalike of a seed brand and fired a strong phishing rule.
        # Short brands are still matched exactly -- `ing.tk` is caught as the
        # brand on the wrong suffix -- but not fuzzily.
        if d > _max_edits(brand):
            continue
        if d < best:
            best, target = d, brand
            if d == 0:
                break
    return best, target


def extract(url: str, brands: dict[str, str] | list[str] | None = None,
            tld_risk: dict[str, float] | None = None) -> FeatureSet:
    """All lexical features for one URL."""
    p = parse(url)
    if brands is None:
        brand_set: dict[str, str] = load_brands()
    elif isinstance(brands, dict):
        brand_set = brands
    else:
        brand_set = {b: "" for b in brands}
    risk_table = tld_risk if tld_risk is not None else load_tld_risk()

    f = FeatureSet()
    host, path, query = p.hostname, p.path, p.query
    pq = decoded_path_query(p)

    # --- shape -----------------------------------------------------------
    f.add("url_length", len(p.raw))
    f.add("hostname_length", len(host))
    f.add("path_length", len(path))
    f.add("query_length", len(query))
    f.add("path_depth", sum(1 for seg in path.split("/") if seg))
    f.add("query_param_count", sum(1 for kv in query.split("&") if kv))

    # --- character composition -------------------------------------------
    f.add("num_dots", host.count("."))
    f.add("num_hyphens", host.count("-"))
    digits = sum(ch.isdigit() for ch in host)
    f.add("num_digits_hostname", digits)
    f.add("digit_ratio_hostname", digits / len(host) if host else 0.0)
    f.add("num_digits_path", sum(ch.isdigit() for ch in path))
    f.add("has_hex_run", bool(_HEX_RUN.search(pq)))

    # --- structure --------------------------------------------------------
    labels = p.subdomain_labels
    f.add("subdomain_depth", len(labels))
    f.add("longest_label_length", max((len(x) for x in labels + [p.domain]), default=0))
    f.add("is_ip_hostname", p.is_ip_host)
    f.add("has_port", p.port is not None)
    f.add("scheme_is_https", p.scheme == "https")
    f.add("has_userinfo", bool(p.userinfo), detail=p.userinfo)
    f.add("has_at_symbol", "@" in p.raw)
    f.add("double_slash_in_path", "//" in path)
    f.add("is_punycode", "xn--" in host)

    # --- registrable domain alone -----------------------------------------
    # Scoped to the registrable domain so that a bare domain and a full URL
    # are measured on identical terms. Everything hostname-wide above is
    # contaminated when the benign sample is bare Tranco domains: they have no
    # subdomain, so subdomain_depth and hostname_length separate the classes
    # perfectly for reasons that have nothing to do with phishing.
    dom = p.domain
    dom_digits = sum(ch.isdigit() for ch in dom)
    f.add("domain_length", len(dom))
    f.add("num_hyphens_domain", dom.count("-"))
    f.add("num_digits_domain", dom_digits)
    f.add("digit_ratio_domain", dom_digits / len(dom) if dom else 0.0)
    f.add("domain_token_count", len([t for t in dom.split("-") if t]))
    f.add("domain_is_punycode", dom.startswith("xn--"))

    # --- name plausibility ------------------------------------------------
    f.add("domain_entropy", shannon_entropy(p.domain))
    f.add("hostname_entropy", shannon_entropy(host))

    # Purely a Public Suffix List property, so it belongs here rather than in
    # the network layer: no lookup is needed to know that kit-abc.vercel.app
    # sits on a free subdomain nobody had to register.
    #
    # The PSL private section does not cover every provider — Backblaze,
    # Azure Front Door and plain S3 are not in it — so a hand list fills the
    # gap. Without it `...s3.us-east-005.backblazeb2.com` inherited
    # Backblaze's ten-year registration and was cleared as an established
    # domain.
    provider_hosted = (
        p.on_shared_hosting
        or (p.registrable in CLOUD_HOSTS and len(labels) >= 1)
    )
    f.add("on_shared_hosting", provider_hosted,
          detail=p.hosting_provider or (p.registrable if provider_hosted else ""))
    f.add("is_shortener", p.registrable in SHORTENERS, detail=p.registrable)

    # --- brand relationship -----------------------------------------------
    n_brand, hits = _brand_positions(p, brand_set)
    f.add("brand_in_wrong_position", n_brand, detail=", ".join(hits[:3]))

    n_embed, embed_hits = _brand_embedded(p, brand_set)
    f.add("brand_embedded_in_domain", n_embed, detail=", ".join(embed_hits[:3]))

    # Three distinct situations that a single edit distance cannot separate:
    #
    #   google.com   SLD is a brand AND the canonical domain  -> legitimate
    #   google.tk    SLD is a brand on the WRONG suffix       -> impersonation
    #   googie.com   SLD is one edit from a brand             -> typosquat
    #
    # Collapsing these into "distance 0" made the model score the real
    # google.com at +1.92 toward phishing for being called google.
    # Matched on the decoded label, so the comparison runs on what a reader
    # sees rather than on `xn--`. This is a dictionary lookup, so it catches a
    # brand whose decoded label *is* the brand name; a Cyrillic look-alike is
    # a different string and is caught by `homograph_brand_match`, which
    # compares skeletons rather than exact names.
    canonical = brand_set.get(p.unicode_domain)
    regional = canonical is not None and p.registrable in load_regional()
    is_own_domain = canonical is not None and (canonical == p.registrable or regional)
    wrong_suffix = bool(canonical) and canonical != p.registrable and not regional
    # Where a company hosts other people's content. The name is the brand's --
    # "windows" really does map to windows.net -- but no page there is the
    # company's own, and a kit on an Azure static website was cleared as "the
    # real, official address for windows.net". Still not a look-alike either.
    brand_domain = is_own_domain and p.registrable not in NEVER_OWNED

    f.add("is_known_brand_domain", brand_domain, detail=p.registrable if brand_domain else "")
    # Not a model column. The regional list is built from names alone -- a
    # brand's label on another suffix, ranked in Tranco's top 100,000 -- so
    # it cannot say who owns the name. The rules ask for years of history
    # before trusting one as the brand's own.
    via_regional = is_own_domain and canonical != p.registrable
    f.add("brand_domain_regional", via_regional, detail=p.registrable if via_regional else "")
    f.add("brand_sld_wrong_suffix", wrong_suffix,
          detail=f"{p.registrable} vs {canonical}" if wrong_suffix else "")

    # The registrable domain is the brand's, but the page is not: these hosts
    # publish whatever a stranger uploads. Registration says nothing about the
    # content, so the brand's reputation must not transfer to it.
    user_content = is_own_domain and serves_user_content(p.hostname)
    f.add("user_content_on_brand_domain", user_content,
          detail=p.hostname if user_content else "")
    # The stronger claim: not just "strangers publish somewhere under this
    # name", but "this exact host was handed to one". Only that supports a
    # decisive rule -- on a platform's own apex, its sign-in form lives at a
    # path just as its users' pages do, and the two cannot be told apart here.
    stranger_host = is_own_domain and stranger_controls_host(p.hostname)
    f.add("user_content_stranger_host", stranger_host,
          detail=p.hostname if stranger_host else "")

    dist, target = _typosquat(p.unicode_domain, brand_set)
    if dist is None:
        f.add_missing("typosquat_distance", "no brand list available")
    elif is_own_domain:
        # Distance to itself is 0 and means nothing. Report it as "not a
        # lookalike" so the feature carries one meaning rather than two.
        f.add("typosquat_distance", TYPOSQUAT_CUTOFF + 1, detail="own brand domain")
    else:
        # Only name a brand when the distance actually means something. At 3+
        # edits the "nearest brand" is coincidence, and printing "3 to hermes"
        # beside vercel.app reads as a finding when it is noise.
        near = target and dist <= 2
        f.add("typosquat_distance", dist,
              detail=f"{dist} to {target}" if near else f"{dist}, no near match")

    # Not a model column. A name under a registry that only vetted
    # institutions can register in: nobody can buy a look-alike there, so the
    # name-shape rules (typosquat, a brand on the wrong suffix) do not apply.
    # usa.gov is one edit from the brand "usaa" and was "not sure" for it.
    # What the page does is still judged in full -- government sites are
    # compromised like any other.
    icann = (p.icann_suffix or p.suffix).lower()
    restricted = icann in RESTRICTED_SUFFIXES or (
        "." in icann and icann.split(".", 1)[0] in RESTRICTED_SECOND_LEVEL)
    f.add("restricted_registry", restricted, detail=icann if restricted else "")

    # --- lures -------------------------------------------------------------
    lures = sorted({w for w in LURE_WORDS if w in pq or w in p.subdomain})
    f.add("lure_word_count", len(lures), detail=", ".join(lures[:4]))

    # --- TLD ---------------------------------------------------------------
    # Keyed on the ICANN suffix, never the private one. Tranco lists only
    # registrable ICANN domains, so no legitimate `*.vercel.app` can ever enter
    # the benign set — which made "vercel.app" score 88% phishing purely
    # because nothing benign was able to appear there. A model reading that
    # flags every legitimate site on Vercel, Netlify or GitHub Pages.
    # `.app` at least has sites on both sides.
    if risk_table:
        key = p.icann_suffix or p.suffix
        f.add("tld_risk_score", risk_table.get(key, risk_table.get("__default__", 0.0)),
              detail=key)
    else:
        f.add_missing("tld_risk_score", "risk table not fitted yet")

    return f
