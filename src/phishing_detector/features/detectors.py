"""Targeted detectors for things a generic feature vector misses.

Each is a pure function over evidence already collected. They exist because
they encode specific attacker behaviour rather than generic page statistics,
and several of them are close to unambiguous when they fire.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from urllib.parse import parse_qs, unquote

from bs4 import BeautifulSoup

from ..urls import ParsedURL, parse
from .base import FeatureSet, sanitise_html

# Each family below is a table of (pattern, label) pairs. The label is what the
# report shows, so these two helpers are all the machinery any of them needs.
Rule = tuple[re.Pattern[str], str]


def _compile_rules(patterns: tuple[tuple[str, str], ...]) -> list[Rule]:
    return [(re.compile(p, re.I), label) for p, label in patterns]


def _matching_labels(rules: list[Rule], text: str) -> list[str]:
    """Sorted, de-duplicated labels of every rule that matches."""
    return sorted({label for rx, label in rules if rx.search(text)})


# Attributes a form control carries that say what it is for.
_FIELD_ATTRS = ("name", "id", "placeholder", "aria-label", "autocomplete", "title")


def _visible_soup(html: str) -> BeautifulSoup:
    """The page parsed once, with scripts, styles and templates removed.

    Every reader below needs exactly this, and they once parsed it separately
    -- a full parse of up to 2 MB of markup each per verdict where one does.
    They only read it after this point.
    """
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "template", "noscript", "svg"]):
        tag.decompose()
    return soup


# A shared-document lure: the first page of a kit that asks for an email "to
# open the file" and sends the next one a password page. "Secure Document --
# access your confidential document with a single verified email" on a jobs
# site was "an ordinary website".
_DOCUMENT_LURE = re.compile(
    r"(?i)\b(?:shared|secure|confidential|protected|encrypted|private)\s+"
    r"(?:document|file|pdf|invoice|fax|voicemail|attachment)s?\b"
    r"|\b(?:verify|confirm|enter|use)\s+your\s+(?:e-?mail|email\s+address|work\s+email)\s+"
    r"(?:to|and)\s+(?:view|access|open|download|unlock|continue\s+to)\b")


def _document_lure(soup: BeautifulSoup) -> str:
    """The lure's wording, when the page also has a box for an email or a password."""
    boxes = [c for c in soup.find_all("input")
             if (c.get("type") or "").lower() in ("email", "password")
             or "mail" in (c.get("name") or c.get("id") or "").lower()]
    if not boxes:
        return ""
    found = _DOCUMENT_LURE.search(" ".join(soup.get_text(" ", strip=True).split())[:20_000])
    return found.group(0) if found else ""


def _control_text(controls: list, soup: BeautifulSoup) -> list[str]:
    """What the form controls say they are for: their own attributes, then every label."""
    parts: list[str] = []
    for control in controls:
        for attr in _FIELD_ATTRS:
            value = control.get(attr)
            if value:
                parts.append(value if isinstance(value, str) else " ".join(value))
    for label in soup.find_all("label"):
        parts.append(label.get_text(" ", strip=True))
    return parts


def _field_text(soup: BeautifulSoup) -> str:
    """The page as the person filling it in sees it.

    Form controls' own attributes, their labels, and the visible text, with
    scripts, styles and templates removed first (`_visible_soup`). Kits name
    their fields for what they harvest, and so do real forms, so this is where
    a sensitive field shows; a script's identifiers are where the false
    matches were.
    """
    parts = _control_text(soup.find_all(["input", "select", "textarea", "button"]), soup)
    parts.append(soup.get_text(" ", strip=True))
    return "\n".join(parts)


_SEED_TERMS = re.compile(r"seed.?phrase|mnemonic|recovery.?phrase|private.?key|secret.?phrase", re.I)
_SEED_PROSE = re.compile(r"seed.?phrase|mnemonic|recovery.?phrase|secret.?phrase", re.I)


def _asks_for_seed_phrase(soup: BeautifulSoup) -> bool:
    """Whether the page *asks* for a wallet phrase, not whether it mentions one.

    The rule this feeds is decisive, and it matched the page's prose: auth0.com
    lists "Private Key JWT" in its navigation and was called a scam, as would
    any developer documentation or crypto news page. A kit asks in its fields
    -- the placeholder, the label -- or puts the words beside the box the
    phrase goes into: a textarea, or a row of twelve or more inputs.
    """
    controls = soup.find_all(["input", "textarea", "select"])
    if _SEED_TERMS.search("\n".join(_control_text(controls, soup))):
        return True
    entry = soup.find("textarea") is not None or sum(
        1 for c in controls if c.name == "input"
        and (c.get("type") or "text").lower() in ("text", "password", "")) >= 12
    return entry and bool(_SEED_PROSE.search(soup.get_text(" ", strip=True)))


# --------------------------------------------------------------------------
# 1. Credential exfiltration endpoints
# --------------------------------------------------------------------------
# Kits have to send stolen credentials somewhere, and the cheap options are
# messaging APIs. A login page that talks to the Telegram Bot API is not
# ambiguous — no legitimate sign-in form does this.
EXFIL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"api\.telegram\.org/bot", "Telegram Bot API"),
    (r"discord(?:app)?\.com/api/webhooks", "Discord webhook"),
    (r"hooks\.slack\.com/services", "Slack webhook"),
    (r"api\.mailgun\.net/v\d/", "Mailgun API"),
    (r"formspree\.io/[a-z]", "Formspree"),
    (r"formsubmit\.co/", "FormSubmit"),
    (r"getform\.io/f/", "Getform"),
    (r"api\.web3forms\.com", "Web3Forms"),
    (r"\bsendmail\.php\b|\bmailer\.php\b|\bsend\.php\b", "generic PHP mailer"),
    # A numeric id assigned in code, as a kit's config sets it. The bare word
    # matched a support-chat widget's `chatId: ""` on verizon.com and the
    # vendor host `ls.chatid.com` on walmart.com, and called both a scam.
    (r"(?<![?&#/.\w-])chat_?id[\"']?\s*[:=]\s*[\"'`]?-?\d{5,}", "Telegram chat id"),
)
_EXFIL_RE = _compile_rules(EXFIL_PATTERNS)
# The channels no legitimate page talks to from the browser. The rest -- form
# services, a PHP mailer, a chat id -- are also how ordinary contact forms and
# chat widgets work, so they say "credentials go here" only on a page that
# asks for credentials (see crosscheck: `exfil_endpoint`).
STRONG_EXFIL = frozenset({"Telegram Bot API", "Discord webhook", "Slack webhook", "Mailgun API"})

# --------------------------------------------------------------------------
# 2. Sensitive field harvesting
# --------------------------------------------------------------------------
# A "login" page asking for a card number or an SSN is not a login page.
# Matched against what a person filling the page in would read -- the form
# controls' own names and labels and the visible text -- never the raw markup.
# Run over the whole document, `ssn` found itself inside every `className`
# and "expiration" inside every token-refresh script, so a plain sign-in page
# read as asking for a social security number and a card expiry, and the
# rules that key on those fired on github.com/login.
SENSITIVE_FIELDS: tuple[tuple[str, str], ...] = (
    (r"card.?number|cardno|ccnum|creditcard|cc.?num", "card number"),
    (r"(?<![a-z])cvv(?![a-z])|(?<![a-z])cvc(?![a-z])|security.?code|card.?code", "CVV"),
    # "expiration" alone is session and password prose on any site; a card's
    # is named with a date or a card beside it.
    (r"exp.?(?:date|month|year)|\bexpir(?:y|ation)\W{0,3}(?:date|month|year)|"
     r"\bcard\W{0,3}expir", "card expiry"),
    (r"\bssn\b|social.?security", "SSN"),
    (r"(?<![a-z])sin(?![a-z])|sort.?code|routing.?number|account.?number", "bank details"),
    (r"(?<![a-z])otp(?![a-z])|one.?time|2fa|two.?factor|auth.?code|verification.?code|smscode", "OTP / 2FA code"),
    (r"mother.?maiden|date.?of.?birth|\bdob\b", "identity question"),
    (r"seed.?phrase|mnemonic|recovery.?phrase|private.?key", "wallet seed phrase"),
)
_SENSITIVE_RE = _compile_rules(SENSITIVE_FIELDS)

# --------------------------------------------------------------------------
# 3. Kit and evasion fingerprints
# --------------------------------------------------------------------------
KIT_MARKERS: tuple[tuple[str, str], ...] = (
    (r"antibot|anti.?bot|botdetect", "anti-bot gate"),
    (r"blockBots|isBot\s*\(", "bot filter"),
    (r"document\.addEventListener\(['\"]contextmenu", "right-click block"),
    (r"devtools.?detect|debugger;\s*\}", "devtools evasion"),
    (r"navigator\.webdriver", "automation detection"),
    (r"window\.location\.replace\(atob\(", "obfuscated redirect"),
    (r"crypto-?js|CryptoJS\.AES", "client-side crypto (kit obfuscation)"),
)
_KIT_RE = _compile_rules(KIT_MARKERS)

# --------------------------------------------------------------------------
# 4. IDN homograph mapping
# --------------------------------------------------------------------------
# Cyrillic and Greek look-alikes are the classic homograph attack: `аpple.com`
# with a Cyrillic а renders identically to the real thing. Normalising to a
# "skeleton" lets an exact brand comparison catch it.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ᴏ": "o", "ɡ": "g", "ʏ": "y", "м": "m",
    "н": "h", "т": "t", "в": "b", "к": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "α": "a", "ε": "e", "ι": "i", "κ": "k", "μ": "m", "χ": "x",
    # Letters with no decomposition that NFKD could strip: Turkish dotless ı,
    # Cyrillic palochka, Latin alpha and iota, and the Cyrillic h, j, q, w
    # and g look-alikes. `ıng.com` and `аррӏе.com` went unmatched without them.
    "ı": "i", "ӏ": "l", "ɩ": "i", "ɑ": "a", "һ": "h", "ј": "j",
    "ԛ": "q", "ԝ": "w", "ѡ": "w", "ԍ": "g", "ɵ": "o", "ɛ": "e", "ʟ": "l",
    "1": "l", "0": "o", "5": "s", "3": "e", "4": "a", "7": "t", "@": "a",
    "rn": "m", "vv": "w", "ln": "in",
}


def skeleton(text: str) -> str:
    """Collapse look-alike characters so a homograph compares equal.

    Accents are dropped too: `paypàl` and `nétflix` read as the brand at a
    glance, and a dictionary lookup on the exact label never matched them.
    """
    out = unicodedata.normalize("NFKD", text.lower())
    out = "".join(ch for ch in out if unicodedata.category(ch) != "Mn")
    out = unicodedata.normalize("NFKC", out)
    for src, dst in CONFUSABLES.items():
        out = out.replace(src, dst)
    return out


def _decode_idn(host: str) -> str:
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


# --------------------------------------------------------------------------
# 5. Embedded URLs / open redirect
# --------------------------------------------------------------------------
_EMBEDDED_URL = re.compile(r"(https?%3a%2f%2f|https?://)", re.I)


def _embedded_target(p: ParsedURL) -> str:
    """A full URL sitting in a query parameter, e.g. ?next=https://evil.ru."""
    for values in parse_qs(p.query).values():
        for v in values:
            candidate = unquote(v)
            if candidate.startswith(("http://", "https://")):
                target = parse(candidate)
                if target.registrable and target.registrable != p.registrable:
                    return target.registrable
    return ""


def _decoded_blobs(html: str) -> str:
    """Decode long base64 literals so exfil endpoints hidden in them are seen."""
    out = []
    for blob in re.findall(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", html)[:40]:
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        if decoded.isprintable():
            out.append(decoded)
    return "\n".join(out)


def extract(html: str, page_url: str, brands: dict[str, str] | None = None,
            missing_why: str = "no HTML retrieved") -> FeatureSet:
    html = sanitise_html(html)
    f = FeatureSet()
    p = parse(page_url)
    brand_map = brands or {}

    # ---- URL-level, always available -------------------------------------
    decoded_host = _decode_idn(p.hostname)
    host_skel = skeleton(decoded_host)
    dom_skel = skeleton(_decode_idn(p.domain))

    f.add("idn_decoded_differs", decoded_host != p.hostname, detail=decoded_host)
    f.add("has_non_ascii_host", any(ord(c) > 127 for c in decoded_host))
    # The payoff: skeleton equals a brand, but the actual label does not.
    homograph = dom_skel in brand_map and dom_skel != p.domain
    f.add("homograph_brand_match", homograph,
          detail=f"{p.domain} -> {dom_skel}" if homograph else "")
    f.add("skeleton_differs_from_domain", host_skel != decoded_host.lower())

    embedded = _embedded_target(p)
    f.add("embedded_url_in_query", bool(embedded), detail=embedded)
    f.add("query_contains_encoded_url", bool(_EMBEDDED_URL.search(p.query or "")))

    if not html:
        for n in ("exfil_endpoint", "exfil_channel_count", "exfil_strong_channel",
                  "sensitive_field_count",
                  "asks_for_card", "asks_for_otp", "asks_for_seed_phrase",
                  "kit_marker_count", "b64_hidden_exfil", "document_lure"):
            f.add_missing(n, missing_why)
        return f

    decoded_extra = _decoded_blobs(html)
    combined = html + "\n" + decoded_extra

    # ---- exfiltration -----------------------------------------------------
    channels = _matching_labels(_EXFIL_RE, combined)
    f.add("exfil_endpoint", bool(channels), detail=", ".join(channels[:3]))
    f.add("exfil_channel_count", len(channels))
    # Not a model column.
    strong = [c for c in channels if c in STRONG_EXFIL]
    f.add("exfil_strong_channel", bool(strong), detail=", ".join(strong))
    f.add("b64_hidden_exfil",
          bool(decoded_extra) and any(rx.search(decoded_extra) for rx, _ in _EXFIL_RE),
          detail="exfil endpoint found inside a base64 blob")

    # ---- sensitive fields --------------------------------------------------
    visible = _visible_soup(html)
    found = _matching_labels(_SENSITIVE_RE, _field_text(visible))
    f.add("sensitive_field_count", len(found), detail=", ".join(found[:4]))
    f.add("asks_for_card", any("card" in x or x == "CVV" for x in found))
    f.add("asks_for_otp", "OTP / 2FA code" in found)
    # Its own test, stricter than the count above (a model column, left as
    # fitted): mentioning a private key is not asking for one.
    f.add("asks_for_seed_phrase", _asks_for_seed_phrase(visible))
    # Not a model column; stops a circumstantial "safe" (crosscheck.review).
    lure = _document_lure(visible)
    f.add("document_lure", bool(lure), detail=lure[:60])

    # ---- kit fingerprints ---------------------------------------------------
    kit = _matching_labels(_KIT_RE, combined)
    f.add("kit_marker_count", len(kit), detail=", ".join(kit[:3]))

    return f
