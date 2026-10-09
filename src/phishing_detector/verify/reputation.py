"""Google Safe Browsing, as a second opinion.

Configured since the first version and documented as "the reputation
cross-check beside the verdict", but never called: the key was read into
`config.CREDENTIALS` and nothing consumed it. This is the consumer.

It is deliberately not a model feature. The model describes what the scanner
observed; this is what Google has already concluded, and mixing the two would
make the model's numbers unmeasurable. It enters as a *rule* instead: a URL on
Google's social-engineering or malware list is a decisive finding in its own
right, which is exactly the corroboration a kit that hides behind a bot wall
otherwise denies the scanner. Not being listed says nothing -- new kits are
unlisted for hours -- so an empty answer is no evidence either way.

Only the submitted URL is sent, only when a key is configured, and only over
TLS to Google's fixed endpoint; nothing the scanned site controls chooses the
destination. Free for non-commercial use under Google's terms.
"""

from __future__ import annotations

import logging

import httpx

from ..config import CREDENTIALS, ENVELOPE

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ("SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE")
_TIMEOUT = 6.0
_log = logging.getLogger("phishing_detector.reputation")

# Google's names, in words a reader has seen before.
PLAIN = {
    "SOCIAL_ENGINEERING": "phishing or deception",
    "MALWARE": "malware",
    "UNWANTED_SOFTWARE": "unwanted software",
}


def configured() -> bool:
    return bool(CREDENTIALS.google_safe_browsing_key)


def lookup(url: str | list[str], key: str | None = None) -> tuple[bool | None, str]:
    """(listed, detail), for one address or for every address in a redirect chain.

    The chain matters: a clean shortener or open redirect in front of a
    listed kit was checked as the clean address alone.

    `listed` is None when the check did not run or did not answer -- no key,
    no network, a refused request -- so a caller can tell "clean" from
    "unknown". `detail` names the threat types when listed, or why there is
    no answer.
    """
    key = key or CREDENTIALS.google_safe_browsing_key
    if not key:
        return None, "no Safe Browsing key configured"
    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": list(THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in ([url] if isinstance(url, str) else url)],
        },
    }
    try:
        r = httpx.post(ENDPOINT, params={"key": key}, json=body, timeout=_TIMEOUT,
                       headers={"User-Agent": ENVELOPE.user_agent})
    except httpx.HTTPError as exc:
        _log.warning("safe browsing unavailable: %s", type(exc).__name__)
        return None, f"Safe Browsing did not answer ({type(exc).__name__})"
    if r.status_code != 200:
        # The key is the operator's business; a 400 or 403 here is a
        # configuration problem, reported without echoing the response.
        return None, f"Safe Browsing refused the request (HTTP {r.status_code})"
    try:
        matches = r.json().get("matches") or []
    except ValueError:
        return None, "Safe Browsing sent an unreadable answer"
    kinds = sorted({PLAIN.get(m.get("threatType", ""), m.get("threatType", "").lower())
                    for m in matches if m.get("threatType")})
    if kinds:
        return True, ", ".join(kinds)
    return False, "not on Google's lists"
