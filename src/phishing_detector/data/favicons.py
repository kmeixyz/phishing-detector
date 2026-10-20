"""Reference favicon hashes for the brand list.

A page serving PayPal's exact favicon bytes from an unrelated domain is close
to conclusive: it is what happens when someone saves the real login page and
re-hosts it. This is a precision signal, which is the scarce kind here.

Exact SHA-256 over the icon bytes, deliberately. A perceptual hash would also
catch resized or recompressed copies and is the obvious upgrade, but exact
matching covers the dominant case (a byte-identical copy) with no image
dependency and no false matches between visually similar icons.

Only the brands with a known canonical domain are fetched, one request each,
using the icon the page itself declares and falling back to the conventional
/favicon.ico that every browser requests unprompted.

    python -m phishing_detector.data.favicons --build
"""

from __future__ import annotations

import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from bs4 import BeautifulSoup

from ..config import CORPUS, ENVELOPE
from ..features.brands import load as load_brands
from ..netguard import BlockedAddress, guarded_client, guarded_stream

FAVICON_DB = CORPUS / "favicon_hashes.json"
TIMEOUT = httpx.Timeout(12.0, connect=6.0)
MAX_ICON_BYTES = 512 * 1024
# Enough of a homepage to reach its <link rel=icon>; the rest is not read.
MAX_PAGE_BYTES = 2 * 1024 * 1024


def icon_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def declared_icon(html: str, base: str) -> str | None:
    """The icon the page declares, absolute, or None if it declares none.

    Shared with the scan-time favicon collector, which reads the same <link>
    from a page it has already fetched.
    """
    if not html:
        return None
    soup = BeautifulSoup(html, "lxml")
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel and link.get("href"):
            try:
                return str(httpx.URL(base).join(link["href"]))
            except ValueError:
                continue
    return None


def _declared_icon(client: httpx.Client, base: str) -> str | None:
    """Fetch a brand's homepage and read the icon it declares.

    Brand homepages redirect constantly (`paypal.com` -> `www.paypal.com`), so
    this has to follow them -- but through `guarded_stream`, which re-checks the
    address at every hop rather than trusting the first one.
    """
    body = b""
    try:
        with guarded_stream(client, base) as r:
            if r.status_code != 200:
                return None
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_PAGE_BYTES:
                    break
    except (BlockedAddress, httpx.HTTPError):
        return None
    return declared_icon(body.decode("utf-8", "replace"), str(r.url))


def _fetch_icon(domain: str) -> tuple[str, str] | None:
    """Hash the icon a brand serves, over a verified connection.

    These hashes are the reference the impersonation check is measured against,
    so whoever chooses these bytes chooses what counts as "really PayPal".
    Unlike the scan-time collectors -- which tolerate broken chains because the
    hostile page still has to be read -- every host reached here is a
    well-configured brand, so verification stays on and a host that fails it is
    skipped rather than trusted.
    """
    base = f"https://{domain}/"
    with guarded_client(timeout=TIMEOUT, follow_redirects=False, verify=True,
                        headers={"User-Agent": ENVELOPE.user_agent}) as client:
        for candidate in (_declared_icon(client, base), f"{base}favicon.ico"):
            if not candidate:
                continue
            content, oversize = b"", False
            try:
                # The declared icon comes out of fetched HTML, so it names an
                # address this build did not choose -- and a redirect on it
                # names another. Every hop is checked, not just the first.
                with guarded_stream(client, candidate) as r:
                    if r.status_code != 200:
                        continue
                    for chunk in r.iter_bytes():
                        content += chunk
                        if len(content) > MAX_ICON_BYTES:
                            oversize = True
                            break
            except (BlockedAddress, httpx.HTTPError):
                continue
            if content and not oversize:
                return domain, icon_hash(content)
    return None


def build(workers: int = 12) -> dict:
    brands = {label: dom for label, dom in load_brands().items() if dom}
    db: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fetch_icon, dom): label for label, dom in brands.items()}
        for fut in as_completed(futures):
            label = futures[fut]
            try:
                got = fut.result()
            except Exception:  # noqa: BLE001
                continue
            if got:
                _, digest = got
                # hash -> brand label, the direction lookups need
                db[digest] = label

    FAVICON_DB.write_text(json.dumps(db, indent=0, sort_keys=True), encoding="utf-8")
    return {"brands_with_domain": len(brands), "icons_hashed": len(db),
            "path": str(FAVICON_DB)}


def load() -> dict[str, str]:
    if not FAVICON_DB.exists():
        return {}
    try:
        return json.loads(FAVICON_DB.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the reference favicon hash database.")
    ap.add_argument("--build", action="store_true")
    args = ap.parse_args()
    if not args.build:
        print(json.dumps({"loaded": len(load())}, indent=2))
        return
    print(json.dumps(build(), indent=2))


if __name__ == "__main__":
    main()
