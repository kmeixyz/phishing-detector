"""Sub-collector contract and the evidence bundle.

Every sub-collector returns a result rather than raising. A phishing domain
that has already been taken down will fail DNS, TLS, HTTP and RDAP all at
once, and that run still has to produce a scored verdict from whatever came
back. Failure is data: `whois_lookup_failed` is a feature.

The bundle is cached to disk keyed by URL hash. Feature extraction gets
re-run hundreds of times during development and must never re-hit a WHOIS
server to do it.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import ENVELOPE, cache_dir, stateless, store_pages
from ..urls import ParsedURL, parse

_log = logging.getLogger("phishing_detector.cache")

OK = "ok"
FAILED = "failed"
TIMEOUT = "timeout"
SKIPPED = "skipped"
# The detail of a source whose answer scoring could not read (score_bundle).
UNREADABLE = "its reply could not be read"


@dataclass
class CollectorResult:
    name: str
    status: str = OK
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    elapsed_s: float = 0.0
    # The source answered, and the answer was "nothing there": no certificate
    # on a plain-http URL, no MX for the name, no favicon, no RDAP record.
    # Still FAILED as far as the features go -- the model was trained with
    # these absent -- but it is evidence, not missing evidence, and coverage
    # must not count it as a source that did not answer. Counting it that way
    # withheld verdicts on exactly the profile a kit has: plain http, no mail,
    # a free subdomain, no icon.
    conclusive: bool = False

    def __post_init__(self) -> None:
        """A result is used as-is everywhere, so it is made well-formed here.

        Every collector builds one correctly, but a cached bundle is read back
        from disk, and a hand-edited or half-written one carried `data` as a
        list or a status nobody handles; the scan then failed outright instead
        of counting one source as failed.
        """
        if not isinstance(self.data, dict):
            self.data = {}
            self.status, self.detail = FAILED, "malformed result"
        if self.status not in (OK, FAILED, TIMEOUT, SKIPPED):
            self.status = FAILED
        self.detail = "" if self.detail is None else str(self.detail)
        try:
            self.elapsed_s = float(self.elapsed_s)
        except (TypeError, ValueError):
            self.elapsed_s = 0.0
        self.conclusive = bool(self.conclusive)

    @property
    def ok(self) -> bool:
        return self.status == OK

    @property
    def answered(self) -> bool:
        return self.status == OK or (self.status == FAILED and self.conclusive)


@dataclass
class EvidenceBundle:
    url: str
    url_hash: str
    collected_at: str
    results: dict[str, CollectorResult] = field(default_factory=dict)
    envelope: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    # -- access ---------------------------------------------------------
    def get(self, name: str) -> CollectorResult:
        return self.results.get(name, CollectorResult(name=name, status=FAILED, detail="not run"))

    def data(self, name: str) -> dict:
        r = self.results.get(name)
        return r.data if r and r.ok else {}

    @property
    def parsed(self) -> ParsedURL:
        return parse(self.url)

    def coverage(self) -> tuple[int, int]:
        """(returned, attempted), excluding steps skipped by design.

        "WHOIS fallback: not needed, RDAP answered" is a success path, not a
        gap in the evidence. Counting it against coverage reported a complete
        scan as "6 of 8" and made the run look degraded when nothing was.
        """
        attempted = [r for r in self.results.values() if r.status != SKIPPED]
        return sum(1 for r in attempted if r.answered), len(attempted)

    def skipped(self) -> list[str]:
        return [r.name for r in self.results.values() if r.status == SKIPPED]

    # -- serialisation --------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "url_hash": self.url_hash,
            "collected_at": self.collected_at,
            "envelope": self.envelope,
            "results": {k: asdict(v) for k, v in self.results.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceBundle":
        return cls(
            url=d["url"],
            url_hash=d["url_hash"],
            collected_at=d["collected_at"],
            envelope=d.get("envelope", {}),
            results={k: CollectorResult(**v) for k, v in d.get("results", {}).items()},
        )

    # -- cache ----------------------------------------------------------
    def cache_path(self):
        return cache_dir() / f"{self.url_hash}.json"

    def save(self) -> None:
        """Write the bundle, minus the page itself when storing is disabled.

        Under PHISHING_DETECTOR_NO_STORE the fetched HTML is dropped before writing, so
        the cache keeps collector results and timings but no attacker-controlled
        content. Features have already been extracted from it in memory.

        A stateless instance writes nothing at all: the bundle still carries
        the submitted URL, and "the server keeps no record of what you checked"
        has to be literally true there.
        """
        if stateless():
            return
        doc = self.to_dict()
        if not store_pages():
            for name in ("HTTP chain", "JS render"):
                data = doc.get("results", {}).get(name, {}).get("data")
                if isinstance(data, dict) and data.get("html"):
                    data["html"] = ""
                    data["html_discarded"] = True
        # The cache is a convenience. A read-only or full disk used to raise
        # here, after every collector had answered, and the scan was lost.
        try:
            self.cache_path().write_text(
                json.dumps(doc, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            _log.warning("evidence cache not written", exc_info=True)
            return
        _prune_cache()

    def size_bytes(self) -> int:
        if stateless():
            return 0
        try:
            p = self.cache_path()
            return p.stat().st_size if p.exists() else 0
        except OSError:
            return 0


# The cache had no bound at all. On a public instance the URLs are chosen by
# whoever is calling, at whatever rate the limiter allows, and `data/` is the
# service's only writable path -- so an unbounded cache is a way to fill the
# disk out from under the database.
MAX_CACHE_BUNDLES = 5_000


def _prune_cache(limit: int = MAX_CACHE_BUNDLES) -> int:
    """Drop the oldest bundles once the cache exceeds `limit`. Returns how many.

    Oldest by modification time, which is last-write rather than last-read, so a
    URL that keeps being rescanned keeps its place. Cheap enough to run after a
    write: it stats the directory only when the count is over.
    """
    try:
        paths = list(cache_dir().glob("*.json"))
        if len(paths) <= limit:
            return 0
        paths.sort(key=lambda p: p.stat().st_mtime)
        doomed = paths[: len(paths) - limit]
        for path in doomed:
            path.unlink(missing_ok=True)
        return len(doomed)
    except OSError:
        # Housekeeping must never take a scan down with it.
        return 0


def new_bundle(url: str) -> EvidenceBundle:
    p = parse(url)
    return EvidenceBundle(
        url=p.raw,
        url_hash=p.hash(),
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        envelope=dict(ENVELOPE.as_rows()),
    )


def load_cached(url: str) -> EvidenceBundle | None:
    if stateless():
        return None
    try:
        path = cache_dir() / f"{parse(url).hash()}.json"
        if not path.exists():
            return None
        b = EvidenceBundle.from_dict(json.loads(path.read_text(encoding="utf-8")))
        b.from_cache = True
        return b
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Unreadable, half-written or hand-edited: collect afresh instead.
        return None


class timed:
    """Context manager recording elapsed seconds onto a CollectorResult."""

    def __init__(self, result: CollectorResult):
        self.result = result

    def __enter__(self) -> CollectorResult:
        self._t0 = time.monotonic()
        return self.result

    def __exit__(self, *exc) -> bool:
        self.result.elapsed_s = round(time.monotonic() - self._t0, 3)
        return False


class RateLimiter:
    """Thread-safe pacing. RDAP, WHOIS and CT operators will ban you without it.

    The lock is not decoration. The previous version read and wrote `_last`
    without one, so concurrent callers all observed the same stale timestamp
    and passed through together: eight threads through a 2 req/s limiter
    completed in 0.51s instead of 3.5s. Every caller here is in a thread pool —
    the scan orchestrator, batch scanning, the corpus collectors — so the
    limiter was effectively absent exactly when it mattered, which is how this
    project got its IP refused by index.commoncrawl.org.

    Slots are reserved under the lock and slept for outside it, so threads
    queue rather than serialising on the sleep itself.

    A scan waits at most `max_wait` for its slot, and takes none if it cannot
    have one in time. The limiters are shared by the whole process, so without
    that bound a handful of callers could queue every later scan past its
    budget -- and WHOIS, which runs on the request thread, until the platform
    killed the request.
    """

    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._next_at = 0.0
        self._lock = threading.Lock()

    def wait(self, max_wait: float | None = None) -> bool:
        """Sleep until this caller's slot. False, without a slot, if too far off."""
        if self.interval <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_at)
            if max_wait is not None and slot - now > max_wait:
                return False
            self._next_at = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)
        return True


class BodyRefused(httpx.DecodingError):
    """A response body this scanner will not decode."""


# Content codings `read_capped` decodes itself. httpx advertises exactly these
# when no brotli or zstd package is installed, which is the case here.
_CODINGS = {"gzip": zlib.MAX_WBITS | 16, "x-gzip": zlib.MAX_WBITS | 16, "deflate": zlib.MAX_WBITS}


def read_capped(response: httpx.Response, cap: int) -> tuple[bytes, int, bool]:
    """At most `cap` decoded bytes of the body. Returns (bytes, total, truncated).

    The cap has to apply to what decompression produces, not to what arrives.
    httpx's `iter_bytes` decodes each network read in one unbounded call and
    stacks one decoder per listed coding, so `Content-Encoding: gzip, gzip`
    turned 590 bytes on the wire into a single 256 MiB chunk before any size
    check ran -- and a few KB more is past the function's memory. So the raw
    bytes are read here and decompressed with `max_length`, and more than one
    coding, or one this does not decode, is refused rather than guessed at: no
    browser-compatible server needs to send either to a client that did not
    ask for them.
    """
    if response.is_stream_consumed:
        # Already read in full by whoever built it -- a response constructed
        # from bytes, never one streamed off the network.
        body = response.content
        return body[:cap], len(body), len(body) >= cap
    codings = [c.strip().lower() for c in response.headers.get("content-encoding", "").split(",")]
    codings = [c for c in codings if c and c != "identity"]
    if len(codings) > 1 or (codings and codings[0] not in _CODINGS):
        raise BodyRefused(f"unsupported content-encoding: {', '.join(codings)[:60]}",
                          request=response._request)
    wbits = _CODINGS[codings[0]] if codings else None
    decoder = zlib.decompressobj(wbits) if wbits is not None else None

    out: list[bytes] = []
    total = raw_total = 0
    started = False
    for raw in response.iter_raw():
        raw_total += len(raw)
        if decoder is None:
            piece = raw
        else:
            piece = b""
            data = raw
            while data and total + len(piece) < cap:
                try:
                    piece += decoder.decompress(data, cap - total - len(piece))
                except zlib.error:
                    # Some servers send raw deflate under "deflate"; browsers
                    # accept it, so the first chunk may retry that way.
                    if started or wbits != zlib.MAX_WBITS:
                        raise BodyRefused("undecodable body", request=response._request) from None
                    wbits = -zlib.MAX_WBITS
                    decoder = zlib.decompressobj(wbits)
                    continue
                data = decoder.unconsumed_tail
            started = True
        out.append(piece)
        total += len(piece)
        # Raw bytes are capped too: a stream that decompresses to nothing is
        # still bytes this process is reading.
        if total >= cap or raw_total >= cap:
            return b"".join(out)[:cap], total, True
    return b"".join(out), total, False
