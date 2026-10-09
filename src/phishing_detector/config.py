"""Paths and the safety envelope.

The envelope is a single object because the interface displays it verbatim
during a scan. If a limit is tightened here, the user sees the new number —
there is no second copy of these values in the templates.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
SNAPSHOTS = DATA / "snapshots"
CORPUS = DATA / "corpus"
MODELS = ROOT / "models"


def _cache_path() -> Path:
    return Path(os.getenv("PHISHING_DETECTOR_CACHE_DIR") or (DATA / "cache"))


# Evidence bundles hold the raw HTML of scanned pages, which for phishing sites
# means real malicious JavaScript sitting on disk as data. Overridable so a
# contained run can keep it inside a volume instead of on the host filesystem.
CACHE = _cache_path()


def cache_dir() -> Path:
    """Resolved per call, not once at import.

    A contained run points this at a volume, and the tests point it at a
    temporary directory so a test run never leaves fetched pages behind. A
    module-level constant fixed at import time could not be redirected by
    either.
    """
    path = _cache_path()
    path.mkdir(parents=True, exist_ok=True)
    return path


load_dotenv(ROOT / ".env")


def _ensure_dirs() -> None:
    # A stateless instance writes nothing, and on the platform it is usually
    # deployed to the tree is read-only -- so creating directories is not just
    # pointless but the thing that would stop the app importing at all.
    if stateless():
        return
    for d in (SNAPSHOTS, CACHE, CORPUS, MODELS):
        d.mkdir(parents=True, exist_ok=True)


def _contact_url() -> str:
    """Where a site operator can find out what this scanner is, or "".

    Wikimedia's edge answered every request from the scanner -- the page, its
    favicon, everything -- with a 403 asking bots to identify themselves, and
    other large sites apply the same rule. A crawler's convention for that is a
    URL after the "+" in its User-Agent. PHISHING_DETECTOR_CONTACT_URL names
    one explicitly; on Vercel the deployment's own production address serves,
    since its front page says what the tool is and does. Read from the
    environment directly because this runs before `on_vercel` is defined.
    """
    explicit = os.getenv("PHISHING_DETECTOR_CONTACT_URL", "").strip()
    if explicit:
        return explicit
    if os.getenv("VERCEL") == "1":
        host = os.getenv("VERCEL_PROJECT_PRODUCTION_URL", "").strip()
        if host:
            return f"https://{host}"
    return ""


def _user_agent() -> str:
    contact = _contact_url()
    return ("Phishing-Detector/0.1 (+" + (f"{contact}; " if contact else "")
            + "passive phishing-detection scanner; "
            "fetches the submitted URL only; does not execute or submit anything)")


@dataclass(frozen=True)
class SafetyEnvelope:
    """Hard limits on what the collector is allowed to do.

    Every field is surfaced in the scanning view. The collector is passive:
    it fetches the URL it was given and nothing else. It never submits a form,
    never supplies credentials real or fake, never follows a download, never
    executes retrieved content, and never probes a path it was not handed.
    """

    max_redirects: int = 10
    max_response_bytes: int = 2 * 1024 * 1024  # 2 MB
    per_collector_timeout_s: float = 15.0
    # Wall clock for one fetch, every hop included. `per_collector_timeout_s`
    # bounds each wait for a byte; this bounds the sum, which a server that
    # trickles one byte at a time otherwise sets for us.
    fetch_deadline_s: float = 30.0
    icon_deadline_s: float = 10.0
    total_scan_timeout_s: float = 45.0
    execute_javascript: bool = False
    submit_forms: bool = False
    allow_downloads: bool = False
    rdap_requests_per_second: float = 0.5
    whois_requests_per_second: float = 0.25
    user_agent: str = field(default_factory=_user_agent)

    # JS rendering limits. Only consulted when execute_javascript is True.
    render_timeout_s: float = 20.0
    render_settle_ms: int = 2500

    def with_javascript(self, enabled: bool) -> "SafetyEnvelope":
        """A copy with JS execution flipped.

        Exists so the envelope shown in the interface is the envelope the scan
        actually ran under. A global constant claiming "js execution off" while
        a particular scan rendered the page would be a lie in the one place the
        user is relying on us to be literal.
        """
        return replace(self, execute_javascript=enabled)

    def as_rows(self) -> list[tuple[str, str]]:
        """Key/value pairs for the scanning view, in display order."""
        rows = [
            ("Redirect depth cap", str(self.max_redirects)),
            ("Response size cap", f"{self.max_response_bytes // (1024 * 1024)} MB"),
            ("Per-collector timeout", f"{self.per_collector_timeout_s:.0f}s"),
            ("Javascript execution", "ENABLED" if self.execute_javascript else "disabled"),
            ("Form submission", "permitted" if self.submit_forms else "never"),
            ("Downloads", "allowed" if self.allow_downloads else "blocked"),
            ("RDAP rate limit", f"{self.rdap_requests_per_second} req/s"),
            ("WHOIS rate limit", f"{self.whois_requests_per_second} req/s"),
        ]
        if self.execute_javascript:
            rows.insert(4, ("Render timeout", f"{self.render_timeout_s:.0f}s"))
        return rows


ENVELOPE = SafetyEnvelope()


def _env_flag(name: str) -> bool:
    """True when an environment variable is set to 1, true or yes."""
    return os.getenv(name, "").strip() in ("1", "true", "yes")


def javascript_permitted() -> bool:
    """Whether JS rendering may be used at all, from the environment.

    Rendering means executing attacker-controlled JavaScript. Everywhere else
    in this project that is explicitly refused, so turning it on is a separate,
    deliberate act rather than a per-request checkbox: set PHISHING_DETECTOR_ALLOW_JS=1.

    Outside a container this materially widens what a hostile page can attempt.
    The interface says so, loudly, whenever the flag is set.
    """
    return _env_flag("PHISHING_DETECTOR_ALLOW_JS")


def containerised() -> bool:
    """Best-effort detection of running inside a container."""
    return Path("/.dockerenv").exists() or os.getenv("PHISHING_DETECTOR_IN_CONTAINER") == "1"


def on_vercel() -> bool:
    """Whether this process is a Vercel function.

    `VERCEL=1` is set by the platform, not by anything a caller controls, which
    is what makes the two decisions keyed on it safe: trusting the client
    address header Vercel writes, and treating the deployment as stateless.
    """
    return os.getenv("VERCEL") == "1"


def production_origin() -> str:
    """`https://<production host>` on Vercel, or "".

    Link previews need absolute addresses, and a preview should always point
    at the production site -- not at whichever preview deployment or alias a
    link happened to be made on. Set by the platform, not by a caller.
    """
    host = os.getenv("VERCEL_PROJECT_PRODUCTION_URL", "").strip() if on_vercel() else ""
    return f"https://{host}" if host else ""


def stateless() -> bool:
    """Whether this instance keeps nothing at all, not even bookkeeping.

    `PHISHING_DETECTOR_NO_STORE` stops the fetched *page* being written. This
    stops everything else: the evidence-bundle cache is neither read nor
    written, the RDAP and CT lookup caches are skipped, the corrections form
    is withheld and `/feedback` answers 404, and the Public Suffix List comes
    from tldextract's bundled snapshot rather than a cache directory. After a
    scan the server holds nothing that says it happened.

    Set PHISHING_DETECTOR_STATELESS=1 to choose it. It is also implied on
    Vercel, where the filesystem is read-only and there is no other value that
    would work -- a forgotten flag there would fail on the first scan with a
    traceback about a directory it could not create, which helps nobody.

    The cost is a live RDAP and CT query on every scan rather than one per
    domain per fortnight, and no way to correct a verdict from the page.
    """
    return _env_flag("PHISHING_DETECTOR_STATELESS") or on_vercel()


def _bare_host(entry: str) -> str:
    """`https://Scan.Example.com:443/` -> `scan.example.com`.

    The Host check compares bare names, so an entry written as a URL or with
    a port matched nothing, and every request was answered 421 -- the site
    down, with nothing to say why.
    """
    host = entry.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def allowed_hosts() -> frozenset[str]:
    """Host header values this instance answers to, or empty for "any".

    Set PHISHING_DETECTOR_ALLOWED_HOSTS to a comma-separated list on anything
    public. The cross-origin guard compares a request's Origin against its Host
    header, and Host is supplied by the caller -- so a request carrying
    `Host: evil.example` and `Origin: http://evil.example` agrees with itself
    and walks through the guard. A proxy that overwrites Host closes this too,
    but relying on that means the app is only as safe as a config file nobody
    reads; this makes it explicit and checkable.
    """
    raw = os.getenv("PHISHING_DETECTOR_ALLOWED_HOSTS", "")
    hosts = {_bare_host(h) for h in raw.split(",") if _bare_host(h)}
    # Vercel tells the function its own hostnames: the per-deployment URL, the
    # branch alias and the production domain. They come from the platform, so
    # they are as trustworthy as the explicit list -- and without them every
    # preview deployment would need its own generated hostname pasted in. A
    # custom domain is not among them and still has to be named explicitly.
    if on_vercel():
        for var in ("VERCEL_URL", "VERCEL_BRANCH_URL", "VERCEL_PROJECT_PRODUCTION_URL"):
            value = os.getenv(var, "").strip().lower()
            if value:
                hosts.add(value)
    return frozenset(hosts)


VERCEL_DEFAULT_RPM = 20


def requests_per_minute() -> int:
    """Inbound requests allowed per caller per minute. 0 disables the limit.

    Defaults to off, because on loopback the only caller is the operator and a
    limit would just get in the way. `deploy/phishing-detector.service` sets it,
    and it should be set on anything reachable by more than one person: a scan
    fans out six collectors against third-party services, so an unlimited
    endpoint is an open fetch service running under this machine's address and
    this project's API keys.

    On Vercel the default is `VERCEL_DEFAULT_RPM` instead. A deployment there is
    public by construction, and its settings live in a dashboard nobody reads at
    startup -- a forgotten variable would otherwise mean no limit at all, with
    only a log line to say so. An explicit `PHISHING_DETECTOR_RPM=0` still turns
    it off; a value that is not a number falls back to the default rather than
    to "unlimited", so a typo cannot open the endpoint up.
    """
    # A shared self-hosted instance is as public as a Vercel one: unset, its
    # limit was 0 -- an open fetch service, the thing this default exists to
    # prevent there.
    default = VERCEL_DEFAULT_RPM if (on_vercel() or shared_instance()) else 0
    raw = os.getenv("PHISHING_DETECTOR_RPM", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    # Only an explicit 0 turns it off. A negative number is a typo, not a
    # request for no limit, and `max(0, ...)` used to read it as one.
    return value if value >= 0 else default


class MisconfiguredDeployment(RuntimeError):
    """The settings contradict each other in a way nothing at runtime can catch."""


def deployment_problems() -> list[str]:
    """Settings that are wrong now, phrased as what to do about them.

    Only genuine incoherence belongs here -- a state where the operator believes
    a protection is on and it is not. Risk choices do not: running without a
    rate limit on a private network is a decision, and a program that refuses to
    start over a decision is a program people work around.

    The case this exists for: `PHISHING_DETECTOR_SHARED=1` says more than one
    person can reach this instance, while an unset `ALLOWED_HOSTS` means the
    Host header is accepted from anyone. The two together are a contradiction,
    and it fails *open* -- the check is skipped silently, so nothing about a
    running instance would ever tell you. Refusing to start is the only moment
    it can be said out loud.
    """
    problems: list[str] = []
    if shared_instance() and not allowed_hosts():
        problems.append(
            "PHISHING_DETECTOR_SHARED=1 is set, so this instance expects more than "
            "one visitor -- but PHISHING_DETECTOR_ALLOWED_HOSTS is empty, which "
            "disables the Host header check entirely.\n"
            "  Set it to the hostname this is served on, e.g.\n"
            "    PHISHING_DETECTOR_ALLOWED_HOSTS=scan.your-domain.example\n"
            "  Comma-separate several. Unset PHISHING_DETECTOR_SHARED if this is "
            "only reachable by you."
        )
    return problems


def warn_about_deployment() -> list[str]:
    """Risk choices worth stating at startup, which are not reasons to refuse."""
    notes: list[str] = []
    odd = sorted(h for h in allowed_hosts()
                 if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", h))
    if odd:
        notes.append(
            "PHISHING_DETECTOR_ALLOWED_HOSTS holds entries that are not hostnames and "
            f"can never match a request: {', '.join(odd)}. Requests for them are "
            "answered 421.")
    # A deployment copies the fitted artefacts across by hand, because the
    # joblib files are gitignored and a fresh clone has none of them. Missing
    # the main model is loud -- the interface says "no model trained". Missing
    # the *ensemble* is silent: scores still appear, and the bootstrap interval
    # that feeds the abstention just becomes None, so the scan stops being able
    # to say "the number is not stable enough to act on". That is a safety
    # property disappearing quietly, which is the kind this project says out
    # loud. The deploy instructions omitted this file for a while, which is
    # exactly how it would happen.
    if (MODELS / "baseline.joblib").exists() and not (MODELS / "bootstrap_ensemble.joblib").exists():
        notes.append(
            "models/bootstrap_ensemble.joblib is missing while the fitted model is "
            "present. Scans will score, but with no prediction interval -- the "
            "abstention that withholds a verdict when the score is unstable cannot "
            "run. Copy it across with the other .joblib files."
        )
    # A stateless instance is public in practice -- it exists to be deployed
    # somewhere reachable -- so the same warning applies whether or not anyone
    # remembered to say so with SHARED.
    if (shared_instance() or stateless()) and not requests_per_minute():
        notes.append(
            "PHISHING_DETECTOR_RPM is unset on a shared instance: there is no inbound "
            "rate limit, and this application has no authentication, so anyone who "
            "can reach it can make it fetch URLs of their choosing at any rate."
        )
    return notes


def shared_instance() -> bool:
    """Whether more than one person can reach this instance.

    Set PHISHING_DETECTOR_SHARED=1 on anything public. It withholds the operator
    surfaces that assume a single user: chiefly the corrections tray, which
    lists the notes and URLs everyone has submitted and would otherwise show
    each visitor everyone else's reports. Reviewing that queue is what
    `feedback_cli.py` is for, and on a shared instance it is the only way.

    Scan history is not covered by this flag because it no longer needs to be:
    it lives in the visitor's own browser in every mode, so there is one code
    path rather than two, and a forgotten flag cannot expose it.

    Implied on Vercel, for the same reason `stateless()` is: a deployment there
    is public, and without the flag it would publish `/docs` and the route
    schema to every visitor. `allowed_hosts()` is never empty there, so this
    cannot trip the SHARED-without-hosts refusal.
    """
    return _env_flag("PHISHING_DETECTOR_SHARED") or on_vercel()


class HostScanRefused(RuntimeError):
    """Raised when a scan would write attacker content to the host filesystem."""


def store_pages() -> bool:
    """Whether fetched page content may be written to disk.

    Set PHISHING_DETECTOR_NO_STORE=1 to scan without keeping the page. Features are
    extracted in memory and only the numbers are cached, so nothing malicious
    reaches the filesystem and there is nothing for an antivirus to quarantine.

    The cost is that a scan cannot be re-analysed later without re-fetching,
    and phishing sites are usually gone within hours. Keeping the page is the
    better default when it can be kept somewhere contained.

    A stateless instance writes nothing, the page included, so it is "not
    storing" whether or not the flag was set. Saying so here is what keeps
    `host_scanning_allowed()` coherent: refusing to scan on a read-only
    filesystem to protect it from a write that cannot happen would just be a
    second flag to forget.
    """
    return not (_env_flag("PHISHING_DETECTOR_NO_STORE") or stateless())


def host_scanning_allowed() -> bool:
    """Whether scanning may run outside a container.

    Scanning stores the fetched page, so a phishing scan leaves live malicious
    JavaScript on the local filesystem. That is not hypothetical: Avast
    quarantined several evidence bundles straight out of the cache directory,
    correctly identifying JS:Redirector and HTML:Phishing signatures in them.

    Inside a container the bundles live in a volume and never touch the host.
    Outside one, this refuses by default and has to be overridden deliberately.
    """
    # Not storing pages removes the reason for the restriction, so that mode is
    # allowed on the host without an explicit override.
    return containerised() or not store_pages() or _env_flag("PHISHING_DETECTOR_ALLOW_HOST_SCAN")


def refuse_host_scan_message() -> str:
    return (
        "Refusing to scan on the host: a scan stores the fetched page, so scanning "
        "phishing URLs would write live malicious JavaScript to this filesystem "
        "(your antivirus will quarantine it, and it should).\n"
        "  Keep nothing on disk:      PHISHING_DETECTOR_NO_STORE=1\n"
        "  Store pages here anyway:   PHISHING_DETECTOR_ALLOW_HOST_SCAN=1\n"
        "  Or run it inside a container of your own, where the pages stay contained."
    )


@dataclass(frozen=True)
class Credentials:
    """Optional API keys. The project works with all of these unset."""

    abusech_auth_key: str | None = field(
        default_factory=lambda: os.getenv("ABUSECH_AUTH_KEY") or None
    )
    google_safe_browsing_key: str | None = field(
        default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_KEY") or None
    )


CREDENTIALS = Credentials()

_ensure_dirs()
