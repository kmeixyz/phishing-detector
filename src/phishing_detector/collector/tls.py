"""TLS certificate evidence.

Two handshakes, deliberately. The first verifies normally and records whether
the chain and hostname actually check out. The second does not verify, purely
so a self-signed or mismatched certificate can still be *read* — a cert we
refuse to trust is exactly the one worth describing to the user.

Nothing is sent over either connection. The socket is opened, the certificate
is read from the handshake, and it is closed.

A note on issuer: Let's Encrypt dominates both phishing and the legitimate
long tail. Issuer is recorded for display, but a model leaning on it is
learning "is this a big company that buys OV certs", not "is this phishing".
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from ..config import ENVELOPE
from ..netguard import BlockedAddress, resolve_public
from ..urls import https_upgrade, parse
from .base import FAILED, CollectorResult, timed

_TIMEOUT = min(ENVELOPE.per_collector_timeout_s, 10.0)


def _fetch_der(host: str, port: int, verify: bool, address: str) -> tuple[bytes | None, str]:
    """The certificate `host` serves on `port`.

    `address` is the one `resolve_public` approved. The socket is opened to it
    rather than to the name, so the connection lands where the guard looked;
    `server_hostname` keeps the name in the handshake, so SNI still selects the
    right certificate and verification still checks against the hostname.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((address, port), timeout=_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), ""
    except ssl.SSLCertVerificationError as exc:
        return None, f"verification failed: {exc.verify_message or exc}"
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return None, str(exc)


def _names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def _matches(hostname: str, names: list[str], cn: str) -> bool:
    candidates = names or ([cn] if cn else [])
    for pattern in candidates:
        p = pattern.lower().lstrip(".")
        if p.startswith("*."):
            if hostname.split(".", 1)[-1] == p[2:]:
                return True
        elif hostname == p:
            return True
    return False


def collect(url: str) -> CollectorResult:
    res = CollectorResult(name="TLS certificate")
    with timed(res):
        # Read the certificate a browser would be shown: for a bare name or a
        # plain `http://` on the default port that is the HTTPS site, which
        # browsers now try first. Only an http address on another port is
        # left without one.
        upgraded = https_upgrade(url)
        guessed = upgraded is not None and not (url or "").strip().lower().startswith("https://")
        p = parse(upgraded or url)
        if p.scheme != "https":
            res.status = FAILED
            res.detail = "not an https URL"
            res.conclusive = True
            return res

        # The IDNA2008 form, so the certificate described here belongs to the
        # domain the HTTP collector fetched. `socket` and `ssl` apply IDNA2003
        # to a unicode hostname, which is a different registrable domain and
        # therefore a different certificate.
        host, port = p.ascii_hostname or p.hostname, p.port or 443

        # Nothing here goes through the HTTP client, so none of its guarding
        # applies: this opens a socket directly, to a host *and a port* the
        # submitted URL chose. Unguarded it is an internal port prober that
        # reports back whatever certificate it finds -- `https://127.0.0.1:9200/`
        # was refused by the fetch collector and handshaked with by this one.
        #
        # The address is resolved once here and the socket is opened to that
        # address, so the name cannot resolve elsewhere in between.
        try:
            addresses = resolve_public(host)
        except BlockedAddress as exc:
            res.status = FAILED
            res.detail = f"refusing to connect: {exc}"
            return res

        # The first address this host can actually reach. `resolve_public`
        # puts IPv4 first; an address that cannot be routed from here fails
        # the connect in a millisecond and the next one is tried, so a
        # dual-stack site is not reported certificate-less because one
        # family has no route.
        address = addresses[0]
        reachable = False
        for candidate in addresses:
            try:
                with socket.create_connection((candidate, port), timeout=_TIMEOUT):
                    address = candidate
                    reachable = True
                    break
            except OSError:
                continue

        der, verify_err = _fetch_der(host, port, verify=True, address=address)
        chain_trusted = der is not None
        if der is None:
            der, err = _fetch_der(host, port, verify=False, address=address)
            if der is None:
                res.status = FAILED
                res.detail = err or verify_err or "no certificate"
                # For a bare name or an http address, HTTPS was our guess,
                # not the visitor's claim. Nothing answering on 443 then says
                # the site has no HTTPS, and that is an answer.
                if guessed and not reachable:
                    res.detail = f"the site does not serve HTTPS ({res.detail})"
                    res.conclusive = True
                return res

        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as exc:
            res.status = FAILED
            res.detail = f"unparseable certificate: {exc}"
            return res

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        sans = _names(cert)
        cn = _cn(cert.subject)
        issuer_cn = _cn(cert.issuer)

        res.data = {
            "issuer": issuer_cn or cert.issuer.rfc4514_string(),
            "subject_cn": cn,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "cert_age_days": (now - not_before).days,
            "validity_days": (not_after - not_before).days,
            "days_to_expiry": (not_after - now).days,
            "san_count": len(sans),
            "san_sample": sans[:8],
            "hostname_match": _matches(host, sans, cn),
            "self_signed": cert.issuer == cert.subject,
            "chain_trusted": chain_trusted,
            "verify_error": verify_err,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
        res.detail = (
            f"{issuer_cn or 'unknown issuer'}, {len(sans)} SAN, "
            f"{(now - not_before).days}d old"
        )
    return res
