"""Vector 3 - SSL/TLS certificate validation.

Two handshakes are made against port 443:
  1. A verified handshake, to test whether the certificate is trusted.
  2. An unverified handshake, to capture the certificate as evidence even
     when it is invalid (self-signed, expired, wrong hostname).
Only the TLS handshake happens; no page content is downloaded.
"""

import hashlib
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from .utils import finding, get_host, is_ip, resolves_to_private

VECTOR = "SSL/TLS"
TIMEOUT = 8
FREE_CAS = ("let's encrypt", "zerossl", "buypass", "google trust services", "cloudflare")


def _name(name: x509.Name, oid) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def _fetch_cert(host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()


def _verify(host: str, port: int):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        return False, str(exc)


def analyze(url: str) -> dict:
    host = get_host(url)
    port = 443
    result = {"vector": VECTOR, "status": "ok", "data": {"host": host, "port": port}, "findings": []}
    data = result["data"]

    if not host:
        result["status"] = "error"
        data["error"] = "No hostname in URL."
        return result
    if resolves_to_private(host):
        result["status"] = "skipped"
        data["note"] = "Host resolves to a private or local address; active probing was blocked."
        return result

    try:
        der, tls_version, cipher = _fetch_cert(host, port)
    except socket.gaierror:
        result["status"] = "error"
        data["error"] = "DNS lookup failed. The domain does not currently resolve."
        result["findings"].append(finding("Domain does not resolve",
            "No DNS record exists. The site may be taken down or not yet live.", 10, VECTOR))
        return result
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        result["status"] = "error"
        data["error"] = f"{type(exc).__name__}: {exc}"[:300]
        result["findings"].append(finding("No HTTPS service",
            "Port 443 did not complete a TLS handshake, so the site offers no encryption.", 15, VECTOR))
        return result

    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    issuer_org = _name(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name(cert.issuer, NameOID.COMMON_NAME)
    trusted, verify_error = _verify(host, port)

    data.update({
        "tls_version": tls_version,
        "cipher_suite": cipher[0] if cipher else None,
        "subject_cn": _name(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _name(cert.subject, NameOID.ORGANIZATION_NAME) or None,
        "issuer_org": issuer_org,
        "issuer_cn": issuer_cn,
        "serial_number": format(cert.serial_number, "X"),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "certificate_age_days": (now - not_before).days,
        "days_until_expiry": (not_after - now).days,
        "subject_alt_names": san[:25],
        "san_count": len(san),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper(),
        "trusted_by_system_store": trusted,
        "verification_error": verify_error,
        "self_signed": cert.issuer == cert.subject,
        "validation_type": "OV/EV (organisation named)" if _name(cert.subject, NameOID.ORGANIZATION_NAME)
                           else "DV (domain validated only)",
    })

    f = result["findings"]
    if data["self_signed"]:
        f.append(finding("Self-signed certificate",
            "The certificate was signed by the site itself, not a trusted authority.", 20, VECTOR))
    if not_after < now:
        f.append(finding("Expired certificate",
            f"Expired on {not_after:%Y-%m-%d}.", 25, VECTOR))
    elif not trusted:
        msg = (verify_error or "").lower()
        if "hostname" in msg or "mismatch" in msg:
            f.append(finding("Hostname mismatch",
                f"The certificate was not issued for {host}.", 20, VECTOR))
        elif not data["self_signed"]:
            f.append(finding("Untrusted certificate",
                f"Verification failed: {verify_error}.", 25, VECTOR))
    if trusted:
        f.append(finding("Trusted certificate chain",
            f"Valid certificate issued by {issuer_org or issuer_cn}.", 0, VECTOR))

    if data["certificate_age_days"] <= 7:
        f.append(finding("Very recent certificate",
            f"Issued {data['certificate_age_days']} day(s) ago.", 5, VECTOR))
    if any(ca in (issuer_org + " " + issuer_cn).lower() for ca in FREE_CAS):
        f.append(finding("Free domain-validated CA",
            "Free certificates are used by most sites, including phishing sites. Informational only.", 0, VECTOR))
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        f.append(finding("Outdated TLS protocol",
            f"{tls_version} is deprecated.", 10, VECTOR))

    return result
