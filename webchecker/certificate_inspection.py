"""Inspect a server certificate using Python's verified TLS defaults."""

from __future__ import annotations

import ipaddress
import logging
import math
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from webchecker.check_results import CheckResult, CheckStatus
from webchecker.url_validation import URLValidationError, validate_url

logger = logging.getLogger(__name__)
MAX_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True)
class CertificateInspection:
    hostname: str
    port: int
    validity: CheckResult
    hostname_match: CheckResult
    chain_trust: CheckResult
    not_before: datetime | None = None
    expires_at: datetime | None = None
    issuer: str | None = None
    tls_version: str | None = None
    cipher_name: str | None = None
    cipher_protocol: str | None = None
    error: str | None = None


def inspect_certificate(
    hostname: str, port: int = 443, timeout: float = 5.0
) -> CertificateInspection:
    """Validate a host's TLS certificate and return individual check results.

    The default SSL context requires a trusted certificate chain and checks
    that the certificate identifies ``hostname``. If validation fails, this
    function does not retry with verification disabled to retrieve the leaf
    certificate.
    """
    normalized_host = _normalize_hostname(hostname)
    if normalized_host is None or not _is_valid_port(port) or not _is_valid_timeout(timeout):
        return _failed_inspection(
            hostname,
            port,
            error="Invalid hostname, port, or timeout.",
        )

    url_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    try:
        target = validate_url(f"https://{url_host}:{port}/")
    except URLValidationError as error:
        logger.info("Certificate inspection target was rejected by URL safety checks.")
        return _failed_inspection(hostname, port, error=str(error))

    context = ssl.create_default_context()
    try:
        with socket.create_connection((target.address, port), timeout=timeout) as connection:
            with context.wrap_socket(
                connection, server_hostname=normalized_host
            ) as tls_connection:
                certificate = tls_connection.getpeercert()
                tls_version = tls_connection.version()
                cipher = tls_connection.cipher()
    except ssl.SSLCertVerificationError as error:
        logger.warning(
            "TLS certificate verification failed (verification code %s).",
            error.verify_code,
        )
        return _verification_failure(
            hostname, port, error.verify_code, error.verify_message
        )
    except socket.gaierror:
        logger.info("Certificate inspection failed: DNS resolution error.")
        return _failed_inspection(hostname, port, error="The hostname could not be resolved.")
    except TimeoutError:
        logger.info("Certificate inspection failed: connection timeout.")
        return _failed_inspection(
            hostname, port, error="The connection timed out while establishing TLS."
        )
    except ssl.SSLError:
        logger.info("Certificate inspection failed: TLS protocol error.")
        return _failed_inspection(
            hostname, port, error="A TLS error prevented certificate inspection."
        )
    except OSError:
        logger.info("Certificate inspection failed: connection error.")
        return _failed_inspection(
            hostname, port, error="Could not connect to the host for certificate inspection."
        )

    try:
        not_before = _certificate_time(certificate, "notBefore")
        expires_at = _certificate_time(certificate, "notAfter")
        issuer = _format_distinguished_name(certificate.get("issuer", ()))
    except (KeyError, TypeError, ValueError, OverflowError):
        logger.warning("TLS connection succeeded, but certificate details were malformed.")
        return _failed_inspection(
            hostname,
            port,
            error="TLS verification succeeded, but certificate details could not be parsed.",
        )

    now = datetime.now(timezone.utc)
    if now < not_before:
        validity = CheckResult(
            CheckStatus.FAIL, "The certificate is not valid yet."
        )
    elif now >= expires_at:
        validity = CheckResult(CheckStatus.FAIL, "The certificate has expired.")
    else:
        validity = CheckResult(
            CheckStatus.PASS, "The certificate is currently within its validity period."
        )

    return CertificateInspection(
        hostname=hostname,
        port=port,
        validity=validity,
        hostname_match=CheckResult(
            CheckStatus.PASS, "The certificate matches the requested hostname."
        ),
        chain_trust=CheckResult(
            CheckStatus.PASS, "The certificate chain was trusted by the system trust store."
        ),
        not_before=not_before,
        expires_at=expires_at,
        issuer=issuer or None,
        tls_version=tls_version,
        cipher_name=cipher[0] if cipher else None,
        cipher_protocol=cipher[1] if cipher else None,
    )


def _normalize_hostname(hostname: str) -> str | None:
    if (
        not isinstance(hostname, str)
        or not hostname
        or hostname != hostname.strip()
        or any(character in hostname for character in "/\\?#@")
        or any(ord(character) < 33 for character in hostname)
    ):
        return None

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if len(ascii_hostname) > 253:
            return None
        labels = ascii_hostname.rstrip(".").split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            return None
        return ascii_hostname


def _is_valid_port(port: int) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _is_valid_timeout(timeout: float) -> bool:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        return False
    try:
        timeout_value = float(timeout)
    except OverflowError:
        return False
    return math.isfinite(timeout_value) and 0 < timeout_value <= MAX_TIMEOUT_SECONDS


def _certificate_time(certificate: dict[str, object], field: str) -> datetime:
    value = certificate[field]
    if not isinstance(value, str):
        raise TypeError(f"Certificate field {field} is not a string.")
    timestamp = ssl.cert_time_to_seconds(value)
    return datetime.fromtimestamp(timestamp, timezone.utc)


def _format_distinguished_name(name: object) -> str:
    if not isinstance(name, tuple):
        return ""
    attributes = (
        f"{key}={value}"
        for relative_name in name
        if isinstance(relative_name, tuple)
        for key, value in relative_name
    )
    return ", ".join(attributes)


def _failed_inspection(
    hostname: str,
    port: int,
    *,
    error: str,
    validity: CheckResult | None = None,
    hostname_match: CheckResult | None = None,
    chain_trust: CheckResult | None = None,
) -> CertificateInspection:
    not_checked = CheckResult(
        CheckStatus.NOT_CHECKED, "Could not check because TLS inspection did not complete."
    )
    return CertificateInspection(
        hostname=hostname,
        port=port,
        validity=validity or not_checked,
        hostname_match=hostname_match or not_checked,
        chain_trust=chain_trust or not_checked,
        error=error,
    )


def _verification_failure(
    hostname: str, port: int, verify_code: int | None, verify_message: str
) -> CertificateInspection:
    message = verify_message or "TLS certificate verification failed."
    if verify_code in (9, 10):
        validity = CheckResult(CheckStatus.FAIL, message)
        error = f"Certificate validity check failed: {message}"
        return _failed_inspection(hostname, port, error=error, validity=validity)
    if verify_code == 62:
        hostname_match = CheckResult(CheckStatus.FAIL, message)
        error = f"Hostname matching failed: {message}"
        return _failed_inspection(
            hostname, port, error=error, hostname_match=hostname_match
        )

    chain_trust = CheckResult(
        CheckStatus.FAIL, f"The certificate chain could not be verified: {message}"
    )
    error = f"Certificate-chain verification failed: {message}"
    return _failed_inspection(hostname, port, error=error, chain_trust=chain_trust)
