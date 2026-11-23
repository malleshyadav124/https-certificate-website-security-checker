"""Represent negotiated TLS details from a verified certificate inspection."""

from dataclasses import dataclass

from webchecker.certificate_inspection import CertificateInspection
from webchecker.check_results import CheckResult, CheckStatus


@dataclass(frozen=True)
class TLSInspection:
    check: CheckResult
    version: str | None = None
    cipher_suite: str | None = None
    cipher_protocol: str | None = None


def negotiated_tls(inspection: CertificateInspection) -> TLSInspection:
    """Extract the protocol and cipher negotiated during certificate validation.

    The details are from one successfully verified connection, not a complete
    inventory of the server's supported protocols or cipher suites.
    """
    if not inspection.tls_version or not inspection.cipher_name:
        message = inspection.error or "TLS negotiation details are unavailable."
        return TLSInspection(
            check=CheckResult(CheckStatus.NOT_CHECKED, message)
        )

    return TLSInspection(
        check=CheckResult(
            CheckStatus.PASS,
            "Negotiated values from one verified TLS connection; this is not a "
            "complete inventory of server-supported configurations.",
        ),
        version=inspection.tls_version,
        cipher_suite=inspection.cipher_name,
        cipher_protocol=inspection.cipher_protocol,
    )
