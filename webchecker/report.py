"""Serialize inspection results and produce targeted remediation advice."""

from __future__ import annotations

from datetime import datetime, timezone

from webchecker.certificate_inspection import CertificateInspection
from webchecker.check_results import CheckResult, CheckStatus
from webchecker.header_checks import HeaderInspection
from webchecker.tls_inspection import TLSInspection


def build_scan_report(
    url: str,
    certificate: CertificateInspection,
    tls: TLSInspection,
    headers: HeaderInspection,
) -> dict[str, object]:
    """Build the JSON-safe report from observed module results only."""
    certificate_checks = {
        "validity": _check_dict(certificate.validity),
        "hostname_match": _check_dict(certificate.hostname_match),
        "chain_trust": _check_dict(certificate.chain_trust),
    }
    all_checks = [
        ("Certificate validity", certificate.validity),
        ("Hostname match", certificate.hostname_match),
        ("Certificate-chain trust", certificate.chain_trust),
        ("Negotiated TLS", tls.check),
        ("HTTP-to-HTTPS redirect", headers.http_to_https),
        *headers.security_headers.items(),
    ]
    statuses = [check.status for _, check in all_checks]
    overall = _overall_assessment(certificate, tls, statuses)
    findings = [
        {
            "id": _check_id(name),
            "name": name,
            "status": check.status.value,
            "message": check.message,
        }
        for name, check in all_checks
    ]

    return {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "certificate": {
            "hostname": certificate.hostname,
            "port": certificate.port,
            "issuer": certificate.issuer,
            "not_before": _datetime_dict(certificate.not_before),
            "expires_at": _datetime_dict(certificate.expires_at),
            "error": certificate.error,
            "checks": certificate_checks,
        },
        "tls": {
            "check": _check_dict(tls.check),
            "version": tls.version,
            "cipher_suite": tls.cipher_suite,
            "cipher_protocol": tls.cipher_protocol,
        },
        "redirect": {
            **_check_dict(headers.http_to_https),
            "final_url": headers.final_url,
        },
        "headers": {
            name: _check_dict(check)
            for name, check in headers.security_headers.items()
        },
        "findings": findings,
        "recommendations": _recommendations(certificate, tls, headers),
    }


def _check_dict(check: CheckResult) -> dict[str, str]:
    return {"status": check.status.value, "message": check.message}


def _datetime_dict(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _overall_assessment(
    certificate: CertificateInspection,
    tls: TLSInspection,
    statuses: list[CheckStatus],
) -> dict[str, str]:
    certificate_checks = (
        certificate.validity,
        certificate.hostname_match,
        certificate.chain_trust,
        tls.check,
    )
    if all(check.status is CheckStatus.PASS for check in certificate_checks):
        connection_status = "VERIFIED"
    elif any(check.status is CheckStatus.FAIL for check in certificate_checks):
        connection_status = "NOT_VERIFIED"
    else:
        connection_status = "NOT_CHECKED"

    checked_statuses = [
        status for status in statuses if status is not CheckStatus.NOT_CHECKED
    ]
    complete = len(checked_statuses) == len(statuses)
    findings_detected = any(
        status in (CheckStatus.FAIL, CheckStatus.WARNING)
        for status in checked_statuses
    )
    findings_status = (
        "DETECTED" if findings_detected else "NONE" if complete else "NOT_ASSESSED"
    )
    scan_status = "COMPLETE" if complete else "INCOMPLETE"

    if connection_status == "NOT_VERIFIED":
        status = CheckStatus.FAIL
    elif findings_detected or not complete:
        status = CheckStatus.WARNING
    elif connection_status == "VERIFIED":
        status = CheckStatus.PASS
    else:
        status = CheckStatus.NOT_CHECKED

    connection_label = {
        "VERIFIED": "HTTPS verified",
        "NOT_VERIFIED": "HTTPS not verified",
        "NOT_CHECKED": "HTTPS not checked",
    }[connection_status]
    findings_label = {
        "DETECTED": "findings detected",
        "NONE": "no findings",
        "NOT_ASSESSED": "findings not fully assessed",
    }[findings_status]
    badge_label = f"{connection_label} · {findings_label}"
    if not complete:
        badge_label += " · incomplete"

    summary = (
        f"HTTPS connection {connection_status.lower().replace('_', ' ')}. "
        f"{'Security findings detected.' if findings_detected else 'No security findings detected.' if complete else 'Findings are not fully assessed.'} "
        f"Scan {scan_status.lower()}."
    )
    return {
        "status": status.value,
        "badge_label": badge_label,
        "connection_status": connection_status,
        "findings_status": findings_status,
        "scan_status": scan_status,
        "summary": summary,
    }


def _check_id(name: str) -> str:
    return name.lower().replace(" ", "_").replace("-", "_")


def _recommendations(
    certificate: CertificateInspection,
    tls: TLSInspection,
    headers: HeaderInspection,
) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []

    certificate_advice = {
        "validity": "Renew the certificate before its expiry, or wait until its valid-from date.",
        "hostname_match": "Install a certificate whose subject alternative names include the requested hostname.",
        "chain_trust": "Install the complete certificate chain from a trusted certificate authority.",
    }
    for key, check in (
        ("validity", certificate.validity),
        ("hostname_match", certificate.hostname_match),
        ("chain_trust", certificate.chain_trust),
    ):
        if check.status in (CheckStatus.FAIL, CheckStatus.WARNING):
            recommendations.append(
                {"finding": key, "advice": certificate_advice[key]}
            )

    if tls.check.status in (CheckStatus.FAIL, CheckStatus.WARNING):
        recommendations.append(
            {
                "finding": "negotiated_tls",
                "advice": "Review the server TLS configuration and prefer currently supported protocol and cipher settings.",
            }
        )

    if headers.http_to_https.status in (CheckStatus.FAIL, CheckStatus.WARNING):
        recommendations.append(
            {
                "finding": "http_to_https",
                "advice": "Configure the HTTP site to redirect requests to the corresponding HTTPS URL.",
            }
        )

    header_advice = {
        "Strict-Transport-Security": "After HTTPS is correctly configured, add an HSTS policy with an appropriate max-age.",
        "Content-Security-Policy": "Define a Content-Security-Policy suited to the site's resources and intended behavior.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff on responses.",
    }
    for name, check in headers.security_headers.items():
        if check.status in (CheckStatus.FAIL, CheckStatus.WARNING):
            recommendations.append(
                {"finding": name, "advice": header_advice[name]}
            )

    return recommendations
