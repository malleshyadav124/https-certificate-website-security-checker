import socket
from datetime import datetime, timezone
from unittest.mock import Mock

from webchecker import create_app
from webchecker.certificate_inspection import CertificateInspection
from webchecker.check_results import CheckResult, CheckStatus
from webchecker.header_checks import HeaderInspection
from webchecker.report import build_scan_report
from webchecker.tls_inspection import TLSInspection


def _check(status, message):
    return CheckResult(status, message)


def test_scan_api_returns_observed_checks_and_recommendations(monkeypatch):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
        ),
    )
    certificate = CertificateInspection(
        hostname="example.test",
        port=443,
        validity=_check(CheckStatus.PASS, "Certificate is within its validity period."),
        hostname_match=_check(CheckStatus.PASS, "Hostname matches."),
        chain_trust=_check(CheckStatus.PASS, "Chain is trusted."),
        not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        issuer="commonName=Example CA",
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_protocol="TLSv1.3",
    )
    headers = HeaderInspection(
        url="https://example.test/",
        http_to_https=_check(CheckStatus.PASS, "HTTP redirected to HTTPS."),
        security_headers={
            "Strict-Transport-Security": _check(CheckStatus.PASS, "HSTS is present."),
            "Content-Security-Policy": _check(
                CheckStatus.WARNING,
                "Content-Security-Policy is missing; this is a security-header finding, "
                "not a certificate validation failure.",
            ),
            "X-Content-Type-Options": _check(
                CheckStatus.PASS, "X-Content-Type-Options is present."
            ),
        },
        final_url="https://example.test/",
    )
    inspect_certificate = Mock(return_value=certificate)
    inspect_headers = Mock(return_value=headers)
    monkeypatch.setattr(
        "webchecker.routes.inspect_certificate", inspect_certificate
    )
    monkeypatch.setattr("webchecker.routes.inspect_headers", inspect_headers)
    client = create_app().test_client()

    response = client.post(
        "/api/scan",
        json={"url": "https://example.test/"},
    )

    assert response.status_code == 200
    report = response.get_json()
    assert report["url"] == "https://example.test/"
    assert report["overall"]["status"] == "WARNING"
    assert report["overall"]["connection_status"] == "VERIFIED"
    assert report["overall"]["findings_status"] == "DETECTED"
    assert report["overall"]["scan_status"] == "COMPLETE"
    assert "HTTPS connection verified" in report["overall"]["summary"]
    assert "Security findings detected" in report["overall"]["summary"]
    assert report["certificate"]["checks"]["validity"]["status"] == "PASS"
    assert report["certificate"]["checks"]["chain_trust"]["status"] == "PASS"
    assert report["certificate"]["issuer"] == "commonName=Example CA"
    assert report["certificate"]["expires_at"] == "2030-01-01T00:00:00+00:00"
    assert report["tls"]["version"] == "TLSv1.3"
    assert report["tls"]["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert report["redirect"]["status"] == "PASS"
    assert report["redirect"]["final_url"] == "https://example.test/"
    assert report["headers"]["Content-Security-Policy"]["status"] == "WARNING"
    assert "not a certificate validation failure" in report["headers"][
        "Content-Security-Policy"
    ]["message"]
    assert report["recommendations"] == [
        {
            "finding": "Content-Security-Policy",
            "advice": "Define a Content-Security-Policy suited to the site's resources and intended behavior.",
        }
    ]
    inspect_certificate.assert_called_once_with("example.test", port=443)
    inspect_headers.assert_called_once_with("https://example.test/")


def test_http_url_uses_default_https_port_for_certificate_check(monkeypatch):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 8080))
            ]
        ),
    )
    certificate = CertificateInspection(
        hostname="example.test",
        port=443,
        validity=_check(CheckStatus.NOT_CHECKED, "not checked"),
        hostname_match=_check(CheckStatus.NOT_CHECKED, "not checked"),
        chain_trust=_check(CheckStatus.NOT_CHECKED, "not checked"),
    )
    inspect_certificate = Mock(return_value=certificate)
    monkeypatch.setattr("webchecker.routes.inspect_certificate", inspect_certificate)
    monkeypatch.setattr(
        "webchecker.routes.inspect_headers",
        Mock(
            return_value=HeaderInspection(
                "http://example.test:8080/",
                _check(CheckStatus.FAIL, "no redirect"),
                {},
            )
        ),
    )

    response = create_app().test_client().post(
        "/api/scan", json={"url": "http://example.test:8080/"}
    )

    assert response.status_code == 200
    inspect_certificate.assert_called_once_with("example.test", port=443)


def test_scan_api_rejects_missing_or_invalid_url():
    client = create_app().test_client()

    missing = client.post("/api/scan", json={})
    invalid = client.post("/api/scan", json={"url": "file:///etc/passwd"})

    assert missing.status_code == 400
    assert "URL string" in missing.get_json()["error"]
    assert invalid.status_code == 400
    assert "HTTP(S)" in invalid.get_json()["error"]


def test_scan_api_blocks_private_dns_destinations_before_inspection(monkeypatch):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
            ]
        ),
    )
    inspect_certificate = Mock()
    inspect_headers = Mock()
    monkeypatch.setattr(
        "webchecker.routes.inspect_certificate", inspect_certificate
    )
    monkeypatch.setattr("webchecker.routes.inspect_headers", inspect_headers)
    client = create_app().test_client()

    response = client.post("/api/scan", json={"url": "https://example.test/"})

    assert response.status_code == 400
    assert "non-public" in response.get_json()["error"]
    inspect_certificate.assert_not_called()
    inspect_headers.assert_not_called()


def test_report_warns_when_only_some_security_checks_completed():
    not_checked = _check(CheckStatus.NOT_CHECKED, "Could not be checked.")
    certificate = CertificateInspection(
        hostname="example.test",
        port=443,
        validity=not_checked,
        hostname_match=not_checked,
        chain_trust=not_checked,
    )
    tls = TLSInspection(check=not_checked)
    headers = HeaderInspection(
        url="https://example.test/",
        http_to_https=_check(CheckStatus.PASS, "HTTP redirected to HTTPS."),
        security_headers={
            "Strict-Transport-Security": _check(CheckStatus.PASS, "Present."),
        },
        final_url="https://example.test/",
    )

    report = build_scan_report("https://example.test/", certificate, tls, headers)

    assert report["overall"]["status"] == "WARNING"
    assert report["overall"]["connection_status"] == "NOT_CHECKED"
    assert report["overall"]["findings_status"] == "NOT_ASSESSED"
    assert report["overall"]["scan_status"] == "INCOMPLETE"
    assert "not fully assessed" in report["overall"]["summary"]
    assert "Scan incomplete" in report["overall"]["summary"]


def test_redirect_failure_is_a_finding_not_a_failed_https_connection():
    passed = _check(CheckStatus.PASS, "Passed.")
    certificate = CertificateInspection(
        hostname="example.test",
        port=443,
        validity=passed,
        hostname_match=passed,
        chain_trust=passed,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
    )
    tls = TLSInspection(check=passed, version="TLSv1.3")
    headers = HeaderInspection(
        url="https://example.test/",
        http_to_https=_check(
            CheckStatus.FAIL, "HTTP remained HTTP after redirects."
        ),
        security_headers={
            "Strict-Transport-Security": passed,
            "Content-Security-Policy": passed,
            "X-Content-Type-Options": passed,
        },
        final_url="http://example.test/",
    )

    report = build_scan_report(
        "https://example.test/", certificate, tls, headers
    )

    assert report["overall"]["status"] == "WARNING"
    assert report["overall"]["connection_status"] == "VERIFIED"
    assert report["overall"]["findings_status"] == "DETECTED"
    assert report["overall"]["scan_status"] == "COMPLETE"
    assert report["overall"]["badge_label"] == (
        "HTTPS verified · findings detected"
    )
    assert "HTTPS connection verified" in report["overall"]["summary"]
    assert "Security findings detected" in report["overall"]["summary"]
    assert report["redirect"]["status"] == "FAIL"


def test_complete_report_without_findings_has_verified_summary():
    passed = _check(CheckStatus.PASS, "Passed.")
    certificate = CertificateInspection(
        hostname="example.test",
        port=443,
        validity=passed,
        hostname_match=passed,
        chain_trust=passed,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
    )
    tls = TLSInspection(check=passed)
    headers = HeaderInspection(
        url="https://example.test/",
        http_to_https=passed,
        security_headers={
            "Strict-Transport-Security": passed,
            "Content-Security-Policy": passed,
            "X-Content-Type-Options": passed,
        },
        final_url="https://example.test/",
    )

    report = build_scan_report(
        "https://example.test/", certificate, tls, headers
    )

    assert report["overall"]["status"] == "PASS"
    assert report["overall"]["connection_status"] == "VERIFIED"
    assert report["overall"]["findings_status"] == "NONE"
    assert report["overall"]["scan_status"] == "COMPLETE"
    assert "No security findings detected" in report["overall"]["summary"]
