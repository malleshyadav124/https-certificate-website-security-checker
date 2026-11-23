import socket
import ssl
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from webchecker.certificate_inspection import (
    CertificateInspection,
    inspect_certificate,
)
from webchecker.check_results import CheckResult, CheckStatus
from webchecker.header_checks import (
    SECURITY_HEADERS,
    _PinnedHTTPAdapter,
    _ResponseSnapshot,
    _as_http_url,
    inspect_headers,
    _request_once,
)
from webchecker.tls_inspection import negotiated_tls
from webchecker.url_validation import URLValidationError, ValidatedTarget, validate_url


PUBLIC_IP = "93.184.216.34"


def _resolve_to_public_ip(monkeypatch):
    record = (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 443))
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(return_value=[record]),
    )


def _certificate_inspection(**overrides):
    fields = {
        "hostname": "example.test",
        "port": 443,
        "validity": CheckResult(CheckStatus.PASS, "valid"),
        "hostname_match": CheckResult(CheckStatus.PASS, "matched"),
        "chain_trust": CheckResult(CheckStatus.PASS, "trusted"),
        "tls_version": "TLSv1.3",
        "cipher_name": "TLS_AES_256_GCM_SHA384",
        "cipher_protocol": "TLSv1.3",
    }
    fields.update(overrides)
    return CertificateInspection(**fields)


def test_negotiated_tls_uses_observations_from_verified_inspection():
    result = negotiated_tls(_certificate_inspection())

    assert result.check.status is CheckStatus.PASS
    assert result.version == "TLSv1.3"
    assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert "not a complete inventory" in result.check.message


def test_negotiated_tls_is_not_checked_when_tls_was_not_established():
    result = negotiated_tls(
        _certificate_inspection(
            tls_version=None,
            cipher_name=None,
            error="The connection timed out.",
        )
    )

    assert result.check.status is CheckStatus.NOT_CHECKED
    assert result.check.message == "The connection timed out."


def test_validate_url_returns_public_pinned_address(monkeypatch):
    _resolve_to_public_ip(monkeypatch)

    target = validate_url("https://example.test/scan?q=1#fragment")

    assert target.url == "https://example.test/scan?q=1"
    assert target.path_and_query == "/scan?q=1"
    assert target.address == PUBLIC_IP
    assert target.port == 443


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@example.test/",
        "https://127.0.0.1/",
        "http://[::1]/",
        "https://example.test:0/",
        "https://example.test:99999/",
        " https://example.test/",
    ],
)
def test_validate_url_rejects_malformed_and_restricted_destinations(url):
    with pytest.raises(URLValidationError):
        validate_url(url)


def test_validate_url_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(return_value=records),
    )

    with pytest.raises(URLValidationError, match="non-public"):
        validate_url("https://example.test/")


def test_https_default_port_is_changed_to_http_default_port(monkeypatch):
    _resolve_to_public_ip(monkeypatch)

    target = validate_url("https://example.test/")

    assert _as_http_url(target) == "http://example.test/"


def test_http_explicit_port_is_preserved_in_http_probe(monkeypatch):
    _resolve_to_public_ip(monkeypatch)

    target = validate_url("http://example.test:443/")

    assert _as_http_url(target) == "http://example.test:443/"


def test_google_style_redirect_that_stays_on_http_fails(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    request_once = Mock(
        side_effect=[
            _ResponseSnapshot(
                301, {"Location": "http://www.example.test/"}, "http://www.example.test/"
            ),
            _ResponseSnapshot(200, {}, None),
        ]
    )
    monkeypatch.setattr("webchecker.header_checks._request_once", request_once)

    result = inspect_headers("https://example.test/")

    assert [call.args[0].url for call in request_once.call_args_list] == [
        "http://example.test/",
        "http://www.example.test/",
    ]
    assert result.http_to_https.status is CheckStatus.FAIL
    assert result.final_url == "http://www.example.test/"
    assert result.final_url.startswith("http://")
    assert "final response URL was http://www.example.test/" in result.http_to_https.message


def test_hsts_received_over_http_is_not_reported_as_effective(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    monkeypatch.setattr(
        "webchecker.header_checks._request_once",
        Mock(
            return_value=_ResponseSnapshot(
                200, {"Strict-Transport-Security": "max-age=31536000"}, None
            )
        ),
    )

    result = inspect_headers("http://example.test/")

    hsts = result.security_headers["Strict-Transport-Security"]
    assert hsts.status is CheckStatus.WARNING
    assert "browsers ignore it" in hsts.message


def test_header_inspection_follows_https_redirect_and_marks_missing_headers(
    monkeypatch,
):
    _resolve_to_public_ip(monkeypatch)
    request_once = Mock(
        side_effect=[
            _ResponseSnapshot(
                301,
                {"Location": "https://example.test/secure"},
                "https://example.test/secure",
            ),
            _ResponseSnapshot(
                200,
                {
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Security-Policy": "default-src 'self'",
                },
                None,
            ),
        ]
    )
    monkeypatch.setattr("webchecker.header_checks._request_once", request_once)

    result = inspect_headers("https://example.test/")

    assert [call.args[0].url for call in request_once.call_args_list] == [
        "http://example.test/",
        "https://example.test/secure",
    ]
    assert request_once.call_count == 2
    assert result.http_to_https.status is CheckStatus.PASS
    assert result.final_url == "https://example.test/secure"
    assert result.final_url.startswith("https://")
    assert result.security_headers["Strict-Transport-Security"].status is CheckStatus.PASS
    assert result.security_headers["Content-Security-Policy"].status is CheckStatus.PASS
    missing = result.security_headers["X-Content-Type-Options"]
    assert missing.status is CheckStatus.WARNING
    assert "not a certificate validation failure" in missing.message
    assert result.error is None


def test_headers_do_not_claim_http_response_is_https(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    monkeypatch.setattr(
        "webchecker.header_checks._request_once",
        Mock(return_value=_ResponseSnapshot(200, {}, None)),
    )

    result = inspect_headers("http://example.test/")

    assert result.http_to_https.status is CheckStatus.FAIL
    assert result.security_headers["Strict-Transport-Security"].status is CheckStatus.WARNING
    assert set(result.security_headers) == set(SECURITY_HEADERS)
    assert all(
        check.status is CheckStatus.WARNING
        for check in result.security_headers.values()
    )


def test_request_snapshot_uses_headers_returned_by_http_response(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response.headers.update(
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
    )
    response.url = "https://example.test/"
    response.raw = Mock()
    session_get = Mock(return_value=response)
    monkeypatch.setattr(requests.Session, "get", session_get)
    target = ValidatedTarget(
        url="https://example.test/",
        scheme="https",
        hostname="example.test",
        port=443,
        path_and_query="/",
        address=PUBLIC_IP,
    )

    snapshot = _request_once(target, timeout=2.0)

    assert snapshot.status_code == 200
    assert snapshot.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert snapshot.headers["Content-Security-Policy"] == "default-src 'self'"
    assert snapshot.headers["X-Content-Type-Options"] == "nosniff"
    session_get.assert_called_once()
    assert session_get.call_args.kwargs["allow_redirects"] is False
    assert session_get.call_args.kwargs["stream"] is True
    assert session_get.call_args.kwargs["verify"] is True


def test_restricted_redirect_destination_is_blocked_before_second_request(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    request_once = Mock(
        return_value=_ResponseSnapshot(302, {"Location": "http://127.0.0.1/admin"}, "http://127.0.0.1/admin")
    )
    monkeypatch.setattr("webchecker.header_checks._request_once", request_once)

    result = inspect_headers("http://example.test/")

    request_once.assert_called_once()
    assert result.error is not None
    assert "Redirect blocked for safety" in result.error
    assert result.http_to_https.status is CheckStatus.NOT_CHECKED
    assert all(
        check.status is CheckStatus.NOT_CHECKED
        for check in result.security_headers.values()
    )


def test_tls_verification_error_does_not_become_a_header_or_certificate_failure(
    monkeypatch,
):
    _resolve_to_public_ip(monkeypatch)
    monkeypatch.setattr(
        "webchecker.header_checks._request_once",
        Mock(side_effect=requests.exceptions.SSLError("untrusted issuer")),
    )

    result = inspect_headers("https://example.test/")

    assert result.error is not None
    assert "TLS certificate verification failed" in result.error
    assert result.http_to_https.status is CheckStatus.NOT_CHECKED
    assert all(
        check.status is CheckStatus.NOT_CHECKED
        for check in result.security_headers.values()
    )


def test_adapter_requires_tls_verification_and_pins_public_ip(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    target = validate_url("https://example.test/")
    adapter = _PinnedHTTPAdapter(target, 3.0)
    try:
        assert adapter._pool.cert_reqs == ssl.CERT_REQUIRED
        assert adapter._pool.assert_hostname == "example.test"
        assert adapter._pool.conn_kw["validated_ip"] == PUBLIC_IP
        with pytest.raises(requests.exceptions.SSLError, match="verification must remain enabled"):
            adapter.get_connection_with_tls_context(
                Mock(url=target.url), verify=False
            )
        with pytest.raises(requests.exceptions.InvalidURL, match="Proxy connections are disabled"):
            adapter.get_connection_with_tls_context(
                Mock(url=target.url), verify=True, proxies={"https": "http://localhost"}
            )
    finally:
        adapter.close()


def test_pinned_https_pool_connects_to_the_validated_ip(monkeypatch):
    _resolve_to_public_ip(monkeypatch)
    target = validate_url("https://example.test/")
    adapter = _PinnedHTTPAdapter(target, 3.0)
    connect = Mock(return_value=object())
    monkeypatch.setattr("webchecker.header_checks.socket.create_connection", connect)
    tls_socket = Mock()
    wrap_tls = Mock(
        return_value=SimpleNamespace(socket=tls_socket, is_verified=True)
    )
    monkeypatch.setattr(
        "urllib3.connection._ssl_wrap_socket_and_match_hostname", wrap_tls
    )
    try:
        connection = adapter._pool._new_conn()
        connection.connect()

        assert connect.call_args.args[0] == (PUBLIC_IP, 443)
        assert connect.call_args.kwargs["timeout"] == 3.0
        assert wrap_tls.call_args.kwargs["server_hostname"] == "example.test"
        assert wrap_tls.call_args.kwargs["cert_reqs"] == ssl.CERT_REQUIRED
    finally:
        adapter.close()


def test_certificate_inspection_rejects_private_destination_before_connecting(
    monkeypatch,
):
    connect = Mock()
    monkeypatch.setattr(socket, "create_connection", connect)

    result = inspect_certificate("127.0.0.1")

    assert result.error == "The URL resolves to a non-public network address."
    assert result.validity.status is CheckStatus.NOT_CHECKED
    connect.assert_not_called()
