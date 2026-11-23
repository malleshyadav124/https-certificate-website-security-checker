from contextlib import nullcontext
import socket
import ssl
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from webchecker.certificate_inspection import (
    CheckStatus,
    inspect_certificate,
)


def _certificate(
    not_before="Jan  1 00:00:00 2020 GMT",
    not_after="Jan  1 00:00:00 2099 GMT",
):
    return {
        "notBefore": not_before,
        "notAfter": not_after,
        "issuer": ((("commonName", "Example Root CA"),),),
    }


def _configure_success(monkeypatch, certificate=None):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
        ),
    )
    context = Mock()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    tls_connection = Mock()
    tls_connection.getpeercert.return_value = certificate or _certificate()
    tls_connection.version.return_value = "TLSv1.3"
    tls_connection.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    context.wrap_socket = Mock(return_value=nullcontext(tls_connection))
    create_context = Mock(return_value=context)
    create_connection = Mock(return_value=nullcontext(object()))
    monkeypatch.setattr(ssl, "create_default_context", create_context)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    return context, create_context, create_connection


def _verification_error(code, message):
    error = ssl.SSLCertVerificationError(message)
    error.verify_code = code
    error.verify_message = message
    return error


def test_inspects_valid_certificate_using_default_verifying_context(monkeypatch):
    context, create_context, create_connection = _configure_success(monkeypatch)

    result = inspect_certificate("example.test", port=8443, timeout=2.5)

    create_context.assert_called_once_with()
    create_connection.assert_called_once_with(("93.184.216.34", 8443), timeout=2.5)
    context.wrap_socket.assert_called_once()
    assert context.wrap_socket.call_args.kwargs == {"server_hostname": "example.test"}
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert result.validity.status is CheckStatus.PASS
    assert result.hostname_match.status is CheckStatus.PASS
    assert result.chain_trust.status is CheckStatus.PASS
    assert result.not_before == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert result.expires_at == datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert result.issuer == "commonName=Example Root CA"
    assert result.tls_version == "TLSv1.3"
    assert result.cipher_name == "TLS_AES_256_GCM_SHA384"
    assert result.cipher_protocol == "TLSv1.3"
    assert result.error is None


@pytest.mark.parametrize(
    ("verify_code", "message", "failed_check"),
    [
        (10, "certificate has expired", "validity"),
        (9, "certificate is not yet valid", "validity"),
        (62, "hostname mismatch", "hostname_match"),
        (20, "unable to get local issuer certificate", "chain_trust"),
    ],
)
def test_reports_certificate_verification_failures(
    monkeypatch, verify_code, message, failed_check
):
    error = _verification_error(verify_code, message)
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
        ),
    )
    context = Mock()
    context.wrap_socket = Mock(side_effect=error)
    monkeypatch.setattr(ssl, "create_default_context", Mock(return_value=context))
    monkeypatch.setattr(
        socket, "create_connection", Mock(return_value=nullcontext(object()))
    )

    result = inspect_certificate("example.test")

    assert getattr(result, failed_check).status is CheckStatus.FAIL
    assert message in getattr(result, failed_check).message
    assert result.error is not None
    assert message in result.error
    assert result.expires_at is None
    assert result.issuer is None


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (TimeoutError("timeout"), "connection timed out"),
        (ssl.SSLError("protocol failure"), "TLS error"),
        (ConnectionRefusedError("refused"), "Could not connect"),
    ],
)
def test_reports_connection_failures(monkeypatch, exception, expected_error):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
        ),
    )
    context = Mock()
    monkeypatch.setattr(ssl, "create_default_context", Mock(return_value=context))
    create_connection = Mock(side_effect=exception)
    monkeypatch.setattr(socket, "create_connection", create_connection)

    result = inspect_certificate("example.test")

    assert expected_error.lower() in result.error.lower()
    assert result.validity.status is CheckStatus.NOT_CHECKED
    assert result.hostname_match.status is CheckStatus.NOT_CHECKED
    assert result.chain_trust.status is CheckStatus.NOT_CHECKED
    context.wrap_socket.assert_not_called()


def test_reports_dns_resolution_failure_without_connecting(monkeypatch):
    monkeypatch.setattr(
        "webchecker.url_validation.socket.getaddrinfo",
        Mock(side_effect=socket.gaierror("resolution failed")),
    )
    create_connection = Mock()
    monkeypatch.setattr(socket, "create_connection", create_connection)

    result = inspect_certificate("example.test")

    assert result.error == "The URL hostname could not be resolved."
    assert result.validity.status is CheckStatus.NOT_CHECKED
    create_connection.assert_not_called()


@pytest.mark.parametrize(
    ("hostname", "port", "timeout"),
    [
        ("https://example.test/path", 443, 5),
        ("example.test/path", 443, 5),
        ("example.test", 0, 5),
        ("example.test", 443, 0),
        ("example.test", 443, 61),
        ("example.test", 443, float("inf")),
        ("example.test", 443, 10**400),
    ],
)
def test_rejects_invalid_input_without_connecting(
    monkeypatch, hostname, port, timeout
):
    create_connection = Mock()
    monkeypatch.setattr(socket, "create_connection", create_connection)

    result = inspect_certificate(hostname, port=port, timeout=timeout)

    assert result.error == "Invalid hostname, port, or timeout."
    assert result.validity.status is CheckStatus.NOT_CHECKED
    create_connection.assert_not_called()


def test_rejects_expired_certificate_details(monkeypatch):
    _configure_success(
        monkeypatch, _certificate(not_after="Jan  1 00:00:00 2000 GMT")
    )

    result = inspect_certificate("example.test")

    assert result.validity.status is CheckStatus.FAIL
    assert result.validity.message == "The certificate has expired."
    assert result.expires_at == datetime(2000, 1, 1, tzinfo=timezone.utc)
