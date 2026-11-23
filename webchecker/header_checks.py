"""Safely inspect HTTP-to-HTTPS redirects and selected response headers."""

from __future__ import annotations

import logging
import math
import socket
import ssl
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from webchecker.check_results import CheckResult, CheckStatus
from webchecker.url_validation import URLValidationError, ValidatedTarget, validate_url

logger = logging.getLogger(__name__)

MAX_TIMEOUT_SECONDS = 60.0
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 1_000_000
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
)
_REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))


@dataclass(frozen=True)
class HeaderInspection:
    url: str
    http_to_https: CheckResult
    security_headers: Mapping[str, CheckResult]
    final_url: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class _ResponseSnapshot:
    status_code: int
    headers: Mapping[str, str]
    location: str | None


class _PinnedConnectionMixin:
    def __init__(self, *args, validated_ip: str, **kwargs):
        self._validated_ip = validated_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        timeout = self.timeout
        if hasattr(timeout, "connect_timeout"):
            timeout = timeout.connect_timeout
        return socket.create_connection(
            (self._validated_ip, self.port),
            timeout=timeout,
            source_address=self.source_address,
        )


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedHTTPAdapter(HTTPAdapter):
    """Use a pre-validated IP while retaining the original HTTP/TLS hostname."""

    def __init__(self, target: ValidatedTarget, timeout: float):
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)
        self._target = target
        self._timeout = timeout
        self._pool = self._create_pool(target)

    def _create_pool(self, target: ValidatedTarget):
        if target.scheme == "https":
            return _PinnedHTTPSConnectionPool(
                host=target.hostname,
                port=target.port,
                timeout=self._timeout,
                maxsize=1,
                block=True,
                retries=False,
                validated_ip=target.address,
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=requests.certs.where(),
                assert_hostname=target.hostname,
                server_hostname=target.hostname,
            )
        return _PinnedHTTPConnectionPool(
            host=target.hostname,
            port=target.port,
            timeout=self._timeout,
            maxsize=1,
            block=True,
            retries=False,
            validated_ip=target.address,
        )

    def get_connection_with_tls_context(
        self, request, verify, proxies=None, cert=None
    ):
        if verify is not True:
            raise requests.exceptions.SSLError(
                "TLS certificate verification must remain enabled."
            )
        if cert is not None:
            raise requests.exceptions.InvalidURL(
                "Client certificates are not used for website inspection."
            )
        self._validate_request_url(request.url)
        if proxies:
            raise requests.exceptions.InvalidURL(
                "Proxy connections are disabled for safe website inspection."
            )
        return self._pool

    def get_connection(self, url, proxies=None):
        self._validate_request_url(url)
        if proxies:
            raise requests.exceptions.InvalidURL(
                "Proxy connections are disabled for safe website inspection."
            )
        return self._pool

    def _validate_request_url(self, url: str) -> None:
        parsed = urlsplit(url)
        port = parsed.port
        effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme != self._target.scheme
            or parsed.hostname != self._target.hostname
            or effective_port != self._target.port
        ):
            raise requests.exceptions.InvalidURL(
                "The request URL does not match the validated destination."
            )

    def close(self):
        self._pool.close()
        super().close()


def inspect_headers(
    url: str, timeout: float = 5.0, max_redirects: int = MAX_REDIRECTS
) -> HeaderInspection:
    """Follow a bounded redirect chain safely and inspect final response headers.

    The check starts with HTTP to test whether that origin upgrades visitors to
    HTTPS. Each URL is resolved and screened again before the connection, and
    the connection is pinned to one of the checked public IP addresses.
    """
    if not _is_valid_timeout(timeout) or not _is_valid_redirect_limit(max_redirects):
        return _failed_inspection(url, "Invalid timeout or redirect limit.")

    try:
        initial = validate_url(url)
        http_url = _as_http_url(initial)
        target = validate_url(http_url)
    except URLValidationError as error:
        return _failed_inspection(url, str(error))

    saw_https_redirect = False
    response_snapshot: _ResponseSnapshot | None = None
    current = target

    for redirect_number in range(max_redirects + 1):
        try:
            response_snapshot = _request_once(current, timeout)
        except requests.exceptions.SSLError:
            logger.info("Header inspection stopped: TLS verification failed.")
            return _failed_inspection(
                url, "TLS certificate verification failed during the HTTP header check."
            )
        except requests.exceptions.Timeout:
            logger.info("Header inspection stopped: request timed out.")
            return _failed_inspection(url, "The website request timed out.")
        except requests.RequestException:
            logger.info("Header inspection stopped: HTTP request failed.")
            return _failed_inspection(url, "The website could not be reached for header checks.")
        except (OSError, ssl.SSLError):
            logger.info("Header inspection stopped: connection or TLS failure.")
            return _failed_inspection(
                url, "A connection or TLS error prevented the header check."
            )

        if (
            response_snapshot.status_code not in _REDIRECT_STATUSES
            or not response_snapshot.location
        ):
            break
        if redirect_number >= max_redirects:
            return _failed_inspection(url, "The website exceeded the redirect limit.")

        destination_url = urljoin(current.url, response_snapshot.location)
        try:
            destination = validate_url(destination_url)
        except URLValidationError as error:
            return _failed_inspection(
                url, f"Redirect blocked for safety: {error}"
            )

        if current.scheme == "http" and destination.scheme == "https":
            saw_https_redirect = True
        current = destination

    if response_snapshot is None:
        return _failed_inspection(url, "No HTTP response was received.")

    final_is_https = current.scheme == "https"
    if saw_https_redirect and final_is_https:
        redirect_check = CheckResult(
            CheckStatus.PASS, "HTTP visitors were redirected to an HTTPS destination."
        )
    else:
        redirect_check = CheckResult(
            CheckStatus.FAIL,
            f"HTTP did not lead to a final HTTPS destination; the final response URL was {current.url}.",
        )

    header_results = _inspect_security_headers(
        response_snapshot.headers, is_https=final_is_https
    )
    return HeaderInspection(
        url=url,
        http_to_https=redirect_check,
        security_headers=header_results,
        final_url=current.url,
    )


def _request_once(target: ValidatedTarget, timeout: float) -> _ResponseSnapshot:
    adapter = _PinnedHTTPAdapter(target, timeout)
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount(f"{target.scheme}://", adapter)
            with session.get(
                target.url,
                allow_redirects=False,
                stream=True,
                timeout=(timeout, timeout),
                verify=True,
                headers={"User-Agent": "Webchecker/1.0"},
            ) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        if int(content_length) > MAX_RESPONSE_BYTES:
                            raise requests.exceptions.RequestException(
                                "The response exceeds the permitted size."
                            )
                    except ValueError:
                        pass
                return _ResponseSnapshot(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    location=response.headers.get("Location"),
                )
    finally:
        adapter.close()


def _inspect_security_headers(
    headers: Mapping[str, str], *, is_https: bool
) -> dict[str, CheckResult]:
    normalized = {name.lower(): value.strip() for name, value in headers.items()}
    results: dict[str, CheckResult] = {}

    for header in SECURITY_HEADERS:
        present = bool(normalized.get(header.lower()))
        if header == "Strict-Transport-Security" and not is_https:
            if present:
                message = (
                    "HSTS was returned over HTTP, where browsers ignore it; "
                    "the policy is not effective."
                )
            else:
                message = (
                    "HSTS was not observed on the final HTTP response; browsers "
                    "ignore HSTS received over HTTP."
                )
            results[header] = CheckResult(CheckStatus.WARNING, message)
        elif present:
            results[header] = CheckResult(
                CheckStatus.PASS, f"{header} is present."
            )
        else:
            results[header] = CheckResult(
                CheckStatus.WARNING,
                f"{header} is missing; this is a security-header finding, "
                "not a certificate validation failure.",
            )
    return results


def _as_http_url(target: ValidatedTarget) -> str:
    parsed = urlsplit(target.url)
    authority_host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    default_port = 443 if target.scheme == "https" else 80
    port = None if target.port == default_port else target.port
    authority = authority_host if port is None else f"{authority_host}:{port}"
    return parsed._replace(scheme="http", netloc=authority).geturl()


def _is_valid_timeout(timeout: float) -> bool:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        return False
    try:
        value = float(timeout)
    except OverflowError:
        return False
    return math.isfinite(value) and 0 < value <= MAX_TIMEOUT_SECONDS


def _is_valid_redirect_limit(max_redirects: int) -> bool:
    return (
        isinstance(max_redirects, int)
        and not isinstance(max_redirects, bool)
        and 0 <= max_redirects <= 10
    )


def _failed_inspection(url: str, message: str) -> HeaderInspection:
    not_checked = CheckResult(CheckStatus.NOT_CHECKED, message)
    headers = {
        name: CheckResult(CheckStatus.NOT_CHECKED, message)
        for name in SECURITY_HEADERS
    }
    return HeaderInspection(
        url=url,
        http_to_https=not_checked,
        security_headers=headers,
        error=message,
    )
