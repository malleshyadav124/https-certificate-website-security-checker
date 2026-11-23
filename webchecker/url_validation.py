"""Validate HTTP(S) targets and pin them to public DNS addresses."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    path_and_query: str
    address: str


class URLValidationError(ValueError):
    """Raised when a URL is malformed or resolves to a restricted address."""


def validate_url(url: str) -> ValidatedTarget:
    """Validate a URL, resolve it, and select a checked public address."""
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 2048
        or url != url.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in url)
    ):
        raise URLValidationError("Enter a valid HTTP or HTTPS URL.")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise URLValidationError("The URL has an invalid host or port.") from error

    if (
        parsed.scheme.lower() not in ("http", "https")
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "%" in hostname
    ):
        raise URLValidationError("Only HTTP(S) URLs without credentials are allowed.")

    scheme = parsed.scheme.lower()
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise URLValidationError("The URL has an invalid port.")

    normalized_host = _normalize_hostname(hostname)
    if normalized_host is None:
        raise URLValidationError("The URL has an invalid hostname.")

    address = _resolve_public_address(normalized_host, effective_port)
    authority_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    authority = authority_host
    if port is not None:
        authority = f"{authority}:{port}"
    path = parsed.path or "/"
    path_and_query = path + (f"?{parsed.query}" if parsed.query else "")
    normalized_url = urlunsplit((scheme, authority, path, parsed.query, ""))

    return ValidatedTarget(
        url=normalized_url,
        scheme=scheme,
        hostname=normalized_host,
        port=effective_port,
        path_and_query=path_and_query,
        address=address,
    )


def _normalize_hostname(hostname: str) -> str | None:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if len(ascii_hostname) > 253:
            return None
        if ascii_hostname.endswith("."):
            ascii_hostname = ascii_hostname[:-1]
        labels = ascii_hostname.split(".")
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
    return str(address)


def _resolve_public_address(hostname: str, port: int) -> str:
    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
        except (socket.gaierror, OSError) as error:
            raise URLValidationError("The URL hostname could not be resolved.") from error
        addresses = {record[4][0] for record in records}
    else:
        addresses = {str(literal_address)}

    if not addresses:
        raise URLValidationError("The URL hostname did not resolve to an address.")

    try:
        parsed_addresses = {ipaddress.ip_address(address) for address in addresses}
    except ValueError as error:
        raise URLValidationError("The URL hostname resolved to an invalid address.") from error

    if any(
        not address.is_global
        or address.is_reserved
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_unspecified
        for address in parsed_addresses
    ):
        raise URLValidationError("The URL resolves to a non-public network address.")

    return str(sorted(parsed_addresses, key=lambda address: (address.version, int(address)))[0])
