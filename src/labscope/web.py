"""Collect HTTP metadata from explicitly authorized IPv4 endpoints."""

import http.client
import ipaddress
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit


BODY_LIMIT = 65536
SOCKET_TIMEOUT = 5


class TitleParser(HTMLParser):
    """Extract the first HTML title."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.finished = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self.finished:
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title" and self.in_title:
            self.in_title = False
            self.finished = True

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data)


def validate_url(
    url: str,
    allowed_targets: list[str],
    allowed_ports: list[int],
) -> tuple[str, str, int, str]:
    """Validate the destination before creating any connection."""
    if any(ord(character) <= 32 or ord(character) == 127 for character in url):
        raise ValueError("URLs must not contain whitespace or control characters.")

    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported.")

    if parsed.fragment:
        raise ValueError("Remove the URL fragment before inspection.")

    if parsed.hostname is None:
        raise ValueError("The URL must include an IPv4 address.")

    address = str(ipaddress.IPv4Address(parsed.hostname))
    port = parsed.port

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    if address not in allowed_targets:
        raise ValueError(f"Out-of-scope target: {address}")

    if port not in allowed_ports:
        raise ValueError(f"Out-of-scope port: {port}")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    return parsed.scheme, address, port, path


def inspect_http(
    url: str,
    allowed_targets: list[str],
    allowed_ports: list[int],
) -> dict:
    """Make one GET request without following redirects."""
    scheme, address, port, path = validate_url(
        url, allowed_targets, allowed_ports
    )

    connection_type = (
        http.client.HTTPSConnection
        if scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_type(address, port, timeout=SOCKET_TIMEOUT)

    try:
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "LabScope/0.1.0",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )

        with connection.getresponse() as response:
            body = response.read(BODY_LIMIT + 1)
            truncated = len(body) > BODY_LIMIT
            body = body[:BODY_LIMIT]

            title = None
            content_type = response.getheader("Content-Type", "")
            encoding = response.getheader("Content-Encoding", "identity")

            if (
                "text/html" in content_type.lower()
                and encoding.lower() == "identity"
            ):
                charset = response.headers.get_content_charset() or "utf-8"
                parser = TitleParser()
                parser.feed(body.decode(charset, errors="replace"))
                title = " ".join("".join(parser.parts).split()) or None

            return {
                "url": url,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "address": address,
                "port": port,
                "status": response.status,
                "reason": response.reason,
                "headers": [
                    {"name": name, "value": value}
                    for name, value in response.getheaders()
                ],
                "title": title,
                "body_bytes_sampled": len(body),
                "body_truncated": truncated,
                "redirect_followed": False,
            }

    except (OSError, http.client.HTTPException, LookupError) as error:
        raise RuntimeError(f"HTTP inspection failed: {error}") from error
    finally:
        connection.close()
