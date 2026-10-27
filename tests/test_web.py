"""Test HTTP inspection and scope enforcement without network traffic."""

import unittest
from email.message import Message
from unittest.mock import MagicMock, patch

from labscope.web import BODY_LIMIT, inspect_http, validate_url


class WebTests(unittest.TestCase):
    def setUp(self):
        self.targets = ["127.0.0.1"]
        self.ports = [8002]

        http_patch = patch("labscope.web.http.client.HTTPConnection")
        self.http = http_patch.start()
        self.addCleanup(http_patch.stop)

        https_patch = patch("labscope.web.http.client.HTTPSConnection")
        self.https = https_patch.start()
        self.addCleanup(https_patch.stop)

        self.connection = self.http.return_value
        self.response = MagicMock()
        self.connection.getresponse.return_value.__enter__.return_value = (
            self.response
        )

        headers = Message()
        headers["Content-Type"] = "text/html; charset=utf-8"

        self.response.headers = headers
        self.response.status = 200
        self.response.reason = "OK"
        self.response.read.return_value = (
            b"<html><title>Lab &amp; Shop</title></html>"
        )
        self.response.getheader.side_effect = (
            lambda name, default=None: headers.get(name, default)
        )
        self.response.getheaders.return_value = list(headers.items())

    def inspect(self, url="http://127.0.0.1:8002/"):
        return inspect_http(url, self.targets, self.ports)

    def test_collects_status_headers_and_title(self):
        result = self.inspect()

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["title"], "Lab & Shop")
        self.assertIn(
            {
                "name": "Content-Type",
                "value": "text/html; charset=utf-8",
            },
            result["headers"],
        )
        self.assertFalse(result["body_truncated"])
        self.connection.close.assert_called_once()

    def test_out_of_scope_ip_never_creates_connection(self):
        with self.assertRaisesRegex(ValueError, "Out-of-scope target"):
            self.inspect("http://192.0.2.10:8002/")

        self.http.assert_not_called()
        self.https.assert_not_called()

    def test_out_of_scope_port_never_creates_connection(self):
        with self.assertRaisesRegex(ValueError, "Out-of-scope port"):
            self.inspect("http://127.0.0.1:9000/")

        self.http.assert_not_called()
        self.https.assert_not_called()

    def test_redirect_is_recorded_without_following_it(self):
        self.response.status = 302
        self.response.reason = "Found"
        self.response.read.return_value = b""
        self.response.getheaders.return_value = [
            ("Location", "http://192.0.2.10/private")
        ]

        result = self.inspect()

        self.assertEqual(result["status"], 302)
        self.assertFalse(result["redirect_followed"])
        self.assertIn(
            {
                "name": "Location",
                "value": "http://192.0.2.10/private",
            },
            result["headers"],
        )
        self.http.assert_called_once()
        self.connection.request.assert_called_once()
        self.https.assert_not_called()

    def test_large_body_is_marked_truncated(self):
        self.response.read.return_value = b"x" * (BODY_LIMIT + 1)

        result = self.inspect()

        self.assertTrue(result["body_truncated"])
        self.assertEqual(result["body_bytes_sampled"], BODY_LIMIT)
        self.response.read.assert_called_once_with(BODY_LIMIT + 1)

    def test_timeout_closes_connection_and_reports_failure(self):
        self.connection.request.side_effect = TimeoutError("timed out")

        with self.assertRaisesRegex(RuntimeError, "HTTP inspection failed"):
            self.inspect()

        self.connection.close.assert_called_once()

    def test_credentials_in_url_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Credentials"):
            self.inspect("http://user:password@127.0.0.1:8002/")

        self.http.assert_not_called()
        self.https.assert_not_called()

    def test_https_default_port_and_query_are_preserved(self):
        result = validate_url(
            "https://127.0.0.1/search?q=lab",
            self.targets,
            [443],
        )

        self.assertEqual(
            result,
            ("https", "127.0.0.1", 443, "/search?q=lab"),
        )
        self.http.assert_not_called()
        self.https.assert_not_called()


if __name__ == "__main__":
    unittest.main()
