#!/usr/bin/env python3
"""
Comprehensive tests for Stored XSS vulnerability remediation in dsvw.py

This test suite validates that the XSS vulnerability fix properly prevents
malicious script injection through pickled objects while maintaining
legitimate functionality.
"""

import unittest
import pickle
import urllib.parse
import http.client
import time
import threading
from dsvw import ReqHandler, ThreadingServer, init, LISTEN_ADDRESS


class TestStoredXSSRemediation(unittest.TestCase):
    """Test suite for validating XSS vulnerability fix in pickle object handling"""

    @classmethod
    def setUpClass(cls):
        """Start the test server once for all tests"""
        # Initialize the database
        init()

        # Use a different port for testing to avoid conflicts
        cls.test_port = 65413
        cls.server = ThreadingServer((LISTEN_ADDRESS, cls.test_port), ReqHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Give the server time to start
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Shutdown the test server"""
        cls.server.shutdown()
        cls.server.server_close()

    def _make_request(self, path):
        """Helper method to make HTTP requests to the test server"""
        conn = http.client.HTTPConnection(LISTEN_ADDRESS, self.test_port, timeout=5)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read().decode('utf-8', errors='ignore')
            return response.status, body
        finally:
            conn.close()

    def test_xss_attack_blocked_script_tag(self):
        """
        Test that XSS attack with <script> tag is blocked.

        This test verifies that a malicious payload containing <script>alert('XSS')</script>
        is properly HTML-encoded and does not execute as JavaScript.
        """
        # Create a malicious payload with script tag
        malicious_data = {
            "user1": "<script>alert('XSS')</script>",
            "user2": "normal_data"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        # Verify the response is successful
        self.assertEqual(status, 200)

        # Verify the script tag is HTML-encoded and not executable
        self.assertIn("&lt;script&gt;", body, "Script opening tag should be HTML-encoded")
        self.assertIn("&lt;/script&gt;", body, "Script closing tag should be HTML-encoded")

        # Verify raw script tags are NOT present (would be exploitable)
        self.assertNotIn("<script>alert", body, "Raw script tag should not be present")

    def test_xss_attack_blocked_img_onerror(self):
        """
        Test that XSS attack with <img onerror> is blocked.

        This test verifies that event handler-based XSS attacks are properly
        HTML-encoded and cannot execute.
        """
        malicious_data = {
            "user": "<img src=x onerror='alert(\"XSS\")'>"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify HTML encoding of dangerous characters
        self.assertIn("&lt;img", body, "Image tag should be HTML-encoded")
        self.assertIn("onerror=", body.replace("&quot;", "").replace("&#x27;", ""))

        # Verify the attack payload is neutralized
        self.assertNotIn("<img src=x onerror=", body, "Raw img tag with onerror should not be present")

    def test_xss_attack_blocked_iframe(self):
        """
        Test that XSS attack with <iframe> is blocked.

        This test verifies that iframe-based attacks are properly encoded.
        """
        malicious_data = {
            "content": "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify iframe is HTML-encoded
        self.assertIn("&lt;iframe", body, "Iframe tag should be HTML-encoded")
        self.assertIn("&lt;/iframe&gt;", body, "Iframe closing tag should be HTML-encoded")
        self.assertNotIn("<iframe src='javascript:", body, "Raw iframe should not be present")

    def test_xss_attack_blocked_svg_onload(self):
        """
        Test that XSS attack with <svg onload> is blocked.

        This test verifies that SVG-based XSS attacks are properly encoded.
        """
        malicious_data = {
            "payload": "<svg/onload=alert('XSS')>"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify SVG is HTML-encoded
        self.assertIn("&lt;svg", body, "SVG tag should be HTML-encoded")
        self.assertIn("onload=", body.replace("&quot;", "").replace("&#x27;", ""))
        self.assertNotIn("<svg/onload=alert", body, "Raw SVG with onload should not be present")

    def test_xss_attack_blocked_anchor_javascript(self):
        """
        Test that XSS attack with javascript: protocol in anchor is blocked.
        """
        malicious_data = {
            "link": "<a href='javascript:alert(\"XSS\")'>Click me</a>"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify anchor tag is HTML-encoded
        self.assertIn("&lt;a href=", body, "Anchor tag should be HTML-encoded")
        self.assertIn("&lt;/a&gt;", body, "Anchor closing tag should be HTML-encoded")
        self.assertNotIn("<a href='javascript:", body, "Raw anchor with javascript: should not be present")

    def test_legitimate_data_preserved(self):
        """
        Test that legitimate data is still displayed correctly (functionality test).

        This test verifies that normal, non-malicious data is properly rendered
        and the HTML encoding doesn't break legitimate use cases.
        """
        legitimate_data = {
            "username1": "john_doe",
            "username2": "jane_smith",
            "username3": "admin"
        }
        pickled = pickle.dumps(legitimate_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify legitimate data is present in response
        self.assertIn("john_doe", body, "Legitimate username should be present")
        self.assertIn("jane_smith", body, "Legitimate username should be present")
        self.assertIn("admin", body, "Legitimate username should be present")

    def test_special_chars_encoded(self):
        """
        Test that special HTML characters are properly encoded.

        This test verifies that all HTML special characters that could be used
        in XSS attacks are properly encoded.
        """
        data_with_special_chars = {
            "test": "< > & \" ' Test & Data"
        }
        pickled = pickle.dumps(data_with_special_chars)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify special characters are HTML-encoded
        self.assertIn("&lt;", body, "Less-than should be encoded")
        self.assertIn("&gt;", body, "Greater-than should be encoded")
        self.assertIn("&amp;", body, "Ampersand should be encoded")
        # Note: quotes may be encoded as &quot; or &#x27; depending on html.escape behavior

    def test_nested_xss_payload_blocked(self):
        """
        Test that nested/obfuscated XSS payloads are blocked.

        This test verifies that attackers cannot bypass the fix with nested tags.
        """
        malicious_data = {
            "nested": "<<script>script>alert('XSS')<</script>/script>"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify nested tags are also encoded
        self.assertIn("&lt;&lt;script&gt;", body, "Nested script tags should be encoded")
        self.assertNotIn("<<script>script>", body, "Raw nested script should not be present")

    def test_mixed_content_with_xss_attempt(self):
        """
        Test that XSS attempts mixed with legitimate content are handled correctly.

        This test verifies that when an attacker mixes malicious and legitimate
        data, the malicious parts are neutralized while legitimate parts remain.
        """
        mixed_data = {
            "user1": "legitimate_user",
            "user2": "<script>alert('XSS')</script>",
            "user3": "another_user"
        }
        pickled = pickle.dumps(mixed_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify legitimate data is present
        self.assertIn("legitimate_user", body)
        self.assertIn("another_user", body)

        # Verify malicious data is encoded
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert('XSS')</script>", body)

    def test_empty_pickle_object(self):
        """
        Test that empty pickle objects are handled correctly.

        Edge case test to ensure the fix doesn't break with edge inputs.
        """
        empty_data = {}
        pickled = pickle.dumps(empty_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        # Should not crash, should return 200 OK
        self.assertEqual(status, 200)

    def test_xss_with_unicode_encoding(self):
        """
        Test that XSS attempts using Unicode encoding are blocked.

        This test verifies that attackers cannot bypass the fix using Unicode
        escape sequences.
        """
        malicious_data = {
            "unicode_xss": "\u003cscript\u003ealert('XSS')\u003c/script\u003e"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # Verify Unicode characters are converted to their actual values and then encoded
        self.assertIn("&lt;script&gt;", body, "Unicode-encoded script tag should be HTML-encoded")
        self.assertNotIn("<script>alert", body, "Raw script should not be present")


class TestXSSRegressionPrevention(unittest.TestCase):
    """Additional tests to prevent regression of the XSS vulnerability"""

    @classmethod
    def setUpClass(cls):
        """Start the test server once for all tests"""
        init()
        cls.test_port = 65414
        cls.server = ThreadingServer((LISTEN_ADDRESS, cls.test_port), ReqHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Shutdown the test server"""
        cls.server.shutdown()
        cls.server.server_close()

    def _make_request(self, path):
        """Helper method to make HTTP requests"""
        conn = http.client.HTTPConnection(LISTEN_ADDRESS, self.test_port, timeout=5)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read().decode('utf-8', errors='ignore')
            return response.status, body
        finally:
            conn.close()

    def test_common_xss_vectors_blocked(self):
        """
        Test that common XSS attack vectors from OWASP are all blocked.

        This comprehensive test uses multiple known XSS payloads to ensure
        robust protection.
        """
        xss_vectors = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<div style='background:url(javascript:alert(\"XSS\"))'>",
        ]

        for vector in xss_vectors:
            with self.subTest(vector=vector):
                data = {"payload": vector}
                pickled = pickle.dumps(data)
                encoded_param = urllib.parse.quote(pickled)

                status, body = self._make_request(f"/?object={encoded_param}")

                self.assertEqual(status, 200)

                # Verify the vector is encoded (contains &lt; or &gt;)
                self.assertTrue(
                    "&lt;" in body or "&gt;" in body,
                    f"XSS vector should be HTML-encoded: {vector}"
                )

                # Verify the raw vector is not present
                self.assertNotIn(
                    vector,
                    body,
                    f"Raw XSS vector should not be present: {vector}"
                )

    def test_double_encoding_not_vulnerable(self):
        """
        Test that double-encoded XSS attempts are also blocked.

        This test ensures the fix handles cases where attackers attempt
        to use double encoding to bypass filters.
        """
        # Pre-encoded malicious payload
        malicious_data = {
            "double": "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        }
        pickled = pickle.dumps(malicious_data)
        encoded_param = urllib.parse.quote(pickled)

        status, body = self._make_request(f"/?object={encoded_param}")

        self.assertEqual(status, 200)

        # The already-encoded entities should be encoded again
        # so &lt; becomes &amp;lt;
        self.assertIn("&amp;lt;", body, "Already-encoded characters should be double-encoded")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
