"""Unit tests for functions used in OWASP ZAP Historic Parser"""
import unittest

from owasp_zap_historic_parser.owasp_zap_historical import convert_alert_to_dictionary
from owasp_zap_historic_parser.owasp_zap_historical import html_parser


class TestFunctions(unittest.TestCase):
    """Unit Tests for functions"""

    def test_convert_alert_to_dictionary_one_tuple(self):
        """This test verifies that convert_alert_to_dictionary converts a single
        into a formatted dictionary. """
        test_tuple = [("Test Level", "Test Alert", 3)]
        expected_tuple = "{'Test Level | Test Alert': {'Alert Level': 'Test Level', " \
                         "'Alert Type': 'Test Alert', 'URLs Affected': 3}}"
        result_tuple = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_tuple), expected_tuple)

    def test_convert_alert_to_dictionary_multi_tuple(self):
        """This test verifies that convert_alert_to_dictionary converts a list of alerts
        into a formatted dictionary. """
        test_tuple = [("Test Level", "Test Alert A", 3), ("Test Level 2", "Test Alert B", 6)]
        expected_tuple = "{'Test Level | Test Alert A': {'Alert Level': 'Test Level', " \
                         "'Alert Type': 'Test Alert A', 'URLs Affected': 3}, 'Test Level 2 " \
                         "| Test Alert B': {'Alert Level': 'Test Level 2', 'Alert Type': " \
                         "'Test Alert B', 'URLs Affected': 6}}"
        result_tuple = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_tuple), expected_tuple)

    def test_convert_utc_to_cst_no_date_empty(self):
        """This test verifies that convert_alert_to_dictionary returns an empty dictionary
        if it is passed an empty list."""
        test_tuple = []
        expected_tuple = "{}"
        result_tuple = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_tuple), expected_tuple)

    def test_html_parser(self):
        """This test verifies that the html parser correctly parses a zap file."""
        result = html_parser("test_files/testReport.html")
        expected_result = "[['Medium', 'X-Frame-Options Header Not Set', 1], ['Low', 'Cookie " \
                          "Without SameSite Attribute', 10], ['Low', 'X-Content-Type-Options " \
                          "Header Missing', 8], ['Low', 'Server Leaks Information via " \
                          "\"X-Powered-By\" HTTP Response Header Field(s)', 8], ['Low', 'Web " \
                          "Browser XSS Protection Not Enabled', 1], ['Low', 'Cookie No HttpOnly " \
                          "Flag', 3], ['Low', 'Incomplete or No Cache-control and Pragma HTTP " \
                          "Header Set', 4], ['Low', 'Absence of Anti-CSRF Tokens', 2], " \
                          "['Informational', 'Information Disclosure - Suspicious Comments', 4], " \
                          "['Informational', 'Timestamp Disclosure - Unix', 4]]"
        self.assertEqual(str(result), expected_result)

    def test_html_parser_empty(self):
        """This test verifies that the html parser correctly parses an empty file."""
        result = html_parser("test_files/empty.html")
        # print(result)
        expected_result = "[]"
        self.assertEqual(str(result), expected_result)
