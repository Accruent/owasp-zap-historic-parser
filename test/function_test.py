"""Unit tests for functions used in OWASP ZAP Historic Parser"""
import unittest
import os

from owasp_zap_historic_parser.owasp_zap_historical import convert_alert_to_dictionary
from owasp_zap_historic_parser.owasp_zap_historical import compare_zap_results
from owasp_zap_historic_parser.owasp_zap_historical import html_parser
from owasp_zap_historic_parser.owasp_zap_historical import get_alert_table_row
from owasp_zap_historic_parser.owasp_zap_historical import get_locators

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
THIS_DATE = "Aug 30 2020 10:43 PM CDT"
COMP_DATE = "Jul 30 2020 9:43 PM CDT"


class TestFunctions(unittest.TestCase):
    """Unit Tests for functions"""

    def test_convert_alert_to_dictionary_one_tuple(self):
        """This test verifies that convert_alert_to_dictionary converts a single
        into a formatted dictionary. """
        test_tuple = [("Test Level", "Test Alert", 3)]
        expected_dictionary = "{'Test Level | Test Alert': {'Alert Level': 'Test Level', " \
                              "'Alert Type': 'Test Alert', 'URLs Affected': 3}}"
        result_dictionary = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_dictionary), expected_dictionary)

    def test_convert_alert_to_dictionary_multi_tuple(self):
        """This test verifies that convert_alert_to_dictionary converts a list of alerts
        into a formatted dictionary. """
        test_tuple = [("Test Level", "Test Alert A", 3), ("Test Level 2", "Test Alert B", 6)]
        expected_dictionary = "{'Test Level | Test Alert A': {'Alert Level': 'Test Level', " \
                              "'Alert Type': 'Test Alert A', 'URLs Affected': 3}, 'Test Level 2 " \
                              "| Test Alert B': {'Alert Level': 'Test Level 2', 'Alert Type': " \
                              "'Test Alert B', 'URLs Affected': 6}}"
        result_dictionary = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_dictionary), expected_dictionary)

    def test_convert_utc_to_cst_no_date_empty(self):
        """This test verifies that convert_alert_to_dictionary returns an empty dictionary
        if it is passed an empty list."""
        test_tuple = []
        expected_dictionary = "{}"
        result_dictionary = convert_alert_to_dictionary(test_tuple)
        self.assertEqual(str(result_dictionary), expected_dictionary)

    def test_html_parser(self):
        """This test verifies that the html parser correctly parses a zap file."""
        file_path = ROOT_PATH + "/" + "test_files/testReport.html"
        result = html_parser(file_path)
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

    def test_html_parser_same(self):
        """This test verifies that the html parser correctly parses a zap file."""
        file_path = ROOT_PATH + "/" + "test_files/testReportWithSame.html"
        result = html_parser(file_path)
        expected_result = "[['Medium', 'X-Frame-Options Header Not Set', 11]]"
        self.assertEqual(str(result), expected_result)

    def test_html_parser_empty(self):
        """This test verifies that the html parser correctly parses an empty file."""
        file_path = ROOT_PATH + "/" + "test_files/empty.html"
        result = html_parser(file_path)
        expected_result = "[]"
        self.assertEqual(str(result), expected_result)

    def test_compare_zap_results_same(self):
        """This test verifies that compare zap results returns the alert table correctly."""
        this_dict = {'High | Same URL Count': {'Alert Level': 'High',
                                               'Alert Type': 'Same URL Count', 'URLs Affected': 3}}
        comp_dict = {'High | Same URL Count': {'Alert Level': 'High',
                                               'Alert Type': 'Same URL Count', 'URLs Affected': 3}}
        check_text = "Number of URLs Affected stayed the same"
        result = compare_zap_results(this_dict, comp_dict, THIS_DATE, COMP_DATE)
        self.assertTrue(check_text in result)

    def test_compare_zap_results_higher(self):
        """This test verifies that compare zap results returns the alert table correctly."""
        this_dict = {'Medium | Higher URL Count': {'Alert Level': 'Medium',
                                                   'Alert Type': 'Higher URL Count',
                                                   'URLs Affected': 4}}
        comp_dict = {'Medium | Higher URL Count': {'Alert Level': 'Medium',
                                                   'Alert Type': 'Higher URL Count',
                                                   'URLs Affected': 3}}
        check_text = "Number of URLs Affected increased"
        result = compare_zap_results(this_dict, comp_dict, THIS_DATE, COMP_DATE)
        self.assertTrue(check_text in result)

    def test_compare_zap_results_lower(self):
        """This test verifies that compare zap results returns the alert table correctly."""
        this_dict = {'Low | Lower URL Count': {'Alert Level': 'Low',
                                               'Alert Type': 'Lower URL Count',
                                               'URLs Affected': 2}}
        comp_dict = {'Low | Lower URL Count': {'Alert Level': 'Low',
                                               'Alert Type': 'Lower URL Count',
                                               'URLs Affected': 3}}
        check_text = "Number of URLs Affected decreased"
        result = compare_zap_results(this_dict, comp_dict, THIS_DATE, COMP_DATE)
        self.assertTrue(check_text in result)

    def test_compare_zap_results_new(self):
        """This test verifies that compare zap results returns the alert table correctly."""
        this_dict = {'Informational | First Alert': {'Alert Level': 'Informational',
                                                     'Alert Type': 'First Alert',
                                                     'URLs Affected': 2},
                     'Low | 2nd Alert': {'Alert Level': 'Low',
                                         'Alert Type': '2nd Alert',
                                         'URLs Affected': 2},
                     'Medium | 3rd Alert': {'Alert Level': 'Medium',
                                            'Alert Type': '3rd Alert',
                                            'URLs Affected': 2},
                     'High | 4th Alert': {'Alert Level': 'High',
                                          'Alert Type': '4th Alert',
                                          'URLs Affected': 2}
                     }
        comp_dict = {}
        check_text = "New Alert"
        result = compare_zap_results(this_dict, comp_dict, THIS_DATE, COMP_DATE)
        self.assertTrue(check_text in result)

    def test_compare_zap_results_resolved(self):
        """This test verifies that compare zap results returns the alert table correctly."""
        this_dict = {}
        comp_dict = {'High | Resolved Alert': {'Alert Level': 'High',
                                               'Alert Type': 'Resolved Alert',
                                               'URLs Affected': 2}}
        check_text = "Alert potentially resolved"
        result = compare_zap_results(this_dict, comp_dict, THIS_DATE, COMP_DATE)
        self.assertTrue(check_text in result)

    def test_get_alert_table_row_same(self):
        """This test verifies that get alert table row returns the row correctly."""
        exp_result = "<tr style='background-color: silver; color: white'><td style='border: " \
                     "1px solid #000;'><strong>Test</strong></td><td style='border: 1px solid " \
                     "#000;'><strong>Test Type</strong></td><td style=' border: 1px solid #000;'>" \
                     "<strong>3</strong></td><td style='border: 1px solid #000;'><strong>3" \
                     "</strong></td><td style='border: 1px solid #000;'><strong>Number of " \
                     "URLs Affected stayed the same</strong></td></tr>"
        result = get_alert_table_row("silver", "white", "Test", "Test Type", 3, 3)
        self.assertEqual(str(result), exp_result)

    def test_get_alert_table_row_higher(self):
        """This test verifies that get alert table row returns the row correctly."""
        exp_result = "<tr style='background-color: red; color: black'><td style='border: " \
                     "1px solid #000;'><strong>Test</strong></td><td style='border: 1px solid " \
                     "#000;'><strong>Test Type</strong></td><td style=' border: 1px solid #000;'>" \
                     "<strong>3</strong></td><td style='border: 1px solid #000;'><strong>2" \
                     "</strong></td><td style='border: 1px solid #000;'><strong>Number of URLs " \
                     "Affected increased</strong></td></tr>"
        result = get_alert_table_row("red", "black", "Test", "Test Type", 3, 2)
        self.assertEqual(str(result), exp_result)

    def test_get_alert_table_row_lower(self):
        """This test verifies that get alert table row returns the row correctly."""
        exp_result = "<tr style='background-color: yellow; color: white'><td style='border: " \
                     "1px solid #000;'><strong>Test</strong></td><td style='border: 1px solid " \
                     "#000;'><strong>Test Type</strong></td><td style=' border: 1px solid #000;'>"\
                     "<strong>1</strong></td><td style='border: 1px solid #000;'><strong>3" \
                     "</strong></td><td style='border: 1px solid #000;'><strong>Number of URLs " \
                     "Affected decreased</strong></td></tr>"
        result = get_alert_table_row("yellow", "white", "Test", "Test Type", 1, 3)
        self.assertEqual(str(result), exp_result)

    def test_get_alert_table_row_new(self):
        """This test verifies that get alert table row returns the row correctly."""
        exp_result = "<tr style='background-color: gray; color: black'><td style='border: 1px " \
                     "solid #000;'><strong>Test</strong></td><td style='border: 1px solid #000;'>"\
                     "<strong>Test Type</strong></td><td style=' border: 1px solid #000;'>" \
                     "<strong>1</strong></td><td style='border: 1px solid #000;'><strong>0" \
                     "</strong></td><td style='border: 1px solid #000;'><strong>New Alert" \
                     "</strong></td></tr>"
        result = get_alert_table_row("gray", "black", "Test", "Test Type", 1, 0)
        self.assertEqual(str(result), exp_result)

    def test_get_alert_table_row_resolved(self):
        """This test verifies that get alert table row returns the row correctly."""
        exp_result = "<tr style='background-color: black; color: white'><td style='border: 1px " \
                     "solid #000;'><strong>Test</strong></td><td style='border: 1px solid " \
                     "#000;'><strong>Test Type</strong></td><td style=' border: 1px solid #000" \
                     ";'><strong>0</strong></td><td style='border: 1px solid #000;'><strong>3" \
                     "</strong></td><td style='border: 1px solid #000;'><strong>Alert " \
                     "potentially resolved</strong></td></tr>"
        result = get_alert_table_row("black", "white", "Test", "Test Type", 0, 3)
        self.assertEqual(str(result), exp_result)

    def test_get_locators_new_locator(self):
        """This test verifies the proper locators are returned by the get locators function
        when a locator from a new zap report is passed in."""
        alert_result, url_count = get_locators("//table[@class='alerts']//td[.='High']", 3)
        exp_alert_result = "(//table[@class='alerts']//td[.='High'])[4]/../td[1]/a"
        exp_url_count = "(//table[@class='alerts']//td[.='High'])[4]/../td[3]"
        self.assertEqual(str(alert_result), exp_alert_result)
        self.assertEqual(str(url_count), exp_url_count)
