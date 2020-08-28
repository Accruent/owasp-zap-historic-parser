"""Unit tests for functions used in OWASP ZAP Historic Parser runner"""
import sys
import unittest

from owasp_zap_historic_parser.runner import parse_options


class TestRunner(unittest.TestCase):
    """Unit Tests for runner.py"""
    def test_filename(self):
        """Argument parser positive test for filename"""
        sys.argv[1:] = ['-f', 'empty.html']
        options = parse_options()
        self.assertEqual('empty.html', options.filename)

    def test_filename_empty(self):
        """Argument parser negative test for filename"""
        sys.argv[1:] = ['-f']
        with self.assertRaises(SystemExit):
            parse_options()


if __name__ == '__main__':
    unittest.main()
