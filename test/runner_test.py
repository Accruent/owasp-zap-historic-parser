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

    def test_host(self):
        """Argument parser positive test for host"""
        sys.argv[1:] = ['-s', 'localhost']
        options = parse_options()
        self.assertEqual('localhost', options.ozh_host)

    def test_host_empty(self):
        """Argument parser negative test for host"""
        sys.argv[1:] = ['-s']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_port(self):
        """Argument parser positive test for port"""
        sys.argv[1:] = ['-t', '5000']
        options = parse_options()
        self.assertEqual('5000', options.ozh_port)

    def test_port_empty(self):
        """Argument parser negative test for port"""
        sys.argv[1:] = ['-t']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_user(self):
        """Argument parser positive test for user"""
        sys.argv[1:] = ['-u', 'username']
        options = parse_options()
        self.assertEqual('username', options.ozh_username)

    def test_user_empty(self):
        """Argument parser negative test for user"""
        sys.argv[1:] = ['-u']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_pass(self):
        """Argument parser positive test for pass"""
        sys.argv[1:] = ['-p', 'password']
        options = parse_options()
        self.assertEqual('password', options.ozh_password)

    def test_pass_empty(self):
        """Argument parser negative test for pass"""
        sys.argv[1:] = ['-p']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_project(self):
        """Argument parser positive test for project"""
        sys.argv[1:] = ['-n', 'test_project']
        options = parse_options()
        self.assertEqual('test_project', options.projectname)

    def test_project_empty(self):
        """Argument parser negative test for project"""
        sys.argv[1:] = ['-n']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_env(self):
        """Argument parser positive test for environment"""
        sys.argv[1:] = ['-e', 'QA_TEST']
        options = parse_options()
        self.assertEqual('QA_TEST', options.this_env)

    def test_env_empty(self):
        """Argument parser negative test for environment"""
        sys.argv[1:] = ['-e']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_scan(self):
        """Argument parser positive test for scan type"""
        sys.argv[1:] = ['-i', 'Active']
        options = parse_options()
        self.assertEqual('Active', options.scantype)

    def test_scan_empty(self):
        """Argument parser negative test for scan type"""
        sys.argv[1:] = ['-i']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_url(self):
        """Argument parser positive test for url link"""
        sys.argv[1:] = ['-l', 'https://www.google.com']
        options = parse_options()
        self.assertEqual('https://www.google.com', options.urllink)

    def test_url_empty(self):
        """Argument parser negative test for url link"""
        sys.argv[1:] = ['-l']
        with self.assertRaises(SystemExit):
            parse_options()

    def test_version(self):
        """Argument parser positive test for version"""
        sys.argv[1:] = ['-v', 'v0.1.1']
        options = parse_options()
        self.assertEqual('v0.1.1', options.version)

    def test_version_empty(self):
        """Argument parser negative test for version"""
        sys.argv[1:] = ['-v']
        with self.assertRaises(SystemExit):
            parse_options()
