"""Unit tests for functions using db in OWASP ZAP Historic Parser"""
import sys
import unittest
from unittest.mock import patch

from owasp_zap_historic_parser.runner import main


class TestDBFunctions(unittest.TestCase):
    """Unit Tests for runner.py"""

    @patch('owasp_zap_historic_parser.runner.process_zap_file')
    # pylint: disable=R0201
    def test_main(self, process_zap_file):
        """Tests main function"""
        sys.argv[1:] = ['-f', 'test_files/testReport.html']
        main()
        process_zap_file.assert_called()
