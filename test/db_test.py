"""Unit tests for functions using db in OWASP ZAP Historic Parser"""
import sys
import unittest
from unittest.mock import patch, MagicMock, call

from owasp_zap_historic_parser.owasp_zap_historical import connect_to_mysql_db, process_zap_file
from owasp_zap_historic_parser.runner import main, parse_options


class TestDBFunctions(unittest.TestCase):
    """Unit Tests for runner.py"""

    @patch('owasp_zap_historic_parser.runner.process_zap_file')
    # pylint: disable=R0201
    def test_main(self, pzf_mock):
        """Tests main function"""
        sys.argv[1:] = ['-f', 'test_files/testReport.html']
        main()
        pzf_mock.assert_called()

    @patch('mysql.connector.connect')
    def test_connect_to_mysql_db(self, connect_mock):
        """Tests the mysql connection function"""
        connect_mock.return_value = MagicMock(name='connection_return')
        args = (1, 2, 3, 4, 5)
        connect_to_mysql_db(*args)
        self.assertEqual(1, connect_mock.call_count)
        self.assertEqual(connect_mock.call_args_list[0], call(host=args[0], port=args[1],
                                                              user=args[2], passwd=args[3],
                                                              database=args[4]))

    @patch('owasp_zap_historic_parser.owasp_zap_historical.html_parser')
    @patch('mysql.connector.connect')
    @patch('owasp_zap_historic_parser.owasp_zap_historical.process_zap_results',
           return_value='some html code')
    def test_process_zap_file(self, mock_hp, mock_connect, mock_pzr):
        """Tests the process zap file function"""
        sys.argv[1:] = ['-f', 'test_files/testReport.html']
        options = parse_options()
        result = process_zap_file(options)
        self.assertEqual(1, mock_hp.call_count)
        self.assertEqual(2, mock_connect.call_count)
        self.assertEqual(1, mock_pzr.call_count)
        self.assertEqual(result, 'some html code')
