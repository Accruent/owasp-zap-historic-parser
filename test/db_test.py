"""Unit tests for functions using db in OWASP ZAP Historic Parser"""
import os
import sys
import unittest
import datetime
from unittest import mock
from unittest.mock import patch, MagicMock, call

from owasp_zap_historic_parser.owasp_zap_historical import connect_to_mysql_db, \
    process_zap_file, process_zap_results, html_parser
from owasp_zap_historic_parser.runner import main, parse_options

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
MOCK_DATE = datetime.datetime(2018, 5, 6, 5, 5, 5)


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

    def test_connect_to_mysql_db_error(self):
        """Tests the mysql connection function when connection fails"""
        args = (1, 2, 3, 4, 5)
        connect_to_mysql_db(*args)
        self.assertRaises(AttributeError)

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

    @patch('mysql.connector.connect')
    def test_process_zap_results_no_compare(self, mock_conn):
        """Tests the process zap file function"""
        file_path = ROOT_PATH + "/" + "test_files/testReport.html"
        mock_cursor = mock.Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (1, datetime.datetime(2018, 5, 6, 5, 5, 5))
        mock_cursor.description = (('name',), ('title',))
        zap_results = html_parser(file_path)
        args = (mock_conn, mock_conn, 'test', 'test', zap_results, 'test',
                'http://www.google.com', 'test')
        result = process_zap_results(*args)
        check_text = 'Not enough rows to compare results for test and test'
        self.assertTrue(check_text in result)

    @patch('mysql.connector.connect')
    def test_process_zap_results_compare_same(self, mock_conn):
        """Tests the process zap file function"""
        file_path = ROOT_PATH + "/" + "test_files/testReport.html"
        mock_cursor = mock.Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.side_effect = [(1, datetime.datetime(2018, 1, 6, 5, 5, 5)),
                                            (2, ), (2, ), (2, ), (2, ), (2, ), (2, ),
                                            (2, datetime.datetime(2018, 2, 6, 5, 5, 5)),
                                            ('test', )]
        mock_cursor.fetchall.side_effect = [[(1, datetime.datetime(2018, 3, 6, 5, 5, 5),
                                              'http://www.google.com'),
                                             (1, datetime.datetime(2018, 4, 6, 5, 5, 5),
                                              'http://www.google.com')],
                                            [("High", "Test Alert A", 3),
                                             ("Medium", "Test Alert B", 6)],
                                            [("High", "Test Alert A", 3),
                                             ("Medium", "Test Alert B", 6)]]
        mock_cursor.description = (('name',), ('title',))
        zap_results = html_parser(file_path)
        args = (mock_conn, mock_conn, 'test', 'test', zap_results, 'test',
                'http://www.google.com', 'test')
        result = process_zap_results(*args)
        check_text = 'Number of URLs Affected stayed the same'
        self.assertTrue(check_text in result)

    @patch('mysql.connector.connect')
    def test_process_zap_results_compare_increase(self, mock_conn):
        """Tests the process zap file function"""
        file_path = ROOT_PATH + "/" + "test_files/testReport.html"
        mock_cursor = mock.Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.side_effect = [(1, datetime.datetime(2018, 1, 6, 5, 5, 5)),
                                            (2, ), (2, ), (2, ), (2, ), (2, ), (2, ),
                                            (2, datetime.datetime(2018, 2, 6, 5, 5, 5)),
                                            ('test', )]
        mock_cursor.fetchall.side_effect = [[(1, datetime.datetime(2018, 3, 6, 5, 5, 5),
                                              'http://www.google.com'),
                                             (1, datetime.datetime(2018, 4, 6, 5, 5, 5),
                                              'http://www.google.com')],
                                            [("Low", "Test Alert A", 3),
                                             ("Informational", "Test Alert B", 6)],
                                            [("Low", "Test Alert A", 2),
                                             ("Informational", "Test Alert B", 5)]]
        mock_cursor.description = (('name',), ('title',))
        zap_results = html_parser(file_path)
        args = (mock_conn, mock_conn, 'test', 'test', zap_results, 'test',
                'http://www.google.com', 'test')
        result = process_zap_results(*args)
        check_text = 'Number of URLs Affected increased'
        self.assertTrue(check_text in result)

    @patch('mysql.connector.connect')
    def test_process_zap_results_compare_decrease(self, mock_conn):
        """Tests the process zap file function"""
        file_path = ROOT_PATH + "/" + "test_files/testReport.html"
        mock_cursor = mock.Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.side_effect = [(1, datetime.datetime(2018, 1, 6, 5, 5, 5)),
                                            (2, ), (2, ), (2, ), (2, ), (2, ), (2, ),
                                            (2, datetime.datetime(2018, 2, 6, 5, 5, 5)),
                                            ('test', )]
        mock_cursor.fetchall.side_effect = [[(1, datetime.datetime(2018, 3, 6, 5, 5, 5),
                                              'http://www.google.com'),
                                             (1, datetime.datetime(2018, 4, 6, 5, 5, 5),
                                              'http://www.google.com')],
                                            [("High", "Test Alert A", 1),
                                             ("False Positive", "Test Alert B", 4)],
                                            [("High", "Test Alert A", 2),
                                             ("False Positive", "Test Alert B", 5)]]
        mock_cursor.description = (('name',), ('title',))
        zap_results = html_parser(file_path)
        args = (mock_conn, mock_conn, 'test', 'test', zap_results, 'test',
                'http://www.google.com', 'test')
        result = process_zap_results(*args)
        check_text = 'Number of URLs Affected decreased'
        self.assertTrue(check_text in result)
