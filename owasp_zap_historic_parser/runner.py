"""This is the arguments/runner module for OWASP ZAP Historical Parser"""
import argparse
from .owasp_zap_historical import process_zap_file


def parse_options():
    """This function defines the arguments"""
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    general = parser.add_argument_group("General")

    general.add_argument(
        '-s', '--host', dest='ozh_host', default='localhost', help="MySQL hosted address"
    )

    general.add_argument(
        '-t', '--port', dest='ozh_port', default=3306, help="MySQL port"
    )

    general.add_argument(
        '-u', '--username', dest='ozh_username', default='superuser', help="MySQL db user name"
    )

    general.add_argument(
        '-p', '--password', dest='ozh_password', default='passw0rd', help="MySQL db password"
    )

    general.add_argument(
        '-n', '--projectname', dest='projectname', help="Name of the project"
    )

    general.add_argument(
        '-e', '--environment', dest='this_env', default='Not Provided', help="Environment Name"
    )

    general.add_argument(
        '-i', '--scantype', dest='scantype', default='Not Provided', help="Path of result files"
    )

    general.add_argument(
        '-l', '--urllink', dest='urllink', default='Not Provided',
        help="URL for published ZAP report"
    )

    general.add_argument(
        '-v', '--version', dest='version', default='Not Provided',
        help="Version of application that ZAP tested"
    )

    general.add_argument(
        '-f', '--filename', dest='filename', help="File / path of ZAP report.html"
    )

    return parser.parse_args()


def main():
    """This function processes the arguments"""
    args = parse_options()
    process_zap_file(args)
