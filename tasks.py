import pathlib
import subprocess

from invoke import task

from owasp_zap_historic_parser import owasp_zap_historical
from version import VERSION as VERSION

ROOT = pathlib.Path(__file__).parent.resolve().as_posix()


@task
def utests(context):
    cmd = [
        "coverage",
        "run",
        "--source=owasp_zap_historic_parser",
        "-p",
        "-m",
        "pytest",
        f"{ROOT}/test",
    ]
    subprocess.run(" ".join(cmd), shell=True, check=False)


@task(utests)
def tests(context):
    subprocess.run("coverage combine", shell=True, check=False)
    subprocess.run("coverage report", shell=True, check=False)
    subprocess.run("coverage html", shell=True, check=False)


@task
def libdoc(context):
    print(f"Generating libdoc for library version {VERSION}")
    target = f"{ROOT}/docs/owasp_zap_historic_parser.html"
    cmd = [
        "python",
        "-m",
        "robot.libdoc",
        "-n owasp_zap_historic_parser",
        f"-v {VERSION}",
        "owasp_zap_historic_parser",
        target,
    ]
    subprocess.run(" ".join(cmd), shell=True, check=False)


@task
def readme(context):
    with open(f"{ROOT}/docs/README.md", "w", encoding="utf-8") as readme_file:
        doc_string = owasp_zap_historical.__doc__
        readme_file.write(str(doc_string))
