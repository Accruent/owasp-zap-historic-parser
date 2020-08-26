"""This module is the setup for OWASP ZAP Historic Parser"""
from setuptools import find_packages, setup
import version

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()
    print(LONG_DESCRIPTION)

with open('requirements.txt') as f:
    REQUIREMENTS = f.read().splitlines()


setup(
    name='owasp-zap-historic-parser',
    version=version.VERSION,
    description='Parser to push OWASP ZAP report data to MySQL and generate delta report',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    classifiers=[
        'Programming Language :: Python',
        'Topic :: Software Development :: Testing',
    ],
    keywords='owasp zap historical report parser',
    author='Neil Howell',
    author_email='neiljhowell@gmail.com',
    url='https://github.com/Accruent/owasp-zap-historic-parser',
    license='GPL-3.0',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,

    install_requires=REQUIREMENTS,
    entry_points={
        'console_scripts': [
            'owaspzaphistoricparser=owasp_zap_historic_parser.runner:main',
        ]
    },
)
