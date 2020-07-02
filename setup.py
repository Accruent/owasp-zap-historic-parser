"""This module is the setup for OWASP ZAP Historic Parser"""
from setuptools import find_packages, setup


with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()
    print(LONG_DESCRIPTION)


setup(
    name='owasp-zap-historic-parser',
    version="0.1.5",
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

    install_requires=[
        'mysql-connector',
    ],
    entry_points={
        'console_scripts': [
            'owaspzaphistoricparser=owasp_zap_historic_parser.runner:main',
        ]
    },
)
