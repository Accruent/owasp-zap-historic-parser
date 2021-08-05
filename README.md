# owasp-zap-historic-parser

[![PyPI version](https://badge.fury.io/py/owasp-zap-historic-parser.svg)](https://badge.fury.io/py/owasp-zap-historic-parser)
[![run-tests](https://github.com/Accruent/owasp-zap-historic-parser/actions/workflows/run-tests.yml/badge.svg)](https://github.com/Accruent/owasp-zap-historic-parser/actions/workflows/run-tests.yml)
[![Downloads](https://pepy.tech/badge/owasp-zap-historic-parser)](https://pepy.tech/project/owasp-zap-historic-parser)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
![Open Source Love png1](https://badges.frapsoft.com/os/v1/open-source.png?v=103)
[![HitCount](http://hits.dwyl.com/Accruent/owasp-zap-historic-parser.svg)](http://hits.dwyl.com/Accruent/owasp-zap-historic-parser)
[![Coverage Status](https://coveralls.io/repos/github/Accruent/owasp-zap-historic-parser/badge.svg?branch=master)](https://coveralls.io/github/Accruent/owasp-zap-historic-parser?branch=master)
[![BCH compliance](https://bettercodehub.com/edge/badge/Accruent/owasp-zap-historic-parser?branch=master)](https://bettercodehub.com/)

---

## Installation

 - Install `owasp-zap-historic-parser` 

    ```
    pip install owasp-zap-historic-parser
    ```

--- 

## Usage

   The OWASP ZAP Historic application requires the following information, and users must pass respective info while using parser

    -s --> mysql hosted machine ip address (default: localhost)
    -t --> mysql port (default: 3306)
    -u --> mysql user name (default: superuser)
    -p --> mysql password (default: passw0rd)
    -n --> project name in owasp zap historic
    -e --> environment name (default: Not Provided)
    -i --> type of scan (active, passive, etc) (default: Not Provided)
    -l --> URL for published ZAP report (default: Not Provided)
    -v --> version of application tested by ZAP (default: Not Provided)
    -f --> filepath & report.html produced by ZAP

 - Use `owasp-zap-historic-parser` to parse report.html and return a delta report

   ```
   > owaspzaphistoricparser
    -s --> localhost
    -t --> 3306
    -u --> 'superuser'
    -p --> passw0rd
    -n --> testname
    -e --> QA
    -i --> Active
    -l --> "https://www.google.com"
    -v --> "v0.1.0 build 2"
    -f --> "c:\\temp\\report_230_.html"
   ```
> Note: Here if MySQL hosted in:
>  - local machine then use `localhost` Ex: -s `localhost`
>  - other machine then use `ipaddress:3306` Ex: -s `10.30.2.150:3306`

   __Example:__
   ```
   > owaspzaphistoricparser
    -s localhost
    -t 3306
    -u 'superuser'
    -p passw0rd
    -n testname
    -e QA
    -i Active
    -l "https://www.google.com"
    -v "v0.1.0 build 2"
    -f "c:\\temp\\report_230_.html"
   ```

---

> For more info refer to [owasp-zap-historic](https://github.com/Accruent/owasp-zap-historic)