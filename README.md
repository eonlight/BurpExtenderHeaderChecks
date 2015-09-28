# BurpExtenderHeaderChecks

A Burp Suite Extension that adds Header Checks and other helper features

## Features List

* Passive Scan
    * Searches the response headers for missing security headers:
        * Strict-Transport-Security
        * X-XSS-Protection
        * Content-Security-Policy
        * X-Content-Type-Options
        * X-Permitted-Cross-Domain-Policies
    * Searches the response headers for information disclosure on the server type and version:
        * Server
        * X-Powered-By
        * X-AspNetMvc-Version
        * X-AspNet-Version
        * X-Generator
        * X-Drupal-Cache
        * X-Pingback
        * Liferay-Portal
        * X-Content-Encoded-By
    * If any of the information disclosure headers is found, it will try to infer any of the following software:
        * apache
        * php
        * nginx
        * microsoft-iis
        * joomla
        * wordpress
        * openssl
        * liferay
        * mysql
        * lighttpd
        * postgre
        * drupal
        * tomcat
    * If any of the software is found it will also make a request to the software web page and scrap the latest version
    * Compares the installed / inferred version and reports if the software installed is out-of-date
    * It scraps the CVEdetails website and also reports the CVEs found (if any) for the installed version
* Active Scan
    * **TODO: Future Work**
* Automatic load of a clean, saved burp state whenever burp is started
* Additional tab on Request / Response Panel with a parsed JSON content
    * Tries to fix the JSON if not in the correct format so it can be parsed
* Configuration Tab:
    * Add or remove security header to check
    * Add an informational issue if any security header is found
    * Add any information disclosure header to look for
    * Add any software to try and infer
    * Configure the clean state path

## Dependencies

* This extension uses Apache's JSON decoder library (already included in the org.json package)
* It also requires Java 7

## How to install

At the moment it is not in the Burp Ext. Store but you can get the jar file from the releases page on github:

https://github.com/eonlight/BurpExtenderHeaderChecks/releases

1. Download the extension
2. Open Burp and go to the Extender tab
3. Click on the "Add" Button and Select "Java" Extension type
4. Click on the "Select file" button and select the downloaded .jar file
5. Click "next" and done!

## Future Work

* Add passive scans that looks in the page's HTML for the server's type and version
* Add active scan that looks for specific server's files to infer the server's type and version
* Support the use of a file such as the "whatweb" and "wappalyzer" configs:
    * https://github.com/AliasIO/Wappalyzer/blob/master/src/apps.json

