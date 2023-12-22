Changelog
=========
v0.4.0 (2023-12-22)
-----------------

Changes
~~~~~~~
- Bumped PyOTI version
- Updated README.md
- Removed old VirusTotalV2 multis class
~~~~~~~

New
~~~~~~
- Added BinaryEdge multis class
- Added bulk hash check CIRCLHashLookup method and exception
- Added bulk hash check IrisInvestigate method
- Added bulk quick and bulk context check GreyNoise methods
- Added bulk url check GoogleSafeBrowsing method
- Added upload file VirusTotalV3 method
- Added Triage multis class
- Added Stairwell multis class
- Added URLscan class method to submit urls
~~~~~~


v0.3.3.2 (2023-02-22)
---------------------

Changes
~~~~~~~
- Bumped PyOTI version
- Added conditional check in CheckDMARC _get_spf() method 
~~~~~~~


v0.3.3.1 (2022-11-10)
---------------------

Changes
~~~~~~~
- Bumped PyOTI version
- Removed semicolon from regex search for DMARC policy in CheckDMARC
~~~~~~~


v0.3.3 (2022-08-01)
-------------------

Changes
~~~~~~~
- Bumped PyOTI version
- Added handling in DNSBlocklist for surbl when domain appears on multiple lists
- Removed GoogleSafeBrowsing exception, return the error instead of raising an exception
~~~~~~~

v0.3.2.1 (2022-07-22) [bugfix]
----------------------------

Changes
~~~~~~~
- Refactored regex used in CheckDMARC ._spoofable_check() [AttributeError: 'NoneType' object has no attribute 'group']
~~~~~~~

v0.3.2 (2022-07-19)
-------------------

Changes
~~~~~~~
- Bumped PyOTI version
- Removed SpamhausError exception
- Refactored DNSBlocklist module and added additional blocklist return codes
~~~~~~~

New
~~~
- Added ThreatFox integration
- Added MalwareBazaar integration
- Added XforceExchange integration
- Added example script to enrich a MISP event using PyOTI
~~~

v0.3.1 (2022-06-22)
-------------------

Changes
~~~~~~~
- Added package exclusions in setup.cfg
- Bumped PyOTI version
~~~~~~~

v0.3.0 (2022-06-17)
-------------------

Changes
~~~~~~~
- Separated each integration into its own file rather than in one module based on IOC types.
- MalwareHashRegistry uses new REST API rather than DNS query.
- Phishtank uses HTTPS API and data is returned in JSON format from API.
- HybridAnalysis can now search for domains and ip addresses.
- Removed get_hash_type() utility in favor of using len() on hash to determine hash types.
- Removed all external library dependencies except requests, aiodns, and disposable-email-domains.
- Switched from setup.py in favor of using setup.cfg.
- Updated Linux/Windows install docs
~~~~~~~

New
~~~
- Added CIRCLHashLookup integration.
- Added GreyNoise integration for community, context, quick check, and RIOT APIs.
~~~