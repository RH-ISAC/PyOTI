Changelog
=========

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