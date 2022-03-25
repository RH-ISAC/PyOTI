# PyOTI - Python Open Threat Intelligence
***

PyOTI is an API framework to easily query threat intel APIs to get fast, accurate and consistent enrichment data to provide added context to your indicators of compromise. Built like a modular framework to make it simple to use any of the available APIs without needing to be an experienced coder. If a service or tool you use isn’t already in PyOTI it is super simple to add a new enrichment module or you may open an issue for a feature request and we can work to get it added into the project. 

Currently, PyOTI only performs queries to check if an indicator of compromise has already been scanned and/or analyzed OR seen by any of the APIs included in PyOTI. However, it is on the road map to add the ability to submit (or resubmit) an indicator of compromise to be scanned and/or analyzed by PyOTI’s APIs.


|Indicator Types             | APIs                                                                           |
|----------------------------|--------------------------------------------------------------------------------|
|Domains                     | CheckDMARC, CIRCLPDNS, IrisInvestigate, WhoisXML                               |
|Email Addresses             | DisposableEmails, EmailRepIO                                                   |
|Hashes                      | MalwareHashRegistry                                                            |
|IP Addresses                | AbuseIPDB, SpamhausIntel                                                       |
|URLs                        | GoogleSafeBrowsing, LinkPreview, Phishtank, ProofpointURLDecoder               |
|Multis                      | CIRCLPSSL, DNSBlockList, HybridAnalysis, MaltiverseIOC, MISP, Onyphe, OTX, Pulsedive, URLhaus, URLscan, VirusTotalV2, VirusTotalV3 |

***
## Installing/Updating 
Windows instructions can be found in the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/windows/README.md).
 
Linux instructions can be found in the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/linux/README.md).
***
## Tutorial
For a quick tutorial on the ease and benefit of using PyOTI you can view the Phishing URL Triage jupyter notebook [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/tutorials/phishing_triage_urls.ipynb).
***
## License
Copyright © 2021-2022, RH-ISAC 

This work is free software. You may redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or
at your option, any later version.
 
This work is distributed in the hope that it will be useful, but is made available WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 
Please review the GNU General Public License at https://www.gnu.org/licenses/ for additional information.
