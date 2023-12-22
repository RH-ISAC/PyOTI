# PyOTI - Python Open Threat Intelligence
***

PyOTI is an API framework to easily query threat intel APIs to get fast, accurate and consistent enrichment data to provide added context to your indicators of compromise. Built as a modular framework to make it easy to use any of the available APIs without needing to be an experienced coder. If a service or tool you use isn’t already in PyOTI it is simple to add a new enrichment module or you may open an issue for a feature request and we can work to get it added into the project. 



| Indicator Types | APIs                                                                                                                                                                           |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Domains         | CheckDMARC, CIRCLPDNS, IrisInvestigate, WhoisXML                                                                                                                               |
| Email Addresses | DisposableEmails, EmailRepIO                                                                                                                                                   |
| Hashes          | CIRCLHashLookup, MalwareBazaar, MalwareHashRegistry                                                                                                                            |
| IP Addresses    | AbuseIPDB, GreyNoise, SpamhausIntel                                                                                                                                            |
| URLs            | GoogleSafeBrowsing, LinkPreview, Phishtank, ProofpointURLDecoder                                                                                                               |
| Multis          | BinaryEdge, CIRCLPSSL, DNSBlockList, HybridAnalysis, MaltiverseIOC, MISP, Onyphe, OTX, Pulsedive, Stairwell, ThreatFox, Triage, URLhaus, URLscan, VirusTotalV3, XForceExchange |

***
## Installing via pip
It is advised to use a virtual environment.
```python
python3 -m pip install pyoti
```

If you want to also use the Jupyter Notebook please install additional dependencies.
```python
python3 -m pip install pyoti[jupyter_notebook]
```
***
## Installing/Updating from source
Windows instructions can be found in the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/windows/README.md).
 
Linux instructions can be found in the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/linux/README.md).
***
## Tutorial
For a quick tutorial on the ease and benefit of using PyOTI you can view the Phishing URL Triage Jupyter Notebook [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/tutorials/phishing_triage_urls.ipynb).
***
## License
Copyright © 2021-2023, RH-ISAC 

This work is free software. You may redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or
at your option, any later version.
 
This work is distributed in the hope that it will be useful, but is made available WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 
Please review the GNU General Public License at https://www.gnu.org/licenses/ for additional information.
