# PyOTI - Python Open Threat Intelligence

PyOTI is a python library to easily query various threat intelligence related APIs.


|Indicator Types             | APIs                                                              |
|----------------------------|------------------------------------------------------------------|
|Domains                     | CheckDMARC, CIRCLPDNS, IrisInvestigate, WhoisXML                 |
|Email Addresses             | EmailRepIO                                                       |
|Hashes                      | MalwareHashRegistry                                              |
|IP Addresses                | AbuseIPDB, SpamhausIntel                                         |
|URLs                        | GoogleSafeBrowsing, LinkPreview, Phishtank                       |
|Multis                      | CIRCLPSSL, DNSBlockList, MaltiverseIOC, MISP, Onyphe, OTX, URLhaus, VirusTotal |
##
## Installation
Virtualenv:
```bash
python3 -m pip install virtualenv
mkdir ~/python-venv && cd ~/python-venv
python3 -m venv pyoti
source ~/python-venv/pyoti/bin/activate

git clone https://github.com/RH-ISAC/PyOTI
cd PyOTI
python3 -m pip install .
```
No virtualenv:
```bash
git clone https://github.com/RH-ISAC/PyOTI
cd PyOTI
python3 -m pip install .
```