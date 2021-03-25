# PyOTI - Python Open Threat Intelligence

PyOTI is a python library to easily query various threat intelligence related APIs.


|Indicator Types             | APIs                                                                           |
|----------------------------|--------------------------------------------------------------------------------|
|Domains                     | CheckDMARC, CIRCLPDNS, IrisInvestigate, WhoisXML                               |
|Email Addresses             | DisposableEmails, EmailRepIO                                                   |
|Hashes                      | MalwareHashRegistry                                                            |
|IP Addresses                | AbuseIPDB, SpamhausIntel                                                       |
|URLs                        | GoogleSafeBrowsing, LinkPreview, Phishtank                                     |
|Multis                      | CIRCLPSSL, DNSBlockList, MaltiverseIOC, MISP, Onyphe, OTX, Pulsedive, URLhaus, VirusTotal |
##
## Installation 
(Installation instructions for Windows can be found on the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/windows/README.md).)

Virtualenv (recommended):
```bash
# install/setup virtual environment
python3 -m pip install virtualenv
mkdir ~/python-venv && cd ~/python-venv
python3 -m venv pyoti
source ~/python-venv/pyoti/bin/activate
# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI ~/PyOTI
cd ~/PyOTI
cp pyoti/keys.py.sample pyoti/keys.py
# make sure to fill in your API secrets!
vim pyoti/keys.py
# install requirements and PyOTI library
python3 -m pip install -r requirements.txt
python3 -m pip install .
```
No virtualenv:
```bash
# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI ~/PyOTI
cd ~/PyOTI
cp pyoti/keys.py.sample pyoti/keys.py
# make sure to fill in your API secrets!
vim pyoti/keys.py
# install requirements and PyOTI library
python3 -m pip install -r requirements.txt
python3 -m pip install .
```
##
## Updating
(Updating instructions for Windows can be found on the docs directory [here](https://github.com/RH-ISAC/PyOTI/blob/main/docs/windows/README.md).)

Virtualenv:
```bash
# activate virtual environment
source ~/python-venv/pyoti/bin/activate
# pull PyOTI repository
cd ~/PyOTI
git pull
bash update_keys.sh 
# make sure to fill in your updated API secrets!
vim pyoti/keys.py
# make sure requirements and PyOTI library are updated
python3 -m pip install -r requirements.txt
python3 -m pip install .
```
No virtualenv:
```bash
# pull PyOTI repository
cd ~/PyOTI
git pull
bash update_keys.sh 
# make sure to fill in your updated API secrets!
vim pyoti/keys.py
# make sure requirements and PyOTI library are updated
python3 -m pip install -r requirements.txt
python3 -m pip install .
```