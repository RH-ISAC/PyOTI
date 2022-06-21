## Installation for Linux

Virtualenv (recommended):
```bash

# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI ~/PyOTI
cd ~/PyOTI
cp examples/keys.py.sample examples/keys.py
# install/setup virtual environment
python3 -m pip install virtualenv
python3 -m venv venv
source ~/PyOTI/venv/bin/activate
# make sure to fill in your API secrets!
vim examples/keys.py
# install PyOTI library
python3 -m pip install .
```
No virtualenv:
```bash
# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI ~/PyOTI
cd ~/PyOTI
cp examples/keys.py.sample examples/keys.py
# make sure to fill in your API secrets!
vim examples/keys.py
# install PyOTI library
python3 -m pip install .
```
## Updating

Virtualenv (recommended):
```bash
# activate virtual environment
source ~/PyOTI/venv/bin/activate
# pull PyOTI repository
cd ~/PyOTI
git pull
bash update_keys.sh 
# make sure to fill in your updated API secrets!
vim examples/keys.py
# make sure PyOTI library is updated
python3 -m pip install .
```
No virtualenv:
```bash
# pull PyOTI repository
cd ~/PyOTI
git pull
bash update_keys.sh 
# make sure to fill in your updated API secrets!
vim examples/keys.py
# make sure PyOTI library is updated
python3 -m pip install .
```