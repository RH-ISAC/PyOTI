## Installation for Windows
It is a requirement to have both Git and Python3 installed and in your $PATH.

You may also need to set execution policy to unrestricted in order to create/activate a Python3 virtual environment.

Virtualenv (recommended):
```powershell

# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI "$env:USERPROFILE\PyOTI"
Set-Location -Path "$env:USERPROFILE\PyOTI"
Copy-Item "$env:USERPROFILE\PyOTI\examples\keys.py.sample" -Destination "$env:USERPROFILE\PyOTI\examples\keys.py"
# install/setup virtual environment
Set-ExecutionPolicy Unrestricted -Force
py -m pip install virtualenv
py -m venv venv
.\venv\Scripts\Activate.ps1
# make sure to fill in your API secrets!
notepad "$env:USERPROFILE\PyOTI\examples\keys.py"
# install PyOTI library
py -m pip install .
```
No virtualenv:
```powershell
# clone PyOTI repository and copy sample keys file
git clone https://github.com/RH-ISAC/PyOTI "$env:USERPROFILE\PyOTI"
Set-Location -Path "$env:USERPROFILE\PyOTI"
Copy-Item "$env:USERPROFILE\PyOTI\examples\keys.py.sample" -Destination "$env:USERPROFILE\PyOTI\examples\keys.py"
# make sure to fill in your API secrets!
notepad "$env:USERPROFILE\PyOTI\examples\keys.py"
# install PyOTI library
py -m pip install .
```
##
## Updating for Windows
Virtualenv:
```powershell
# activate virtual environment
Set-ExecutionPolicy Unrestricted -Force
Set-Location -Path "$env:USERPROFILE\PyOTI"
.\venv\Scripts\Activate.ps1
# pull PyOTI repository and update keys
git pull
powershell .\update_keys.ps1 
# make sure to fill in your updated API secrets!
notepad "$env:USERPROFILE\PyOTI\examples\keys.py"
# make sure PyOTI library is updated
py -m pip install .
```
No virtualenv:
```powershell
# pull PyOTI repository
Set-ExecutionPolicy Unrestricted -Force
Set-Location -Path "$env:USERPROFILE\PyOTI"
git pull
powershell .\update_keys.ps1 
# make sure to fill in your updated API secrets!
notepad "$env:USERPROFILE\PyOTI\examples\keys.py"
# make sure PyOTI library is updated
py -m pip install .
```