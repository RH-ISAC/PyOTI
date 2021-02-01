#!/usr/bin/env bash

# This bash script is meant to be run from the root directory of PyOTI.
# It will check the diff between pyoti/keys.py.sample and pyoti/keys.py and append
# any API key variables that are missing from pyoti/keys.py and set them to ''.
# Please make sure to update pyoti/keys.py with API secrets after running.

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # no color

# check if input file ends with newline
function is_newline(){
  [[ $(tail -c 1 "$1" | wc -l) -gt 0 ]]
}

KEYS=$(diff <(awk '{print $1}' pyoti/keys.py.sample | sort -u) <(awk '{print $1}' pyoti/keys.py | sort -u) | grep "<" | cut -d " " -f2)

if [ -z "$KEYS" ]
then
  echo -e "${GREEN}[*]${NC} No keys need to be updated!"
else
  echo -e "${GREEN}[!]${NC} New keys found! Adding to pyoti/keys.py..."
  echo ""

  if ! is_newline pyoti/keys.py
  then
    echo "" >> pyoti/keys.py
  fi

  for key in $KEYS
  do
    echo $key "= ''" >> pyoti/keys.py
    echo -e "${GREEN}[+]${NC}" $key "added to pyoti/keys.py!"
  done

  echo ""
  echo -e "${GREEN}[*]${RED} Add API secrets to pyoti/keys.py!"
fi
