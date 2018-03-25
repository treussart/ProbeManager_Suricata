#!/usr/bin/env bash

echo '## Load data Suricata ##'
# Get args
arg=$1
destfull=$2

python "$destfull"probemanager/manage.py loaddata init-suricata.json --settings=probemanager.settings.$arg
