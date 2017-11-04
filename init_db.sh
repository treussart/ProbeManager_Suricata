#!/usr/bin/env bash

echo '## Load data Suricata ##'
# Get args
if [ -z $1 ] || [ $1 == 'dev' ]; then
    arg="dev"
    dest=""
elif [ $1 == 'prod' ]; then
    arg=$1
    if [ -z $2 ]; then
        dest='/usr/local/share'
    else
        dest=$2
    fi
else
    echo 'Bad argument'
    exit 1
fi
destfull="$dest"/ProbeManager/

if [ $arg == 'prod' ]; then
    "$destfull"venv/bin/python "$destfull"probemanager/manage.py loaddata init-suricata.json --settings=probemanager.settings.$arg
else
    venv/bin/python probemanager/manage.py loaddata init-suricata.json --settings=probemanager.settings.$arg
fi