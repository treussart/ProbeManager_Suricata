#!/usr/bin/env bash

echo '## Install Suricata ##'
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

config=""
# OSX with brew
if [[ $OSTYPE == *"darwin"* ]]; then
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw suricata ; then
            brew install suricata
        fi
        config="/usr/local/etc/suricata/suricata.yaml"
    fi
fi
# Debian
if [ -f /etc/debian_version ]; then
    if ! type suricata ; then
        apt install suricata
    fi
    config="/etc/suricata/suricata.yaml"
fi
if [ $arg == 'prod' ]; then
    touch /var/log/suricata/suricata.log
    chmod a+w  /var/log/suricata/suricata.log
    chmod a+r  /var/log/suricata/suricata.log
    echo "SURICATA_BINARY = '$( which suricata )'" >> "$destfull"probemanager/suricata/settings.py
    echo "SURICATA_CONFIG = '$config'" >> "$destfull"probemanager/suricata/settings.py
else
    echo "SURICATA_BINARY = '$( which suricata )'" >> probemanager/suricata/settings.py
    echo "SURICATA_CONFIG = '$config'" >> probemanager/suricata/settings.py
fi
