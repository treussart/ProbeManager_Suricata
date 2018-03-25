#!/usr/bin/env bash

echo '## Install Suricata ##'
# Get args
arg=$1
destfull=$2

config=""
rules=""
# OSX with brew
if [[ $OSTYPE = *"darwin"* ]]; then
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw suricata ; then
            brew install suricata
        fi
        config="/usr/local/etc/suricata/suricata.yaml"
        rules="/usr/local/etc/suricata/rules"
    fi
fi
# Debian
if [ -f /etc/debian_version ]; then
    if ! type suricata ; then
        sudo apt install -y suricata
    fi
    which suricata
    config="/etc/suricata/suricata.yaml"
    rules="/etc/suricata/rules"
fi
if [[ "$arg" = 'prod' ]]; then
    sudo touch /var/log/suricata/suricata.log
    sudo chmod a+rw  /var/log/suricata/suricata.log
    sudo chmod a+rw /etc/suricata/rules
fi
echo "SURICATA_BINARY = '$( which suricata )'" > "$destfull"probemanager/suricata/settings.py
echo "SURICATA_CONFIG = '$config'" >> "$destfull"probemanager/suricata/settings.py
echo "SURICATA_RULES = '$rules'" >> "$destfull"probemanager/suricata/settings.py
