#!/usr/bin/env bash

echo '## Install Suricata ##'
# Install on ProbeManager server
# Get args
arg=$1
destfull=$2

if [[ "$SURICATA_VERSION" == "" ]]; then
    SURICATA_VERSION="4.0.4"
fi
config=""
rules=""
# OSX with brew
if [[ $OSTYPE = *"darwin"* ]]; then
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw suricata ; then
            brew install suricata
        fi
        which suricata
        config="/usr/local/etc/suricata/suricata.yaml"
        rules="/usr/local/etc/suricata/rules"
    fi
# Debian and Ubuntu
elif [ -f /etc/debian_version ]; then
    cat /etc/issue.net
    if ! type suricata ; then
        sudo apt update
        sudo apt -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libmagic-dev libcap-ng-dev libjansson-dev pkg-config
        wget https://www.openinfosecfoundation.org/download/suricata-"$SURICATA_VERSION".tar.gz
        tar -xzf suricata-"$SURICATA_VERSION".tar.gz
        (cd suricata-"$SURICATA_VERSION" && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make && sudo make install && sudo make install-conf)
    fi
    which suricata
    config="/etc/suricata/suricata.yaml"
    rules="/etc/suricata/rules"
    if [[ "$arg" = 'prod' ]]; then
        sudo touch /var/log/suricata/suricata.log
        sudo chmod a+rw  /var/log/suricata/suricata.log
        sudo chown -R $(whoami) /etc/suricata
        if [ -f $( which suricata ) ]; then
            sudo chown $(whoami) $( which suricata )
        fi
        if [ ! -d /etc/suricata/rules ]; then
            mkdir /etc/suricata/rules
        fi
        if [ -f /etc/suricata/suricata-debian.yaml ]; then
            mv /etc/suricata/suricata-debian.yaml /etc/suricata/suricata.yaml
        fi
        which suricata
        suricata -V
    fi
fi
if ! type suricata ; then
    exit 1
fi
echo "SURICATA_BINARY = '$( which suricata )'" > "$destfull"probemanager/suricata/settings.py
echo "SURICATA_CONFIG = '$config'" >> "$destfull"probemanager/suricata/settings.py
echo "SURICATA_RULES = '$rules'" >> "$destfull"probemanager/suricata/settings.py
echo "SURICATA_VERSION = '$SURICATA_VERSION'" >> "$destfull"probemanager/suricata/settings.py
