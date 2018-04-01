#!/usr/bin/env bash

echo '## Install Suricata ##'
# Get args
arg=$1
destfull=$2

config=""
rules=""
if [[ "$SURICATA_VERSION" != "" ]]; then
wget https://www.openinfosecfoundation.org/download/suricata-"$SURICATA_VERSION".tar.gz
tar -xzf suricata-"$SURICATA_VERSION".tar.gz
(cd suricata-"$SURICATA_VERSION" && ./configure && make && sudo make install-conf)
# OSX with brew
elif [[ $OSTYPE = *"darwin"* ]]; then
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw suricata ; then
            brew install suricata
        fi
        which suricata
        config="/usr/local/etc/suricata/suricata.yaml"
        rules="/usr/local/etc/suricata/rules"
    fi
# Debian
elif [ -f /etc/debian_version ]; then
    cat /etc/issue.net
    if ! type suricata ; then
        issue=$( cat /etc/issue.net )
        if [[ $issue = *"Ubuntu"* ]]; then
            sudo add-apt-repository -y ppa:oisf/suricata-stable
            sudo apt update
            sudo apt -y install suricata
        else
            echo 'deb http://http.debian.net/debian stretch-backports main' | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
            sudo apt update
            sudo apt -y -t stretch-backports install suricata
        fi
    fi
    which suricata
    config="/etc/suricata/suricata.yaml"
    rules="/etc/suricata/rules"
    if [[ "$arg" = 'prod' ]]; then
        suricata -V
        sudo touch /var/log/suricata/suricata.log
        sudo chmod a+rw  /var/log/suricata/suricata.log
        sudo chown -R $(whoami) /etc/suricata
        sudo chown $(whoami) $( which suricata )
        sudo ls -l /etc/suricata
        if [ ! -f /etc/suricata/rules ]; then
            mkdir /etc/suricata/rules
        fi
        if [ -f /etc/suricata/suricata-debian.yaml ]; then
            mv /etc/suricata/suricata-debian.yaml /etc/suricata/suricata.yaml
        fi
    fi
fi
echo "SURICATA_BINARY = '$( which suricata )'" > "$destfull"probemanager/suricata/settings.py
echo "SURICATA_CONFIG = '$config'" >> "$destfull"probemanager/suricata/settings.py
echo "SURICATA_RULES = '$rules'" >> "$destfull"probemanager/suricata/settings.py
