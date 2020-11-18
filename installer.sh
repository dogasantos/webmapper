#!/bin/bash

install_pynmap(){
    pip3 uninstall -y python-nmap
    cd /tmp
    git clone https://github.com/dogasantos/python-nmap
    cd python-nmap
    python setup.py install
    cd /tmp
    rm -rf python-nmap
}
if [ $(whereis pip3|echo $?) -eq 0 ]
then
    echo "install python3-pip"
    apt-get install -y python3-pip
fi

install_pynmap
pip3 install -r requirements.txt
