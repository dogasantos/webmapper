#!/bin/bash

workdir=$(pwd)
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
    apt-get install -y python3-pip python3
fi
python3 -m pip install -r requirements.txt
install_pynmap


echo '#!/bin/bash' > /usr/bin/webmapper
echo "python3 $workdir/webmapper.py $@" >>  /usr/bin/webmapper
chmod 755 /usr/bin/webmapper