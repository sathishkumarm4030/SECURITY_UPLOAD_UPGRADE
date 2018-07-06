# Vcpe SECURITY PACKAGE UPLOAD & UPGRADE
step1: install packages
below are the packages used in script.please install pkgs before running script or when facing error install
1) netmiko - git clone https://github.com/sathishkumarm4030/netmiko_enh_june6.git
2) textfsm
3) pandas
4) requests
5) json

apt-get install git
apt-get install python-pip
pip install pandas
pip install textfsm
pip install requests
#sudo pip install cffi==1.11.5
sudo apt-get install python-serial


2) download repos from git
git clone https://github.com/sathishkumarm4030/netmiko_enh_june6.git
git clone https://github.com/sathishkumarm4030/SECURITY_UPLOAD_UPGRADE.git





install below packages
1) download netmiko pkg from github - git clone https://github.com/sathishkumarm4030/netmiko_enh_june6.git
2) cd netmiko & run "python setup.py install"


step3: run File_transfer.py

Step4: Prompting for Editing the Vcpe list. If you dont want edit, u can press enter & continue.


after script run:

RESULT stored in RESULT.csv
SCRIPT LOGS stored in LOGS



