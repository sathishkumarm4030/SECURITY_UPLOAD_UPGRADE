# Vcpe SECURITY PACKAGE UPLOAD & UPGRADE
step1: install packages
below are the packages used in script.please install pkgs before running script or when facing error install
1) netmiko - https://github.com/sathishkumarm4030/netmiko_enhanced.git
2) textfsm
3) pandas
4) requests
5) json

install below packages
1) download netmiko pkg from github - git clone https://github.com/sathishkumarm4030/netmiko_enh_june6.git
2) cd netmiko & run "python setup.py install"

step2: Update upgrade_device_list.csv for your devices

step3: run File_transfer.py

Step4: Prompt will come for Editing the Vcpe list. If you dont want edit, u can press enter & continue.


after script run:

RESULT stored in RESULT.csv
SCRIPT LOGS stored in LOGS



