import time
import requests
from string import Template
from netmiko import ConnectHandler
import textfsm
from netmiko import redispatch
import csv
from Utils.Variables import *
import errno
import os
import logging
import logging.handlers
import urllib3
from datetime import datetime
from netmiko import ConnectHandler
import netmiko
import paramiko
import socket
import re
import threading
import os
import subprocess


urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

report = []
parsed_dict = {}
cpe_logger = ""
cpe_logger_dict ={}
devices_list = []
# currtime = str(datetime.now())
# currtime =  currtime.replace(" ", "_").replace(":", "_").replace("-", "_").replace(".", "_")
currtime = str(datetime.now().replace(microsecond=0))
currtime =  currtime.replace(" ", "_").replace(":", "_").replace("-", "_").replace(".", "_")
up_pkg_dict = {}
batch = ""
# cpe_list_file_name = vd_dict['ip'] + '_Vcpe_List.csv'
cpe_list_file_name = vd_dict['ip'] + '_Vcpe_List_' + currtime + '.csv'
curr_prompt = ""
source_file = ""
upload_report = []
result_list = []


ssh_exceptions = (netmiko.ssh_exception.NetMikoAuthenticationException,
                  netmiko.ssh_exception.NetMikoTimeoutException, netmiko.NetMikoTimeoutException,
                  netmiko.NetMikoAuthenticationException, netmiko.NetmikoTimeoutError, netmiko.NetmikoAuthError,
                  netmiko.ssh_exception.SSHException, netmiko.ssh_exception.AuthenticationException,
                  paramiko.OPEN_FAILED_CONNECT_FAILED, socket.timeout, paramiko.SSHException)

if __name__ == "__main__":
    fileDir = os.path.dirname(os.path.dirname(os.path.realpath('__file__')))
else:
    fileDir = os.path.dirname(os.path.realpath('__file__'))

logfile_dir = fileDir + "/LOGS/" + vd_dict['ip'] + "_" + currtime + "/"
if not os.path.exists(os.path.dirname(logfile_dir)):
    try:
        os.mkdir(os.path.dirname(logfile_dir))
    except OSError as exc:  # Guard against race condition
        if exc.errno != errno.EEXIST:
            raise

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
formatter1 = logging.Formatter("%(message)s")
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter1)
logging.getLogger('').addHandler(console)


def setup_logger(name, filename, level=logging.DEBUG):
    log_file = logfile_dir + filename  + ".log"
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger = logging.getLogger(name)
    return logger

main_logger = setup_logger('Main', 'UpgradeVersaCpes')



def do_cross_connection(cpe_name, vd_ssh_dict, dev_dict, redispatch_type='versa'):
    global cpe_logger
    netconnect = make_connection(vd_ssh_dict)
    netconnect.write_channel("ssh " + dev_dict["username"] + "@" + dev_dict["ip"] + "\n")
    time.sleep(2)
    output = netconnect.read_channel()
    main_logger.debug(output)
    if 'assword:' in output:
        netconnect.write_channel(dev_dict["password"] + "\n")
        output = netconnect.read_channel()
        main_logger.debug(output)
    elif 'yes' in output:
        print "am in yes condition"
        netconnect.write_channel("yes\n")
        output = netconnect.read_channel()
        main_logger.debug(output)
        time.sleep(1)
        netconnect.write_channel(dev_dict["password"] + "\n")
        output = netconnect.read_channel()
        main_logger.debug(output)
    else:
        # cpe_logger.info(output)
        close_connection(netconnect)
        return "VD to CPE " + dev_dict["ip"] + "ssh Failed."
    time.sleep(2)
    try:
        main_logger.debug("doing redispatch")
        redispatch(netconnect, device_type=redispatch_type)
    except ValueError as Va:
        main_logger.info(cpe_name + " : "+ str(Va))
        main_logger.info(cpe_name + ": Not able to get router prompt from VD to CPE " + dev_dict["ip"] + " CLI. please check login creds")
        close_connection(netconnect)
        return "Redispatch not Success"
    time.sleep(2)
    return netconnect






def cpe_list_print():
    global cpe_list
    # print "BELOW ARE THE CPEs going for Upgrade:\n"
    main_logger.info("BELOW ARE THE CPEs going for Upgrade:")
    for i, rows in cpe_list.iterrows():
        # print cpe_list.ix[i, 'device_name_in_vd'] + "\n"
        main_logger.info(cpe_list.ix[i, 'device_name_in_vd'])
    time.sleep(1)
    # if raw_input("shall we proceed for Upgrade. Please Enter yes or no\n") != "yes":
    #     main_logger.debug("You are not entered yes. Script exiting")
    #     exit()

def write_result_from_dict(results):
    data_header = ['cpe', 'upgrade', 'interface', 'bgp_nbr_match', 'route_match', 'config_match']
    with open(logfile_dir + 'RESULT.csv', 'w') as file_writer:
        writer = csv.writer(file_writer)
        writer.writerow(data_header)
        for item in results:
            writer.writerow(item)
        for result1 in results:
            main_logger.debug("==" * 50)
            for header, res in zip(data_header, result1):
                main_logger.debug(header + ":" + res)
            main_logger.debug("==" * 50)


def write_result(results, result_type):
    data_header = ['cpe', 'filename', result_type]
    with open(logfile_dir + 'RESULT.csv', 'w') as file_writer:
        writer = csv.writer(file_writer)
        writer.writerow(data_header)
        for item in results:
            writer.writerow(item)



def write_cpe_output(results, state):
    write_output_filename = logfile_dir + "/PARSED_DATA/" + str(results[0][0]) + "_outputs.txt"

    if not os.path.exists(os.path.dirname(write_output_filename)):
        try:
            os.makedirs(os.path.dirname(write_output_filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    if state == "before_upgrade":
        data_header = ['cpe', 'before_upgrade_package_info', 'snapshot taken', 'before_upgrade_interface', 'before_upgrade_bgp_nbr_match', 'before_upgrade_route_match', 'before_upgrade_config_match']
        try:
            os.remove(write_output_filename)
        except OSError:
            pass
    elif state == "after_upgrade":
        data_header = ['cpe', 'after_upgrade_package_info', 'after_upgrade_interface', 'after_upgrade_bgp_nbr_match', 'after_upgrade_route_match', 'after_upgrade_config_match']

    with open(write_output_filename, "a") as f:
        for i in range(len(data_header)):
            print >> f, data_header[i]
            print >> f, "===" * 50
            print >> f, results[i]
            # for idx, k in enumerate(j):
            #         print >> f, k
            print >> f, "===" * 50



def write_output(results):
    write_output_filename = fileDir + "/PARSED_DATA/" + str(results[0][0]) + "_outputs.txt"
    data_header = ['cpe', 'before_upgrade_package_info', 'after_upgrade_package_info', 'before_upgrade_interface', 'after_upgrade_interface', 'before_upgrade_bgp_nbr_match', 'after_upgrade_bgp_nbr_match', 'before_upgrade_route_match', 'after_upgrade_route_match', 'before_upgrade_config_match', 'after_upgrade_config_match']
    if not os.path.exists(os.path.dirname(write_output_filename)):
        try:
            os.makedirs(os.path.dirname(write_output_filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    with open(write_output_filename, "w") as f:
        for i, j in zip(data_header, results):
            print >> f, i
            print >> f, "===" * 50
            for idx, k in enumerate(j):
                    print >> f, k
            print >> f, "===" * 50



def config_template(text, params1):
    template = Template(text)
    txt = template.safe_substitute(params1)
    return txt

def make_connection_return_conn_fail(a_device):
    global main_logger, curr_prompt
    try:
        net_connect = ConnectHandler(**a_device)
        output = net_connect.read_channel()
        main_logger.debug(output)
    except ssh_exceptions as Va:
        main_logger.info(Va)
        # main_logger.debug("Not able to enter Device. please Check")
        return "CONN_ERR: " + str(Va)
    #net_connect.enable()
    time.sleep(2)
    main_logger.debug("{}: {}".format(net_connect.device_type, net_connect.find_prompt()))
    curr_prompt = net_connect.find_prompt()
    # print str(net_connect) + " connection opened"
    main_logger.debug(str(net_connect) + " connection opened")
    return net_connect

def make_connection(a_device):
    global main_logger, curr_prompt
    try:
        net_connect = ConnectHandler(**a_device)
        output = net_connect.read_channel()
        main_logger.debug(output)
    except ValueError as Va:
        main_logger.debug(Va)
        main_logger.debug("Not able to enter Versa Director CLI. please Check")
        exit()
    #net_connect.enable()
    time.sleep(2)
    main_logger.debug("{}: {}".format(net_connect.device_type, net_connect.find_prompt()))
    curr_prompt = net_connect.find_prompt()
    # print str(net_connect) + " connection opened"
    main_logger.debug(str(net_connect) + " connection opened")
    return net_connect

def make_connection_to_cli(a_device):
    global main_logger, curr_prompt
    a_device['device_type'] = 'versa'
    try:
        net_connect = ConnectHandler(**a_device)
        output = net_connect.read_channel()
        main_logger.debug(output)
    except ValueError as Va:
        main_logger.debug(Va)
        main_logger.debug("Not able to enter Versa Director CLI. please Check")
        exit()
    net_connect.enable()
    time.sleep(2)
    main_logger.debug("{}: {}".format(net_connect.device_type, net_connect.find_prompt()))
    curr_prompt = net_connect.find_prompt()
    # print str(net_connect) + " connection opened"
    main_logger.debug(str(net_connect) + " connection opened")
    return net_connect



def close_cross_connection(nc):
    time.sleep(1)
    main_logger.debug(nc.write_channel("exit\n"))
    time.sleep(1)
    redispatch(nc, device_type='linux')
    # main_logger.debug(nc.find_prompt())





def close_connection(net_connect):
    net_connect.disconnect()
    main_logger.debug(str(net_connect) + " connection closed")





def build_csv(device_list):
    global cpe_list_file_name
    #data_header = ['device_name_in_vd', 'ip', 'day', 'batch', 'org', 'type', 'softwareVersion', 'ping-status', 'sync-status']
    # with open(logfile_dir + 'Vcpe_list_raw.csv', 'w') as file_writer:
    #     writer = csv.writer(file_writer)
    #     writer.writerow(data_header)
    #     for item in device_list:
    #         writer.writerow(item)
    # csv_data_read = pd.read_csv(logfile_dir + 'Vcpe_list_raw.csv')
    with open(cpe_list_file_name, 'w') as file_writer1:
        data_header = ['device_name_in_vd', 'ip', 'day', 'batch', 'org', 'type', 'softwareVersion', 'ping-status',
                       'sync-status', 'serialNo', 'model', 'existing-packageName']
        writer = csv.writer(file_writer1)
        writer.writerow(data_header)
        for item in device_list:
            writer.writerow(item)



def get_device_list(oper_type='patch_upgrade'):
    global batch
    response1 = requests.get(vdurl + appliance_url,
                             auth=(user, passwd),
                             headers=headers3,
                             verify=False)
    data1 = response1.json()
    count, day, batch = 1, 1, 1
    # print data1
    for i in data1['versanms.ApplianceStatusResult']['appliances']:
        device_list = []
        # if i['type']=='branch':
        # if i['ownerOrg'] != 'Colt':
        if i['ping-status'] == 'REACHABLE':
            if oper_type == 'file_transfer':
                if count%15 == 0:
                    batch += 1
            if oper_type == 'sec_package':
                if count%15 == 0:
                    batch += 1
            else:
                if count%11 == 0:
                    batch += 1
            device_list.append(i['name'])
            device_list.append(i['ipAddress'])
            device_list.append(day)
            device_list.append(batch)
            device_list.append(i['ownerOrg'])
            device_list.append(i['type'])
            device_list.append(i['softwareVersion'])
            device_list.append(i['ping-status'])
            device_list.append(i['sync-status'])
            try:
                if i['Hardware'] != "":
                    device_list.append(i['Hardware']['serialNo'])
                    device_list.append(i['Hardware']['model'])
                    device_list.append(i['Hardware']['packageName'])
            except KeyError as ke:
                print i['name']
                print "Hardware Info NIL"
                continue
            # print count, day, batch
            count += 1
            devices_list.append(device_list)
    # print devices_list
    return devices_list


def get_device_list_only_branch(oper_type='patch_upgrade'):
    global batch
    response1 = requests.get(vdurl + appliance_url,
                             auth=(user, passwd),
                             headers=headers3,
                             verify=False)
    data1 = response1.json()
    count, day, batch = 1, 1, 1
    # print data1
    for i in data1['versanms.ApplianceStatusResult']['appliances']:
        device_list = []
        if i['type']=='branch':
            if i['ownerOrg'] != 'Colt':
                if i['ping-status'] == 'REACHABLE':
                    if oper_type == 'file_transfer':
                        if count%5 == 0:
                            batch += 1
                    if oper_type == 'sec_package':
                        if count%15 == 0:
                            batch += 1
                    else:
                        if count%11 == 0:
                            batch += 1
                    device_list.append(i['name'])
                    device_list.append(i['ipAddress'])
                    device_list.append(day)
                    device_list.append(batch)
                    device_list.append(i['ownerOrg'])
                    device_list.append(i['type'])
                    device_list.append(i['softwareVersion'])
                    device_list.append(i['ping-status'])
                    device_list.append(i['sync-status'])
                    try:
                        if i['Hardware'] != "":
                            device_list.append(i['Hardware']['serialNo'])
                            device_list.append(i['Hardware']['model'])
                            device_list.append(i['Hardware']['packageName'])
                    except KeyError as ke:
                        print i['name']
                        print "Hardware Info NIL"
                        continue
                    # print count, day, batch
                    count += 1
                    devices_list.append(device_list)
    # print devices_list
    return devices_list


def get_device_list_wo_ping_check(oper_type='patch_upgrade'):
    global batch
    response1 = requests.get(vdurl + appliance_url,
                             auth=(user, passwd),
                             headers=headers3,
                             verify=False)
    data1 = response1.json()
    count, day, batch = 1, 1, 1
    # print data1
    for i in data1['versanms.ApplianceStatusResult']['appliances']:
        device_list = []
        # if i['type']=='branch':
        # if i['ownerOrg'] != 'Colt':
        # if i['ping-status'] == 'REACHABLE':
        if oper_type == 'file_transfer':
            if count%5 == 0:
                batch += 1
        else:
            if count%9 == 0:
                batch += 1
        device_list.append(i['name'])
        device_list.append(i['ipAddress'])
        device_list.append(day)
        device_list.append(batch)
        # device_list.append(i['ownerOrg'])
        device_list.append(i['type'])
        if 'softwareVersion' in i:
            device_list.append(i['softwareVersion'])
        device_list.append(i['ping-status'])
        device_list.append(i['sync-status'])
        # try:
        #     if i['Hardware']!="":
        #         device_list.append(i['Hardware']['serialNo'])
        #         device_list.append(i['Hardware']['model'])
        #         device_list.append(i['Hardware']['packageName'])
        # except KeyError as ke:
        #     print i['name']
        #     print "Hardware Info NIL"
        #print count, day, batch
        count +=1
        devices_list.append(device_list)
    # print devices_list
    return devices_list



def request_ping(net_connect, cpe):
    net_connect.send_command_expect("cli", strip_prompt=False, strip_command=False, expect_string=">")
    cmd = "request devices device " + cpe + " ping"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False, expect_string=">")
    # net_connect.send_command_expect("quit", strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(", 0% packet loss," in output)


def request_connect(net_connect, cpe):
    cmd = "request devices device " + cpe + " connect"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" Connected to" in output)


def request_live_status(net_connect, cpe):
    cmd = "request devices device " + cpe + " check-sync"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str("result in-sync" in output)


def request_sync_from_cpe(net_connect, cpe):
    cmd = "request devices device " + cpe + " sync-from"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" result true" in output)

def request_sync_from_cpe(net_connect, cpe):
    cmd = "request devices device " + cpe + " sync-from"
    main_logger.info("CMD>> : " + cmd)
    output = net_connect.send_command_expect(cmd, strip_prompt=False, strip_command=False)
    main_logger.info(output)
    return str(" result true" in output)


def check_device_status(nc, device_name):
    if request_ping(nc, device_name) == True:
        if request_connect(nc, device_name) == "True":
            if request_sync_from_cpe(nc, device_name):
                        return "PASS"
            else:
                return "CPE out-of sync."
        else:
            return "VD --> CPE Request connect failed."
    else:
        return "VD --> CPE Request ping failed."

def file_check(source_file):
    global file_size, source_md5_checksum
    source_file_detail = subprocess.check_output("ls -ltr /tmp/" + source_file + " | awk '{print $5}'", shell=True, stderr=subprocess.STDOUT).rstrip()
    # source_file_detail = netconnect.send_command_expect("ls -ltr " + source_file, expect_string = "\$|#")
    main_logger.debug(source_file_detail)
    if "No such file or directory" in source_file_detail:
        main_logger.info(source_file_detail)
        exit()
    else:
        file_size = source_file_detail
        source_md5_check = subprocess.check_output("md5sum /tmp/" + source_file + " | awk '{print $1}'", shell=True, stderr=subprocess.STDOUT).rstrip()
        main_logger.debug(source_md5_check)
        source_md5_checksum = source_md5_check
        main_logger.debug("Source File Checksum : " + source_md5_checksum)

#source_file, cpe_ip, dev_username, dev_passwd, i

def modify_vshell(netconnect, cpe_name, cpe_user, cpe_passwd, filename, cpe_logger):
    global file_size, source_md5_checksum
    cpe_logger.debug(netconnect.send_command_expect("shell", expect_string="\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("sudo bash\n", expect_string = ":|\$|#"))
    # time.sleep(1)
    cpe_logger.debug(netconnect.send_command_expect(cpe_passwd + "\n", expect_string = "\$|#"))
    # time.sleep(1)
    # cpe_logger.debug(netconnect.send_command_expect("exit\n", expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("cat /opt/versa/scripts/vshell", strip_prompt=False, strip_command=False, expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect(vshell_cmd, strip_prompt=False, strip_command=False, expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("cat /opt/versa/scripts/vshell", strip_prompt=False, strip_command=False, expect_string = "\$|#"))
    return "File Modification done"


def file_upload(source_file, dest_name, dest_ip, dev_user, dev_passwd, index_passed):
    global File_tr_Success, File_tr_Failed, file_size, source_md5_checksum
    global cpe_list, device_report
    File_tr_Success = "File Transfer Success : "
    File_tr_Failed = "File Transfer Failed : "
    dev_dict = {
        "device_type": 'versa', "ip": dest_ip, \
        "username": dev_user, "password": dev_passwd, \
        "port": '22'
    }
    check_ssh = make_connection_return_conn_fail(dev_dict)
    if isinstance(check_ssh, str) and "CONN_ERR:" in check_ssh:
        result = File_tr_Failed + check_ssh
        device_report[dest_name] = [dest_name, source_file, result]
        return
    try:
        cmd = "rsync -v -e 'sshpass -p " + dev_passwd + " ssh -o StrictHostKeyChecking=no' /tmp/" + source_file + " " + dev_user + "@" + dest_ip + ":/home/versa/packages --progress"
        main_logger.debug("CMD>> : " + cmd)
        output1 = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        main_logger.debug(output1)
    except subprocess.CalledProcessError as cperr:
        main_logger.debug(cperr)
        result = "CalledProcessError: "+ str(cperr)
        device_report[dest_name] = [dest_name, source_file, result]
        return
    if 'speedup is' in output1:
        output2 = output1
        op_copy = output2[:]
        transfered_Size = re.search("total size is (\S+) ", op_copy.replace(",", "")).group(1)
        if file_size==transfered_Size:
            # main_logger.debug(op_copy)
            main_logger.debug(dest_name + " : file transfer Success")
            result = File_tr_Success + "Transfered size " + transfered_Size
        else:
            # main_logger.debug(op_copy)
            main_logger.debug("file transfer Failed")
            result = File_tr_Failed + " expected=" + file_size + " actual_transfered=" + transfered_Size
    else:
        main_logger.debug("VD to CPE " + dest_ip + " file transfer Failed.")
        result =  File_tr_Failed + output1
    device_report[dest_name] = [dest_name, source_file, result]
    return



def sec_pkg_execute(netconnect, cpe_name, cpe_user, cpe_passwd, filename, cpe_logger):
    global file_size, source_md5_checksum, oss_patch_version
    netconnect.send_command_expect("shell ", strip_prompt=False, strip_command=False, expect_string = "\$|#")
    dest_file_detail = netconnect.send_command_expect("ls -ltr /home/versa/packages/" + filename, strip_prompt=False, strip_command=False)
    cpe_logger.debug(dest_file_detail)
    if "No such file or directory" in dest_file_detail:
        cpe_logger.info(cpe_name + " : "+ dest_file_detail)
        return dest_file_detail
    else:
        dest_file_size = re.search("\S+ versa (\S+) ", dest_file_detail).group(1)
        cpe_logger.info(cpe_name + " file size: " + dest_file_size)
        dest_file_md5_check = netconnect.send_command_expect("md5sum /home/versa/packages/" + source_file, expect_string = "\$|#")
        cpe_logger.debug(dest_file_md5_check)
        dest_file_md5_checksum = re.search("(\S+)  /home/versa/packages/" + source_file, dest_file_md5_check).group(1)
        cpe_logger.debug(cpe_name + " File Checksum : " + dest_file_md5_checksum)
    time.sleep(1)
    if file_size != dest_file_size:
        err_info =  "File Size is not same as source: sourcefile_size=" + file_size + " destfile_size=" + dest_file_size
        cpe_logger.info(err_info)
        return err_info
    if dest_file_md5_checksum != source_md5_checksum:
        md5_err_info = "File checksum is not same as Source: src_file_checksum=" + source_md5_checksum + " dest_file_checksum=" + dest_file_md5_checksum
        cpe_logger.info(md5_err_info)
        return md5_err_info
    #chmod of bin file
    cpe_logger.debug(netconnect.send_command_expect("sudo bash\n", expect_string = ":|\$|#"))
    cpe_logger.debug(netconnect.send_command_expect(cpe_passwd + "\n", expect_string = "\$|#"))
    # time.sleep(1)
    cpe_logger.debug(netconnect.send_command_expect("chmod a+x /home/versa/packages/" + filename, strip_prompt=False, strip_command=False, expect_string = "\$|#"))
    # time.sleep(1)

    cpe_logger.debug(netconnect.send_command_expect("exit\n", expect_string = "\$|#"))
    # time.sleep(1)
    sec_exec_logs_file = "/tmp/packtrack_" + currtime
    cpe_logger.debug("Security pack execution Logfile : " + sec_exec_logs_file)
    cmd_exec_sec_pack = "sudo /home/versa/packages/" + filename + " > " + sec_exec_logs_file +" 2>&1 &"
    cpe_logger.debug(cmd_exec_sec_pack)
    cpe_logger.debug(netconnect.send_command_expect(cmd_exec_sec_pack + "\n", expect_string = "\$|#"))
    time.sleep(5)
    try:
        script_process_id = netconnect.send_command_expect("echo $!", expect_string = "\$|#")
    except IOError as IE:
        cpe_logger.info(IE)
        cpe_logger.info(netconnect.send_command_expect("ps -ef | grep " + filename + " | grep -v grep ", expect_string = "\$"))
        script_process_id = netconnect.send_command_expect("ps -ef | grep \"sudo /home/versa/packages/" + filename + "\""\
                                                           + " | grep -v grep | awk '{print  $2}'", expect_string = "\$|#")
        # return "Failed: Unable to get Process ID "
    script_process_id = re.sub(r"[\n\t\s\']*", "", script_process_id)
    cpe_logger.debug(".............." + script_process_id + "..........")
    if script_process_id == "":
        return "Failed: Process not found "
    timer = 0
    while script_process_id in netconnect.send_command_expect("ps -ef | grep -w " + script_process_id + " | grep -v grep", expect_string = "\$|#"):
        cpe_logger.debug("process timer value : " + str(timer))
        if timer > 120:
            return filename + " : " + script_process_id + " Process running more than 120 secs"
        cpe_logger.info(cpe_name + " : " + script_process_id + " process alive")
        timer += 5
        time.sleep(5)
    bin_process = netconnect.send_command_expect("cat " + sec_exec_logs_file, strip_prompt=False, strip_command=False, expect_string = "\$|#")
    cpe_logger.debug(bin_process)
    if 'All packages are already at latest version' in bin_process:
        return filename + " Patch execution already done. All packages are already at latest version"
    if 'error:' in bin_process or 'Error' in bin_process:
        return filename + " Patch execuiton failed. Error Found in exec Log"
    else:
        netconnect.send_command_expect("exit", strip_prompt=False,
                                                     strip_command=False, expect_string=">")
        result = netconnect.send_command_expect("show security osspack info | tab", strip_prompt=False,
                                                     strip_command=False, expect_string=">")
        if oss_patch_version in result:
            return filename + " Patch Execution success"
        else:
            return filename + " Patch execuiton success. Version not found in show security oss pack info | tab"


def req_install_security_package(netconnect, cpe_name, cpe_user, cpe_passwd, cpe_logger, sec_pkg_vers_number):
    netconnect.send_command_expect("shell ", strip_prompt=False, strip_command=False, expect_string = "\$|#")
    cpe_logger.debug(netconnect.send_command_expect("sudo su\n", expect_string = ":|\$|#"))
    # cpe_logger.debug(netconnect.send_command_expect(cpe_passwd + "\n", expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("mv /home/versa/packages/versa-security-package-* /opt/versa/etc/spack/downloads/", strip_prompt=False, strip_command=False, expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("chown versa:versa /opt/versa/etc/spack/downloads/*", strip_prompt=False, strip_command=False, expect_string="\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("chmod 664 /opt/versa/etc/spack/downloads/*", strip_prompt=False, strip_command=False, expect_string="\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("sed -i 's/premium/sample/g' /opt/versa/etc/spack/.flavor", strip_prompt=False, strip_command=False, expect_string="\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("exit\n", expect_string = "\$|#"))
    cpe_logger.debug(netconnect.send_command_expect("exit\n", expect_string=">"))
    cpe_logger.debug(netconnect.send_command_expect("show security security-package information | tab", strip_prompt=False, strip_command=False, expect_string="\]"))
    cpe_logger.debug(netconnect.send_command_expect("request security security-package install version number " + sec_pkg_vers_number, strip_prompt=False, strip_command=False, expect_string="\]"))
    # cpe_logger.debug(netconnect.send_command_expect("request security security-package install status", strip_prompt=False, strip_command=False, expect_string="\]"))
    # time.sleep(5)
    # cpe_logger.debug(netconnect.send_command_expect("request security security-package install status", strip_prompt=False, strip_command=False, expect_string="\]"))
    return "req sec package install command executed"

def run_thread_for_modify(cpe_name, cpe_user, cpe_passwd, dev_dict, i):
    global device_report, cpe_list
    cpe_logger = setup_logger(cpe_name, cpe_name)
    cpe_logger_dict[cpe_name] = cpe_logger
    netconnect = make_connection_return_conn_fail(dev_dict)
    if isinstance(netconnect, str) and "CONN_ERR:" in netconnect:
        result = netconnect
        device_report[cpe_name] = [cpe_name, source_file, result]
        return
    sec_result = modify_vshell(netconnect, cpe_name, cpe_user, cpe_passwd, source_file, cpe_logger)
    device_report[cpe_name] += [sec_result]
    # close_cross_connection(netconnect)
    close_connection(netconnect)
    return

def run_thread_for_upgrade(cpe_name, cpe_user, cpe_passwd, dev_dict, i):
    global device_report, cpe_list
    cpe_logger = setup_logger(cpe_name, cpe_name)
    cpe_logger_dict[cpe_name] = cpe_logger
    netconnect = make_connection_return_conn_fail(dev_dict)
    if isinstance(netconnect, str) and "CONN_ERR:" in netconnect:
        result = netconnect
        device_report[cpe_name] += [result]
        return
    sec_result = sec_pkg_execute(netconnect, cpe_name, cpe_user, cpe_passwd, source_file, cpe_logger)
    device_report[cpe_name] += [sec_result]
    # close_cross_connection(netconnect)
    close_connection(netconnect)
    return

def run_thread_for_package_upgrade(cpe_name, cpe_user, cpe_passwd, dev_dict, i, sec_pkg_vers_number):
    global source_file, device_report, cpe_list
    cpe_logger = setup_logger(cpe_name, cpe_name)
    cpe_logger_dict[cpe_name] = cpe_logger
    netconnect = make_connection_return_conn_fail(dev_dict)
    if isinstance(netconnect, str) and "CONN_ERR:" in netconnect:
        result = netconnect
        device_report[cpe_name] += [result]
        return
    sec_result = req_install_security_package(netconnect, cpe_name, cpe_user, cpe_passwd, cpe_logger, sec_pkg_vers_number)
    device_report[cpe_name] += [sec_result]
    close_connection(netconnect)
    return

def Modify_vshell_file():
    global File_tr_Success, File_tr_Failed, upload_report, result_list
    global report, cpe_list, parsed_dict, cpe_logger, cpe_logger_dict, source_file
    global device_report
    cpe_list_print()
    time.sleep(2)
    device_report = {}
    vd_cli_nc = make_connection_to_cli(vd_ssh_dict)
    for i, rows in cpe_list.iterrows():
        cpe_name = cpe_list.ix[i, 'device_name_in_vd']
        cpe_ip = cpe_list.ix[i, 'ip']
        cpe_type = cpe_list.ix[i, 'type']
        if cpe_type == 'branch':
            dev_username = vd_dict['cpe_user']
            dev_passwd = vd_dict['cpe_passwd']
        else:
            dev_username = vd_dict['node_user']
            dev_passwd = vd_dict['node_passwd']

        dev_dict = {
            "device_type": 'linux', "ip": cpe_ip, \
            "username": dev_username, "password": dev_passwd, \
            "port": '22'
        }
        device_report[cpe_name] = [cpe_name, source_file]
        check_result = request_ping(vd_cli_nc, cpe_name)
        print check_result
        if check_result == 'False':
            device_report[cpe_name] += ["Ping failed"]
            cpe_list = cpe_list.drop(index=i)
            main_logger.info(cpe_name + ":" + check_result)
    close_connection(vd_cli_nc)
    try:
        threads = []
        for i, rows in cpe_list.iterrows():
            cpe_name = cpe_list.ix[i, 'device_name_in_vd']
            cpe_ip = cpe_list.ix[i, 'ip']
            cpe_type = cpe_list.ix[i, 'type']
            if cpe_type == 'branch':
                dev_username = vd_dict['cpe_user']
                dev_passwd =  vd_dict['cpe_passwd']
            else:
                dev_username = vd_dict['node_user']
                dev_passwd =  vd_dict['node_passwd']

            dev_dict = {
                "device_type": 'versa', "ip": cpe_ip, \
                "username": dev_username, "password": dev_passwd, \
                "port": '22'
            }
            device_report[cpe_name] = [cpe_name, source_file]
            thrd_objs = threading.Thread(target=run_thread_for_modify, args=(cpe_name, dev_username, dev_passwd, dev_dict, i))
            # thrd_objs.setDaemon(True)
            threads.append(thrd_objs)
        for th in threads:
            main_logger.info("starting thread :" + str(th.name) + " For device " + th._Thread__args[0] + "\n")
            # print "DEVICE NAME: " + th._Thread__args[0]
            th.start()

        print threading.activeCount()

        for th in threads:
            th.join()

        for th in threads:
            th.exit()

        print threading.activeCount()
            # thrd_objs.start()
            # thrd_objs.join()
            # thrd_objs.join()
            # thread.start_new_thread(run_thread_for_upgrade, (cpe_name, dev_dict, i))
            # print " starting thread for " + str(i)
    except:
        main_logger.info("Error: unable to start Thread")
        # sec_result = run_thread_for_upgrade(cpe_name, dev_dict, i)
        # device_report[cpe_name] += [sec_result]

    main_logger.info("<<<<<Vshell modfication result RESULT>>>")
    main_logger.info("'cpe', 'filename', 'Vshell modification'")
    for dev, sec_patch_result in device_report.iteritems():
        main_logger.info(sec_patch_result)
    for dev_key in device_report:
        result_list.append(device_report[dev_key])



def sec_patch_upgrade_devices():
    global File_tr_Success, File_tr_Failed, upload_report, result_list
    global report, cpe_list, parsed_dict, cpe_logger, cpe_logger_dict, source_file
    global device_report
    cpe_list_print()
    time.sleep(2)
    device_report = {}
    file_check(source_file)
    try:
        threads = []
        for i, rows in cpe_list.iterrows():
            cpe_name = cpe_list.ix[i, 'device_name_in_vd']
            cpe_ip = cpe_list.ix[i, 'ip']
            cpe_type = cpe_list.ix[i, 'type']
            if cpe_type == 'branch':
                dev_username = vd_dict['cpe_user']
                dev_passwd =  vd_dict['cpe_passwd']
            else:
                dev_username = vd_dict['node_user']
                dev_passwd =  vd_dict['node_passwd']

            dev_dict = {
                "device_type": 'versa', "ip": cpe_ip, \
                "username": dev_username, "password": dev_passwd, \
                "port": '22'
            }
            device_report[cpe_name] = [cpe_name, source_file]
            thrd_objs = threading.Thread(target=run_thread_for_upgrade, args=(cpe_name, dev_username, dev_passwd, dev_dict, i))
            # thrd_objs.setDaemon(True)
            threads.append(thrd_objs)
        for th in threads:
            main_logger.info("starting thread :" + str(th.name) + " For device " + th._Thread__args[0] + "\n")
            # print "DEVICE NAME: " + th._Thread__args[0]
            th.start()

        #print threading.activeCount()

        for th in threads:
            th.join()

        for th in threads:
            th.exit()

        #print threading.activeCount()
            # thrd_objs.start()
            # thrd_objs.join()
            # thrd_objs.join()
            # thread.start_new_thread(run_thread_for_upgrade, (cpe_name, dev_dict, i))
            # print " starting thread for " + str(i)
    except:
        main_logger.debug("Error: unable to start ")
        # sec_result = run_thread_for_upgrade(cpe_name, dev_dict, i)
        # device_report[cpe_name] += [sec_result]

    main_logger.info("<<<<<Security patch execution RESULT>>>")
    main_logger.info("'cpe', 'filename', 'patch_upgrade_status'")
    for dev, sec_patch_result in device_report.iteritems():
        main_logger.info(sec_patch_result)
    for dev_key in device_report:
        result_list.append(device_report[dev_key])

def sec_package_upgrade_devices(sec_pkg_vers_number):
    global source_file, upload_report, result_list
    global report, cpe_list, parsed_dict, cpe_logger, cpe_logger_dict, source_file
    global device_report
    cpe_list_print()
    time.sleep(2)
    device_report = {}
    try:
        threads = []
        for i, rows in cpe_list.iterrows():
            cpe_name = cpe_list.ix[i, 'device_name_in_vd']
            cpe_ip = cpe_list.ix[i, 'ip']
            cpe_type = cpe_list.ix[i, 'type']
            if cpe_type == 'branch':
                dev_username = vd_dict['cpe_user']
                dev_passwd =  vd_dict['cpe_passwd']
            else:
                dev_username = vd_dict['node_user']
                dev_passwd =  vd_dict['node_passwd']

            dev_dict = {
                "device_type": 'versa', "ip": cpe_ip, \
                "username": dev_username, "password": dev_passwd, \
                "port": '22'
            }
            device_report[cpe_name] = [cpe_name, source_file]
            thrd_objs = threading.Thread(target=run_thread_for_package_upgrade, args=(cpe_name, dev_username, dev_passwd, dev_dict, i, sec_pkg_vers_number))
            threads.append(thrd_objs)
        for th in threads:
            main_logger.info("starting thread :" + str(th.name) + " For device " + th._Thread__args[0] + "\n")
            # print "DEVICE NAME: " + th._Thread__args[0]
            th.start()

        #print threading.activeCount()

        for th in threads:
            th.join()

        for th in threads:
            th.exit()
    except:
        # main_logger.debug("Error: unable to start Thread for " + cpe_name)
        main_logger.debug("CPENAME:>>" + cpe_name)
    main_logger.info("<<<<<Security package execution RESULT>>>")
    main_logger.info("'cpe', 'filename', 'package_upgrade_status'")
    for dev, sec_patch_result in device_report.iteritems():
        main_logger.info(sec_patch_result)
    for dev_key in device_report:
        result_list.append(device_report[dev_key])

def package_upload_to_devices():
    global File_tr_Success, File_tr_Failed, upload_report, result_list, device_report
    global report, cpe_list, parsed_dict, cpe_logger, cpe_logger_dict, source_file, file_size
    cpe_list_print()
    time.sleep(2)
    device_report = {}
    source_file_detail = subprocess.check_output("ls -ltr /tmp/" + source_file + " | awk '{print $5}'", shell=True, stderr=subprocess.STDOUT).rstrip()
    # source_file_detail = netconnect.send_command_expect("ls -ltr " + source_file, expect_string = "\$")
    main_logger.debug(source_file_detail)
    if "No such file or directory" in source_file_detail:
        main_logger.info(source_file_detail)
        exit()
    else:
        # source_file_detail_list = source_file_detail.split(" ")
        # main_logger.debug("File size is " + source_file_detail_list[6])
        # file_size = source_file_detail_list[6]
        file_size = source_file_detail
        source_md5_check = subprocess.check_output("md5sum /tmp/" + source_file + " | awk '{print $1}'", shell=True, stderr=subprocess.STDOUT).rstrip()
        main_logger.debug(source_md5_check)
        source_md5_checksum = source_md5_check
        main_logger.debug("Source File Checksum : " + source_md5_checksum)
    time.sleep(1)
    try:
        threads = []
        for i, rows in cpe_list.iterrows():
            cpe_name = cpe_list.ix[i, 'device_name_in_vd']
            cpe_ip = cpe_list.ix[i, 'ip']
            cpe_type = cpe_list.ix[i, 'type']
            if cpe_type == 'branch':
                dev_username = vd_dict['cpe_user']
                dev_passwd = vd_dict['cpe_passwd']
            else:
                dev_username = vd_dict['node_user']
                dev_passwd = vd_dict['node_passwd']
            thrd_objs = threading.Thread(target=file_upload, args=(source_file, cpe_name, cpe_ip, dev_username, dev_passwd, i))
            threads.append(thrd_objs)
        for th in threads:
            main_logger.info("starting thread :" + str(th.name) + " For device " + th._Thread__args[1] + "\n")
            # print "DEVICE NAME: " + th._Thread__args[0]
            th.start()
        #print threading.activeCount()

        for th in threads:
            th.join()

        for th in threads:
            th.exit()
    except:
            main_logger.debug("Error: unable to start ")
            # sec_result = run_thread_for_upgrade(cpe_name, dev_dict, i)
            # device_report[cpe_name] += [sec_result]

    main_logger.info("<<<<<Security patch execution RESULT>>>")
    main_logger.info("'cpe', 'filename', 'patch_upgrade_status'")
    for dev, sec_patch_result in device_report.iteritems():
        main_logger.info(sec_patch_result)
    for dev_key in device_report:
        result_list.append(device_report[dev_key])



def DO_File_Transfer():
    global source_file, result_list
    time.sleep(1)
    source_file = raw_input("Enter File name to transfer Bastionhost to Devices.(file should be in BH /tmp folder):\n")
    global cpe_list, batch
    build_csv(get_device_list(oper_type="file_transfer"))
    raw_input("Edit " + cpe_list_file_name +" & Press enter to continue")
    csv_data_read = pd.read_csv(cpe_list_file_name)
    batches = max(csv_data_read['batch'])
    batches_list = csv_data_read['batch'].drop_duplicates().sort_values().values
    main_logger.debug("total batches : " +  str(csv_data_read['batch'].drop_duplicates().count()))
    main_logger.debug("batch List : " + str(batches_list))
    # batches = csv_data_read['batch'].values.max
    # cpe_list = read_csv_file(cpe_list_file_name, 'CPE-27')
    # for singlebatch in range(1, batches+1):
    for singlebatch in batches_list:
        cpe_list = read_csv_file(cpe_list_file_name, day, singlebatch)
        main_logger.debug("DAY :" + str(day))
        main_logger.debug("Batch : " + str(singlebatch))
        package_upload_to_devices()
    write_result(result_list, 'file_upload')


def DO_Sec_patch_Upgrade():
    global source_file, result_list, oss_patch_version
    time.sleep(1)
    source_file = raw_input("Enter patch file name:\n")
    oss_patch_version = raw_input("Enter oss patch version:\n")
    global cpe_list, batch
    build_csv(get_device_list())
    raw_input("Edit " + cpe_list_file_name +" & Press enter to continue")
    csv_data_read = pd.read_csv(cpe_list_file_name)
    batches = max(csv_data_read['batch'])
    batches_list = csv_data_read['batch'].drop_duplicates().sort_values().values
    main_logger.info("total batches : " +  str(csv_data_read['batch'].drop_duplicates().count()))
    main_logger.info("batch List : " + str(batches_list))
    for singlebatch in batches_list:
        cpe_list = read_csv_file(cpe_list_file_name, day, singlebatch)
        main_logger.info("DAY :" + str(day))
        main_logger.info("Batch : " + str(singlebatch))
        sec_patch_upgrade_devices()
    write_result(result_list, 'sec_patch_execuiton')

def DO_Sec_package_Upgrade():
    global source_file, result_list
    global cpe_list, batch
    build_csv(get_device_list_only_branch(oper_type="sec_package"))
    time.sleep(5)
    raw_input("Edit " + cpe_list_file_name + " and save and Press enter to continue")
    sec_pkg_vers_number = raw_input("Enter Security package version number:\n")
    # sec_pkg_vers_number = "1640"
    source_file = sec_pkg_vers_number
    csv_data_read = pd.read_csv(cpe_list_file_name)
    batches = max(csv_data_read['batch'])
    start_batch = min(csv_data_read['batch'])
    for singlebatch in range(int(start_batch), int(batches)+1):
        cpe_list = read_csv_file(cpe_list_file_name, day, singlebatch)
        if len(cpe_list) == 0:
            continue
        main_logger.info("DAY :" + str(day))
        main_logger.info("Batch : " + str(singlebatch))
        sec_package_upgrade_devices(sec_pkg_vers_number)
    write_result(result_list, 'sec_package_execuiton')

def DO_vshell_Modify():
    global source_file, result_list
    time.sleep(1)
    source_file = vshellfile
    global cpe_list, batch
    build_csv(get_device_list_wo_ping_check())
    raw_input("Edit " + cpe_list_file_name +" & Press enter to continue")
    csv_data_read = pd.read_csv(cpe_list_file_name)
    batches = max(csv_data_read['batch'])
    batches_list = csv_data_read['batch'].drop_duplicates().sort_values().values
    main_logger.info("total batches : " +  str(csv_data_read['batch'].drop_duplicates().count()))
    main_logger.info("batch List : " + str(batches_list))
    for singlebatch in batches_list:
        cpe_list = read_csv_file(cpe_list_file_name, day, singlebatch)
        main_logger.info("DAY :" + str(day))
        main_logger.info("Batch : " + str(singlebatch))
        Modify_vshell_file()
        time.sleep(1)
    write_result(result_list, 'sec_patch_execuiton')

# main()



