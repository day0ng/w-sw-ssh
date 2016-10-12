#!/usr/bin/env python

"""
    Emulates SSH login and executes cli commands as user interactive to network
    devices such as switches, routers etc.

    Copyright (c) Dayong Wang, wandering_997@sina.com
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Revision history
    ~~~~~~~~~~~~~~~~
    2015/11/07
    creates by Dayong Wang:
    - Just remove some unnecessary information.

    2016/10/11
    bug fix by Dayong Wang:
    - Exit while password is wrong and ask for input again.

    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: $
    $Rev: $
    $Author: $

"""

import getopt
import getpass
import os
import pexpect
import re
import subprocess
import sys
import threading
import time



def help_and_exit():

    print('''
Usage:  %s <options>

    --uid <uid>                 SSH username

    --pwd <pwd>                 SSH password

    -p                          Get password from user input

    --host <ip[:port],...>      ip[:port] list of remote ssh server, default port is 22

    --host_file <file_name>     File of ip[:port] list

    --cmd <cmd1;cmd2;...>       Command list to execute on remote ssh server

    --cmd_prefix <file_prefix>  Prefix of command list files. For example:
                                    test.cmd.cisco
                                    test.cmd.cisco_nexus
                                    test.cmd.h3c
                                    test.cmd.huawei
                                'test' is the prefix (--cmd_prefix).

    --cmd_interval <seconds>    Time to wait after a command being executed, default is 0.5s.
                                And some devices would get error if execute command too fast.

    --save                      Save config on device automatically after user cmd being executed.

    --log_dir <path>            Log command output to /<path>/<ip_addr> instead of stdout.
                                Example:
                                /var/log/test/$(date "+%%Y")/$(date "+%%Y%%m%%d")/

    --thread <num>              The maximum threads could be spread each time, default is 1000.

    --timeout <seconds>         Time to wait for command executing, default is 10 seconds.
                                Try to set higher value in case of seeing 'pexpect timed out' error.

    --l2_sw                     Check the layer-2 switch only infomation, such as uplink, gateway etc.


Caution:

    --host has higher priority than --host_file
    --cmd  has higher priority than --cmd_prefix


Example:

    w-sw-ssh.py --uid npc -p --host 192.168.161.10 --cmd "disp users"
    w-sw-ssh.py --uid npc -p --host_file ~/ip.test --cmd_prefix ~/cmd.test

''' % (os.path.basename(__file__)))

    sys.exit()



def w_time(time_format = '%Y-%m-%d %H:%M:%S'):

    return time.strftime(time_format, time.localtime(time.time()))



def sys_cmd(str_cmd):

    sp = subprocess.Popen(str_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    str_out = sp.stdout.read()
    str_err = sp.stderr.read()
    sp.wait()
    return [str_out, str_err]



def w_threading(func_name, func_args, max_thread):

    # multi threading
    if func_name == None or func_name == '':
        print('w_threading() error: func_name is empty.\n')
        return False
    if func_args == None or not isinstance(func_args, list):
        print('w_threading() error: func_args is wrong.\n')
        return False
    if not isinstance(max_thread, int) or max_thread == None or max_thread == '':
        max_thread = 1000

    # create thread pool
    thread_pool = list()
    for i in range(0, len(func_args)):
        th = threading.Thread(target=func_name, args=func_args[i])
        thread_pool.append(th)

    # execute threads for max_thread number of threads each time
    thread_count = len(thread_pool)
    if thread_count > max_thread:
        i_begin = 0
        i_end = 0
        round_num = thread_count / max_thread
        if thread_count % max_thread > 0:
            round_num += 1
        # max_thread: How many threads (test) could be executed at one time
        for j in range(0, round_num):
            i_begin = j * max_thread
            if j == round_num - 1:                 # the last round
                i_end = thread_count
            else:
                i_end = i_begin + max_thread
            # start threads
            for i in range(i_begin, i_end):
                thread_pool[i].start()
            # terminate threads
            for i in range(i_begin, i_end):
                thread_pool[i].join()
    # === thread_count <= max_thread ===
    else:
        # start threads
        for i in range(0, thread_count):
            thread_pool[i].start()
        # terminate threads
        for i in range(0, thread_count):
            thread_pool[i].join()
    # ========== Run threads - End ==========
#___ End of w_threading() ____



def uf_login_expect(ssh, timeout, f_out):
    #
    #_____ yes/no | password _____
    #
    # [root@SERVER bin]# ssh npc@172.22.131.63
    # The authenticity of host '172.22.131.63 (172.22.131.63)' can't be established.
    # RSA key fingerprint is 9c:9c:e2:41:7d:83:76:80:d5:fa:97:38:da:fe:4d:23.
    # Are you sure you want to continue connecting (yes/no)? yes
    # Warning: Permanently added '172.22.131.63' (RSA) to the list of known hosts.
    # npc@172.22.131.63's password: 
    # Password incorrect.
    # 
    # Login failed, check your uid or pwd.Permission denied, please try again.
    # npc@172.22.131.63's password:
    #
    #_____ known_hosts _____
    #
    # [root@SERVER bin]# ssh npc@172.22.131.63
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
    # Someone could be eavesdropping on you right now (man-in-the-middle attack)!
    # It is also possible that the RSA host key has just been changed.
    # The fingerprint for the RSA key sent by the remote host is
    # 9c:9c:e2:41:7d:83:76:80:d5:fa:97:38:da:fe:4d:23.
    # Please contact your system administrator.
    # Add correct host key in /root/.ssh/known_hosts to get rid of this message.
    # Offending key in /root/.ssh/known_hosts:2330
    # RSA host key for 172.22.131.63 has changed and you have requested strict checking.
    # Host key verification failed.
    # [root@SERVER bin]#
    #
    cmd_out = ''
    try:
        idx = ssh.expect(['(P|p)assword: $', '\(yes/no\)\?', 'Host key verification failed'], timeout=timeout)
        cmd_out = '%s%s' % (ssh.before, ssh.after)
        if f_out == None:
            print(cmd_out)
        else:
            f_out.write(cmd_out)
        return [idx, cmd_out]
    except:
        return [-1, cmd_out]



def uf_login_fix_known_hosts(cmd_out):

    tmp_out = cmd_out.split("\n")
    for tmp_row in tmp_out:
        # Offending key in /root/.ssh/known_hosts:2330
        if re.search('known_hosts:[0-9]+', tmp_row, re.IGNORECASE) == None:
            continue
        tmp_row = re.sub('^.* /', '/', tmp_row).strip()
        tmp_hosts, tmp_line = tmp_row.split(':')
        tmp_cmd = "sed -i '%sd' %s" % (tmp_line, tmp_hosts)
        return sys_cmd(tmp_cmd)
    return ''



def uf_login_send_yes(ssh, sleep_time):

    ssh.sendline('yes')
    time.sleep(sleep_time)
    return True



def uf_login_send_pwd(ssh, sleep_time, pwd):

    ssh.sendline(pwd)
    time.sleep(sleep_time)
    return True



def uf_ssh_login(ssh, timeout, output_file, f_out, ip, port, uid, pwd, sleep_time):
    #
    # Depends on:
    #
    #   uf_login_expect()
    #   uf_login_fix_known_hosts()
    #   uf_login_send_yes()
    #   uf_login_send_pwd()
    # 
    idx, cmd_out = uf_login_expect(ssh, timeout, f_out)             # login expect
    # login error
    if idx == -1:
        print('[%s] %s:%s Error: uid <%s> login failed (1)' % (w_time(), ip, port, uid))
        return False
    # wrong known_hosts
    if idx == 2:
        uf_login_fix_known_hosts(cmd_out) 
        print('[%s] %s:%s Error: Host key was fixed and try again.' % (w_time(), ip, port))
        return False
    # ask for yes/no
    if idx == 1:
        uf_login_send_yes(ssh, sleep_time)
        idx, cmd_out = uf_login_expect(ssh, timeout, f_out)         # login expect
    # ask for password
    if idx == 0:
        uf_login_send_pwd(ssh, sleep_time, pwd)
    return True



def uf_expect_prompt(ssh, timeout, f_out):
    #
    # Prompt:
    #
    #       ^MBJ_XX_311-F-02_N7718-1#
    #       <BJ_XX_305-A-15_CE5810>
    #       <BJ-XXX-101-1109/1111-LVS-S5500>
    #       ^@<BJ_XX_311_F-12-13_LVS_S5560>
    #       BJ-XXX-2-2960S-2016#
    #       [~BJ_XX_320-I-10_CE5810]
    #
    # Characters:
    #
    #       < > a-z A-Z 0-9 ~ @ * / _ - [] ()
    #
    # Q: Why put a . next to \\n)?
    # A: Some devices output a prompt likes ^@<BJ_XX_311_F-12-13_LVS_S5560>
    #
    prompt = "(\\r|\\n).?[<>a-zA-Z0-9~@\*/_\-\[\]\(\)]+(>|%|#|\\$|\]) *$"
    cmd_out = ''
    try:
        idx = ssh.expect([prompt, pexpect.TIMEOUT], timeout=timeout)
        cmd_out = '%s%s' % (ssh.before, ssh.after)
        if f_out == None:
            print(cmd_out)
        else:
            f_out.write(cmd_out)
        return [idx, cmd_out]
    except:
        return [-1, cmd_out]



def uf_expect_sendline(ssh, timeout, f_out, sleep_time, content):

    ssh.sendline('')
    ssh.sendline(content)
    time.sleep(sleep_time)
    return uf_expect_prompt(ssh, timeout, f_out)



def uf_get_vendor_model(ssh, timeout, f_out, sleep_time):

    vendor  = ''
    model   = ''
    cmd_out = ''
    #___ Get vendor ___
    reg_vendor_search = ''
    reg_vendor_sub = ''
    # 1st, for h3c or huawei devices
    tmp_cmd = 'display version | in (Huawei|H3C).*(Software|uptime)'
    idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, tmp_cmd)
    if idx == 1:
        print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
        return [vendor, model]
    if re.search('% Invalid|Unrecognized command', cmd_out) == None:
        if cmd_out.find('H3C ') >= 0:
            vendor = '%s%s' % (vendor, 'h3c')
            reg_vendor_search = '^h3c.*uptime'
            reg_vendor_sub = ' *uptime.*$'
        if cmd_out.find('Huawei ') >= 0:
            vendor = '%s%s' % (vendor, 'huawei')
            reg_vendor_search = '^huawei.*uptime'
            reg_vendor_sub = ' *uptime.*$'
    # 2nd, for cisco devices
    else:
        tmp_cmd = 'show version | in Cisco.*Software|cisco.*(Chassis|processor)'
        idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, tmp_cmd)
        if idx == 1:
            print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
            return [vendor, model]
        if cmd_out.find('Cisco Nexus ') >= 0:
            vendor = 'cisco_nexus'
            reg_vendor_search = '^cisco.*chassis'
            reg_vendor_sub = ' *(\(|chassis).*$'
        elif cmd_out.find('Cisco ') >= 0:
            vendor = 'cisco'
            reg_vendor_search = '^cisco.*processor'
            reg_vendor_sub = ' *(\(|chassis).*$'
    #___ Get model ___
    tmp_row = ''
    tmp_out = cmd_out.split('\n')
    for tmp_row in tmp_out:
        tmp_row = tmp_row.strip()
        if re.search(reg_vendor_search, tmp_row, re.IGNORECASE) == None:
            continue
        else:
            model = re.sub(reg_vendor_sub, '', tmp_row, re.IGNORECASE)
            model = re.sub('^(cisco nexus|cisco|h3c|huawei) *', '', model, re.IGNORECASE)
            break 
    # Return
    return [vendor, model]



def uf_set_nomore(ssh, timeout, f_out, sleep_time, vendor):

    cmd_nomore = ''
    if vendor == 'cisco':
        cmd_nomore = 'terminal length 0'
    if vendor == 'cisco_nexus':
        cmd_nomore = 'terminal length 0'
    if vendor == 'h3c':
        cmd_nomore = 'screen-length disable'
    if vendor == 'huawei':
        cmd_nomore = 'screen-length 0 temp'
    return uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_nomore)



def uf_save(ssh, timeout, f_out, sleep_time, vendor):

    cmd_save = ''
    if vendor == 'cisco':
        cmd_save = 'end\rcopy run start\r'
    if vendor == 'cisco_nexus':
        cmd_save = 'copy run start'
    if vendor == 'h3c':
        cmd_save = 'save force'
    if vendor == 'huawei':
        cmd_save = 'return\rsave\r\y\r'
    return uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_save)



def uf_logout(ssh, timeout, f_out, sleep_time, vendor):

    cmd_logout = ''
    if vendor == 'cisco':
        cmd_logout = 'end\rexit'
    if vendor == 'cisco_nexus':
        cmd_logout = 'end\rexit'
    if vendor == 'h3c':
        cmd_logout = 'quit\rquit\r'
    if vendor == 'huawei':
        cmd_logout = 'quit\rquit\r'
    return uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_logout)



def uf_get_l2_uplink(ssh, timeout, f_out, sleep_time, vendor):

    l2_uplink         = ''
    gw_ip             = ''
    gw_mac            = ''
    cmd_get_gw_ip     = ''
    cmd_get_gw_mac    = ''
    cmd_get_gw_uplink = ''
    reg_get_gw_ip_search  = '\s?[1-9]\d{0,2}(\.\d{1,3}){3}\s?'           # match ip but not 0.0.0.0
    reg_get_gw_mac_search = '\s?([\da-f]{4}[\.-]){2}[\da-f]{4}\s?'
    reg_get_gw_uplink_sub = ''

    # Init cmd
    if vendor == 'cisco':
        cmd_get_gw_ip     = 'show ip default-gateway'
        cmd_get_gw_mac    = 'show ip arp _IP_'
        cmd_get_gw_uplink = 'show mac address-table address _MAC_'
    if vendor == 'cisco_nexus':
        cmd_get_gw_ip     = 'show ip route 0.0.0.0/0'
        cmd_get_gw_mac    = 'show ip arp _IP_'
        cmd_get_gw_uplink = 'show mac address-table address _MAC_'
    if vendor == 'h3c':
        cmd_get_gw_ip     = 'display ip routing-table 0.0.0.0 0'
        cmd_get_gw_mac    = 'disp arp _IP_'
        cmd_get_gw_uplink = 'display mac-address _MAC_'
    if vendor == 'huawei':
        cmd_get_gw_ip     = 'display ip routing-table 0.0.0.0 0'
        cmd_get_gw_mac    = 'disp arp dynamic | include _IP_'
        cmd_get_gw_uplink = 'display mac-address _MAC_'

    # Get gateway IP
    idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_get_gw_ip)
    if idx == 1:
        print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
        return l2_uplink
    if idx == -1:
        return l2_uplink
    tmp_row = ''
    tmp_out = cmd_out.split('\n')
    for tmp_row in tmp_out:
        tmp_row = tmp_row.strip()
        tmp_re = re.search(reg_get_gw_ip_search, tmp_row, re.IGNORECASE)
        if tmp_re == None:
            continue
        else:
            gw_ip = tmp_re.group(0).strip()
            break 
    if gw_ip == '':
        return l2_uplink

    # Get gateway MAC
    cmd_get_gw_mac = re.sub('_IP_', gw_ip, cmd_get_gw_mac)
    idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_get_gw_mac)
    if idx == 1:
        print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
        return l2_uplink
    if idx == -1:
        return l2_uplink
    tmp_row = ''
    tmp_out = cmd_out.split('\n')
    for tmp_row in tmp_out:
        tmp_row = tmp_row.strip()
        tmp_re = re.search(reg_get_gw_mac_search, tmp_row, re.IGNORECASE)
        if tmp_re == None:
            continue
        else:
            gw_mac = tmp_re.group(0).strip()
            break 
    if gw_mac == '':
        return l2_uplink
   
    # Get gateway uplink
    cmd_get_gw_uplink = re.sub('_MAC_', gw_mac, cmd_get_gw_uplink)
    idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_get_gw_uplink)
    if idx == 1:
        print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
        return l2_uplink
    if idx == -1:
        return l2_uplink
    tmp_row = ''
    tmp_out = cmd_out.split('\n')
    for tmp_row in tmp_out:
        tmp_row = tmp_row.strip()
        if re.search(cmd_get_gw_uplink, tmp_row) != None:
            continue
        tmp_re = re.search(reg_get_gw_mac_search, tmp_row, re.IGNORECASE)
        if tmp_re == None:
            continue
        else:
            l2_uplink = re.sub('^.*%s' % (gw_mac), '', tmp_row).strip()
            break 

    if l2_uplink != '':
        l2_uplink_list = l2_uplink.split()
        if vendor == 'h3c':
            l2_uplink = l2_uplink_list[2]
        elif vendor == 'huawei':
            l2_uplink = l2_uplink_list[1]
        elif vendor == 'cisco_nexus':
            l2_uplink = l2_uplink_list[4]
        elif vendor == 'cisco':
            l2_uplink = l2_uplink_list[1]
        else:
            l2_uplink = ''

    return l2_uplink



def w_main(ip, port, uid, pwd, cmd, cmd_prefix, cmd_interval, log_dir, flt_timeout, save, l2_sw):
    #_________ start of arguments init _________
    # arg: ip
    if not isinstance(ip, str) or ip.strip() == '':
        print('[%s] Error: incorrect IP address <%s>' % (w_time(), ip))
        return False
    # arg: port
    if not isinstance(port, str) or port.strip() == '':
        port = '22'
    # arg: uid
    if not isinstance(uid, str) or uid.strip() == '':
        print('[%s] %s:%s Error: incorrect UID' % (w_time(), ip, port))
        return False
    # arg: pwd
    if not isinstance(pwd, str) or pwd.strip() == '':
        print('[%s] %s:%s Error: incorrect PWD' % (w_time(), ip, port))
        return False
    # arg: cmd, cmd_prefix
    cmd_list = list()
    if not isinstance(cmd, str) or cmd == None or cmd.strip() == '':
        if not isinstance(cmd_prefix, str) or cmd_prefix == None or cmd_prefix.strip() == '':
            print('[%s] %s:%s Warning: neither --cmd nor --cmd_prefix was specified.\n' % (w_time(), ip, port))
        else:
            cmd_list = None
            # Then go to place where vendor was alreay identified.
    else:
        cmd_list = cmd.split(';')
    # arg: cmd_interval, default 0.5
    if isinstance(cmd_interval, float):
        sleep_time = cmd_interval
    else:
        sleep_time = 0.5
    if sleep_time <= 0:
        sleep_time = 0.5
    # arg: log_dir
    if not isinstance(log_dir, str) or log_dir == None or log_dir.strip() == '':
        output_file = ''
    else:
        output_file = '%s/%s' % (log_dir, ip)
        output_path = os.path.dirname(output_file)
        if not os.path.exists(output_path):
            try:
                sys_cmd('mkdir -p %s' % (output_path))
            except:
                print('[%s] %s:%s Error: mkdir %s failed!' % (w_time(), ip, port, output_path))
                return False
        if os.path.exists(output_path):
            try:
                f_out = open(output_file, 'w')
            except:
                print('[%s] %s:%s Error: file %s is failed to open.' % (w_time(), ip, port, output_file))
                return False
        else:
            output_file = ''
    if output_file == '':
        f_out = None
    # arg: timeout
    if isinstance(flt_timeout, float):
        timeout = flt_timeout
    else:
        timeout = 10
    # arg: save
    if not isinstance(save, str) or save.strip() == '':
        save = 'no'
    # arg: l2_sw
    if not isinstance(l2_sw, str) or l2_sw.strip() == '':
        l2_sw = 'no'
    #_________ end of arguments init _________

    # Login - ssh
    try:
        print('[%s] ssh -p %s -l %s %s' % (w_time(), port, uid, ip))
        ssh = pexpect.spawn('ssh -p %s -l %s %s' % (port, uid, ip))
        time.sleep(sleep_time)
    except:
        print('[%s] %s:%s Error: ssh failed' % (w_time(), ip, port))
        return False
    if not uf_ssh_login(ssh, timeout, output_file, f_out, ip, port, uid, pwd, sleep_time):
        return False
    idx, cmd_out = uf_expect_prompt(ssh, timeout, f_out)
    if idx != 0:
        return False

    # Get vendor and model
    vendor, model = uf_get_vendor_model(ssh, timeout, f_out, sleep_time)
    if vendor == '':
        print("[%s] %s:%s Error: can not get device vendor." % (w_time(), ip, port))
        return False
    if model == '':
        print("[%s] %s:%s Error: can not get device type." % (w_time(), ip, port))
        return False

    # Set no-more
    idx, cmd_out = uf_set_nomore(ssh, timeout, f_out, sleep_time, vendor)
    if idx == 1:
        print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
        return False

    # Get l2-uplink
    l2_uplink = ''
    if l2_sw == 'yes':
        l2_uplink = uf_get_l2_uplink(ssh, timeout, f_out, sleep_time, vendor)

    # if cmd_prefix was prefered.
    if cmd_list == None:
        cmd_prefix = '%s.cmd.%s' % (cmd_prefix, vendor)
        if not os.path.exists(cmd_prefix):
            print('[%s] %s:%s Error: %s does not exist.\n' % (w_time(), ip, port, cmd_prefix))
            return False
        f_cmd = open(cmd_prefix)
        cmd_list = f_cmd.readlines()
        f_cmd.close()

    # Execute the command
    cmd_idx = 0
    cmd_all = ''
    for i in range(0, len(cmd_list)):
        cmd_idx = i + 2
        cmd_line = cmd_list[i].strip()
        cmd_all = '%s\n%s) %s' % (cmd_all, str(i+1).rjust(5), cmd_line)
        time.sleep(sleep_time)
        try:
            idx, cmd_out = uf_expect_sendline(ssh, timeout, f_out, sleep_time, cmd_line)
            if idx == 1:
                print("[%s] %s:%s Error: pexpect timed out." % (w_time(), ip, port))
                return False
        except:
            print('\n[%s] %s:%s Error: command %s is failed to be executed.' % (w_time(), ip, port, cmd_list[i].strip()))

    # Save config
    if save == 'yes':
        if timeout < 10:
            timeout = 10
        idx, cmd_out = uf_save(ssh, timeout, f_out, sleep_time, vendor)
        cmd_all = '%s\n%s) %s' % (cmd_all, str(cmd_idx).rjust(5), '[Save Config]')
        if idx == 1:
            print("[%s] %s:%s Error: save config timed out." % (w_time(), ip, port))
            return False
        if idx == -1:
            print("[%s] %s:%s Error: save config failed." % (w_time(), ip, port))

    # Logout
    uf_logout(ssh, timeout, f_out, sleep_time, vendor)
    ssh.close()
    the_end = '''

=======================================
Device:     %s
Vendor:     %s
Model:      %s
L2_Uplink:  %s
Commands:   %s

    \r\n''' % (ip, vendor, model, l2_uplink, cmd_all)
    if f_out == None:
        print(the_end)
    else:
        f_out.write(the_end)
        f_out.close()

    return True

#___ End of w_main() ___



if __name__ == '__main__':

    host = ''
    uid = ''
    pwd = ''
    cmd = ''
    host_file = ''
    cmd_prefix = ''
    cmd_interval = 0.5
    log_dir = ''
    thread = 1000
    timeout = 10
    save = 'no'
    l2_sw = 'no'

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp", ['uid=','pwd=','host=','host_file=','cmd=','cmd_prefix=','cmd_interval=','log_dir=','thread=','timeout=','save','l2_sw'])
    except:
        print("Wrong options!")
        print("Try '-h' to get more information.")
        sys.exit()
    if len(opts) == 0:
        help_and_exit()

    for op, value in opts:

        if op == '-h':
            help_and_exit()

        elif op == '--uid':
            uid = value

        elif op == '--pwd':
            pwd = value

        elif op == '-p':
            pwd = getpass.getpass()

        elif op == '--host':
            host = value

        elif op == '--host_file':
            host_file = value

        elif op == '--cmd':
            cmd = value

        elif op == '--cmd_prefix':
            cmd_prefix = value

        elif op == '--cmd_interval':
            try:
                cmd_interval = float(value)
            except ValueError:
                print('Wrong option: --cmd_interval only accepts a float value.')
                print("Try '-h' to get more information.")
                sys.exit(1)

        elif op == '--log_dir':
            log_dir = value

        elif op == '--thread':
            if value.isalnum():
                thread = int(value)

        elif op == '--timeout':
            try:
                timeout = float(value)
            except ValueError:
                print('Wrong option: --timeout only accepts a float value.')
                print("Try '-h' to get more information.")
                sys.exit(1)

        elif op == '--save':
            save = 'yes'

        elif op == '--l2_sw':
            l2_sw = 'yes'

        else:
            help_and_exit()

    #__________ multi-thread __________

    # func_name
    func_name = w_main

    # func_args
    func_args = list()

    print('')
    if host != '':
        host_list = host.split(',')
    elif host_file != '':
        if not os.path.exists(host_file):
            print('%s does not exist, please specify host with --host or --host_file.\n' % (host_file))
            help_and_exit()

        f_host = open(host_file)
        host_list = f_host.readlines()
        f_host.close()
    else:
        print('Please specify host with --host or --host_file.\n')
        help_and_exit()

    host_len = len(host_list)
    for i in range(0, host_len):
        if host_list[i].find(':') >= 0:
            ip, port = host_list[i].split(':')
            ip = ip.strip()
            port = port.strip()
        else:
            ip = host_list[i].strip()
            port = ''
        func_args.append([ip, port, uid, pwd, cmd, cmd_prefix, cmd_interval, log_dir, timeout, save, l2_sw])

    # Start multi-threading
    w_threading(func_name, func_args, thread)

    # exit
    print('')
    sys.exit()


