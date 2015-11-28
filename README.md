# w-sw-ssh
This is a simple tool to execute multiple commands on network device, such as router and switch, and it supports Cisco Catalyst, Cisco Nexus, Huawei and H3C.


Author
==============
Wang Dayong (Email: wandering_997@sina.com, http://weibo.com/wandering997)


Depends
==============
pexpect (https://pypi.python.org/pypi/pexpect/)


Help
==============

[root@TEST w-sw-ssh]# w-sw-ssh.py

Usage:  w-sw-ssh.py <options>

    --uid <uid>                 SSH username

    --pwd <pwd>                 SSH password

    -p                          Get password from user input

    --host <ip[:port],...>      ip[:port] list of remote ssh server, default port is 22

    --host_file <file_name>     Filename of ip[:port] list

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
                                /var/log/test/$(date "+%Y")/$(date "+%Y%m%d")/

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


[root@TEST w-sw-ssh]# 


