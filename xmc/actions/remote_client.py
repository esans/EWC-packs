#!/usr/bin/env python


import subprocess
import sys


def main():
    retval = 1

    remote_client_script = "/opt/stackstorm/packs/xmc/actions/remote_client.exp"

    cmds = sys.argv[1]
    devciceip = sys.argv[2]
    user = sys.argv[3]
    password = sys.argv[4]
    device_family = sys.argv[5]
    need_log = "False"

    if "show config" in cmds:
        need_log = "True"

    expcmd = 'expect ' + remote_client_script + \
        ' ' + "\"" + cmds + "\"" + \
        ' ' + devciceip + \
        ' ' + user + \
        ' ' + password + \
        ' ' + "\"" + device_family + "\"" + \
        ' ' + need_log

    print expcmd
    retval = subprocess.call(expcmd, shell="True")

    print retval
    return retval


if __name__ == "__main__":
    main()
