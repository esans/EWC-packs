#!/usr/bin/env python

import json
import yaml
import os
import sys

from st2client.client import Client
from actions.python_actions.lib.fortinet_policy import FortinetApi

ST2_CONFIG_FILE = '/etc/st2/st2.conf'
SUPPORTED_FIREWALL_TYPES = {0: "fortinet", 1: "paloalto", 2: "checkpoint"}


class InstallExtremeFirewallPackage:
    """
        Install Extreme Management Center Policy PAckage
    """

    def __init__(self):
        st2_base_path = self.get_st2_base_path()
        self.firewall_config_file = '{0}/configs/san.yaml'.format(st2_base_path)

    def get_st2_base_path(self):
        base_path = '/opt/stackstorm'

        newlines = []
        with open(ST2_CONFIG_FILE, "r") as infile:
            for line in infile.readlines():
                if 'base_path' in line:
                    base_paths = line.split(' ')
                    base_path = base_paths[len(base_paths) - 1]
                    break;

        base_path = base_path.split('\n')[0]
        return base_path

    def install_firewall_package(self, token):
        firewall_info = self.load_config_file()
        if firewall_info is not None:
            self.install_firewall(firewall_info, token)

    def install_firewall(self, firewall_dirs, token):
        client = Client(base_url='http://127.0.0.1', token=token)

        for firewall in firewall_dirs['firewalls']:
            if firewall_dirs['firewalls'][firewall]['type'] == SUPPORTED_FIREWALL_TYPES.values()[0]:
                ip = firewall_dirs['firewalls'][firewall]['ip']
                username = firewall_dirs['firewalls'][firewall]['username']
                key_pair = client.keys.get_by_name(name=firewall, decrypt=True)
                password = key_pair.value
                fortinet_api = FortinetApi(ip, username, password)
                status = fortinet_api.install_policy_package_on_all()
                if status is not None:
                    result = json.loads(status)
                    result_data = result['result'][0]
                    if result_data['status']['code'] == 0:
                        print 'Successfully installed Extreme Policy Package for {0}'.format(ip)
                    else:
                        print 'Failed to install Extreme Policy Package for {0}'.format(ip)

    def load_config_file(self):
        data_loaded = None

        with open(self.firewall_config_file, 'r') as stream:
            data_loaded = yaml.load(stream)

        return data_loaded

    def check_file(self):
        file_exist = False

        san_file = os.path.exists(self.firewall_config_file)
        if san_file:
            file_exist = True

        return file_exist


if __name__ == "__main__":
    if len(sys.argv) == 2:
        token = sys.argv[1]
        install_package = InstallExtremeFirewallPackage()
        if install_package.check_file():
            install_package.install_firewall_package(token)
        else:
            print '{0} does not exist'.format(install_package.firewall_config_file)
    else:
        print 'Wrong number of input.'
        print 'Usase: python install_extreme_policy_package.py [token]'
