#!/usr/bin/env python

import os
import getpass
import subprocess
import collections
import yaml
import copy
import socket

from st2client.client import Client
from st2client.models import KeyValuePair
from PostInstallUtils import PostInstallUtils

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MAX_COUNT = 3
SUPPORTED_FIREWALL_TYPES = {0: "fortinet", 1: "paloalto", 2: "checkpoint"}
EWC_TYPE = "Extreme Workflow Composer"

class SanConfig(PostInstallUtils):
    """
        Firewall configuration.
    """

    def __init__(self, get_credential, print_log=False):
        self.username = "st2admin"
        self.password = "extreme"

        self.utils = PostInstallUtils('/opt/xmc/ova/log/sanPostConfig.log')
        self.logger = self.utils.get_logger()
        self.print_log = print_log
        if not self.print_log:
            self.utils.load_config_file(self.print_log)

        self.st2_base_path = self.utils.get_st2_base_path()

        if get_credential:
            self.get_user_credential()

        self.firewall_config_file = '{0}/configs/san.yaml'.format(self.st2_base_path)

        self.token = self.utils.get_auth_token(self.username, self.password, self.print_log)
        ip = socket.gethostbyname(socket.gethostname())
        self.st2_client = Client(api_url='https://{0}/api'.format(ip), token=self.token)

    def get_user_credential(self):
        self.username = raw_input("Please enter {0} admin user name: (st2admin) ".format(EWC_TYPE))
        if self.username == '':
            self.username = 'st2admin'
        self.password = getpass.getpass("Please enter {0} admin user password: ".format(EWC_TYPE))

    def encrypt_passwords(self, firewall_list):
        for firewall_key, firewall_value in firewall_list.iteritems():
            for key, value in firewall_value.iteritems():

                if key == 'password':
                    if self.print_log:
                        self.logger.debug('Encrypt password for firewall {0}'.format(firewall_key))
                    self.st2_client.keys.update(KeyValuePair(name=firewall_key, value=value,
                                                             secret=True))

    def delete_encrypt_passwords(self, firewall_list_deleted):
        for firewall_name in firewall_list_deleted:
            self.delete_encrypt_password(firewall_name)

    def delete_encrypt_password(self, key_name):
        encrypted_password = self.st2_client.keys.get_by_name(key_name)
        self.st2_client.keys.delete(encrypted_password)

    def is_valid_ipv4_address(self, address):
        return self.utils.is_valid_ipv4_address(address)

    def validate_attempt(self):
        message = 'Maximum re-try attempt has been reached. Exiting from script. '
        print message
        exit(1)

    def get_ip(self, message):
        return self.utils.get_ip(message, self.print_log)

    def get_password(self, message):
        return self.utils.get_password(message, "Firewall", self.print_log)

    def firewall_type_validate(self, message):
        count = 0
        return_type = None

        while count < MAX_COUNT:
            print message
            answer = raw_input("Your choice is (0): ")
            if answer == '':
                return_type = SUPPORTED_FIREWALL_TYPES.values()[0]
                print ("Setting firewall type to default {0}".format(return_type))
                break
            elif answer.isdigit() and 0 <= int(answer) <= 2:
                return_type = SUPPORTED_FIREWALL_TYPES.values()[int(answer)]
                break
            else:
                print 'Invalid Option'

            count = count + 1

        if return_type is None:
            self.validate_attempt()

        return return_type

    def firewall_manager_config_validate(self, message, firewalls=None):
        if firewalls is None:
            firewalls = {}

        count = 0
        return_value = False

        print message
        self.print_firewall(firewalls)

        while count < MAX_COUNT:
            answer = raw_input("Your choice is (y/n): ")
            if answer == "Y" or answer == 'y':
                return_value = True
                break
            elif answer == "N" or answer == 'n':
                break
            else:
                print 'Invalid Option'

            count = count + 1

        return return_value

    def print_firewall(self, firewall_list):
        if bool(firewall_list):
            firewalls = copy.deepcopy(firewall_list)

            for firewall_key, firewall_value in firewalls.iteritems():
                temp_value = firewall_value
                temp_value['password'] = 'xxxxxx'
                print 'Name: {0} -> {1}'.format(firewall_key, temp_value)

    def load_san_config_file(self):
        data_loaded = None

        with open(self.firewall_config_file, 'r') as stream:
            data_loaded = yaml.load(stream)

        return data_loaded

    def firewall_manager_config(self):
        not_done = True
        firewall_list = {}

        while not_done:
            message = '\nPlease enter firewall type: \n' \
                      '0: FortiManager \n' \
                      '1: Palo Alto \n' \
                      '2: Checkpoint \n'
            firewall_type = self.firewall_type_validate(message)
            firewall_ip = self.get_ip('Please enter the IP Address: ')
            firewall_username = raw_input('Please enter the user name: ')
            firewall_password = self.get_password('Please enter the password: ')

            firewall_info = {'type': firewall_type, 'ip': firewall_ip,
                             'username': firewall_username, 'password': firewall_password}
            firewall_list['firewall_{0}'.format(firewall_ip)] = firewall_info

            not_done = self.firewall_manager_config_validate(
                '\nDo you want to configure more firewall services for SAN pack?: ')

        if bool(firewall_list):
            message = "\nFollowing Firewall services configuration will be saved to {0}\n".format(
                self.firewall_config_file)
            message = message + 'And Extreme Policy Package will be installed to firewall services'

            ret = self.firewall_manager_config_validate(message, firewall_list)

            if ret:
                return firewall_list
            else:
                return None

        return firewall_list

    def update_firewall_config_file(self, firewall_dir):
        sorted_firewall_dir = collections.OrderedDict(sorted(firewall_dir.items()))
        if self.print_log:
            self.logger.debug('Update {0} file'.format(self.firewall_config_file))

        with open(self.firewall_config_file, "w+") as outfile:
            outfile.write('---\n')
            outfile.write('firewalls:\n')

            for firewall_key, firewall_value in sorted_firewall_dir.iteritems():
                outfile.write(' ' + firewall_key + ':\n')
                for key, value in firewall_value.iteritems():
                    if key == "password":
                        outfile.write('   {0}: \"{{ st2kv.system.os_{1} }}\"\n'.format(
                            key, firewall_key))
                    else:
                        outfile.write('   {0}: {1}\n'.format(key, value))

    def check_existing_configuration(self, message):
        firewall_list = {}
        san_file = os.path.exists(self.firewall_config_file)

        if san_file:
            firewall_list_dict = self.load_san_config_file()
            if bool(firewall_list_dict) and firewall_list_dict['firewalls'] is not None:
                print message
                firewall_list = firewall_list_dict['firewalls']
                self.print_firewall(firewall_list)
            else:
                print "No firewall services are configured"
        else:
            print "{0} does not exist.".format(self.firewall_config_file)

        return firewall_list

    def is_firewall_exist(self, firewall_name, firewall_list):
        return_value = False
        if bool(firewall_list):
            for firewall in firewall_list:
                if firewall == firewall_name:
                    return_value = True
                    break

        return return_value

    def get_new_firewall_list(self, firewall_list):
        not_done = True

        while not_done:
            message = '\nPlease enter firewall name that is going to be deleted: '
            firewall_username = raw_input(message)
            if "firewall_" in firewall_username:
                if self.is_firewall_exist(firewall_username, firewall_list):
                    remove_flag = self.firewall_manager_config_validate(
                        '\nDo you want to remove firewall {0}?'.format(firewall_username))
                    if remove_flag:
                        print 'firewall {0} is removed'.format(firewall_username)
                        self.delete_encrypt_password(firewall_username)
                        if len(firewall_list) == 1:
                            firewall_list = {}
                            break;

                        else:
                            firewall_list.pop(firewall_username)
                else:
                    print 'Could not find match for {0}'.format(firewall_username)
            else:
                print 'Invalid firewall name is given {0}'.format(firewall_username)

            if bool(firewall_list):
                not_done = self.firewall_manager_config_validate(
                    '\nDo you want to configure more firewall services? ')

        return firewall_list

    def install_san_pack(self):
        subprocess.call("sudo cp -R /opt/xmc/packs/san {0}/packs/".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo chown -R root:st2packs {0}/packs/san".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo chmod 755 {0}/packs/san/actions/*".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo st2 run packs.setup_virtualenv packs=san", shell=True)

        print ("Installed san pack")

    def update_ovf_file(self):
        ovf_file = '/opt/xmc/ova/ovf-env.xml'
        newlines = []
        with open(ovf_file, "r") as infile:
            for line in infile.readlines():
                if 'FIREWALL_INSTALL_REPLACE_ME' in line:
                    newlines.append(line.replace('FIREWALL_INSTALL_REPLACE_ME', 'True'))
                else:
                    newlines.append(line)

        with open(ovf_file, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)

        print ("Updated file " + ovf_file)


    def post_install(self):
        firewall_list = self.firewall_manager_config()
        if bool(firewall_list):
            self.encrypt_passwords(firewall_list)
            self.update_firewall_config_file(firewall_list)
            self.install_package()

    def install_package(self):
        install_package_script_file = '{0}/packs/san/install_extreme_policy_package.py'.format(
            self.st2_base_path)
        subprocess.call('sudo chmod 755 {0}'.format(install_package_script_file), shell=True)
        subprocess.call('sudo python {0} {1}'.format(install_package_script_file, self.token),
                        shell=True)

    def reconfig_firewalls(self):
        if self.utils.is_san_pack_installed() != 'True':
            self.install_san_pack()
            self.update_ovf_file()

        message = 'Following information from {0} file will be removed'.format(
            self.firewall_config_file)
        firewall_list_old = self.check_existing_configuration(message)

        message = 'Do you want to continue? '
        answer = self.firewall_manager_config_validate(message)
        if answer:
            firewall_list_new = self.firewall_manager_config()
            if bool(firewall_list_new):
                if bool(firewall_list_old):
                    self.delete_encrypt_passwords(firewall_list_old)
                self.encrypt_passwords(firewall_list_new)
                self.update_firewall_config_file(firewall_list_new)
                self.install_package()
                subprocess.call("sudo st2ctl reload --register-configs", shell=True)

    def add_firewalls(self):
        message = 'New firewall services will be added to the following existing firewall ' \
                  'services from {0} file '.format(self.firewall_config_file)
        firewall_list_old = self.check_existing_configuration(message)
        message = 'Do you want to continue? '
        answer = self.firewall_manager_config_validate(message)
        if answer:
            firewall_list_new = self.firewall_manager_config()
            if bool(firewall_list_new):
                self.encrypt_passwords(firewall_list_new)

                for firewall_key, firewall_value in firewall_list_new.iteritems():
                    firewalls = copy.deepcopy(firewall_list_old)
                    for old_key, old_value in firewalls.iteritems():
                        if firewall_key == old_key:
                            print 'Removing existing duplicate service with ip {0}'.format(
                                old_value['ip'])
                            del firewall_list_old[old_key]

                merged_firewall_list = firewall_list_old.copy()
                merged_firewall_list.update(firewall_list_new)
                self.update_firewall_config_file(merged_firewall_list)
                self.install_package()
                subprocess.call("sudo st2ctl reload --register-configs", shell=True)

    def delete_firewalls(self):
        message = 'You are going to remove firewall configuration from following existing ' \
                  'firewalls from {0} file '.format(self.firewall_config_file)
        firewall_list_old = self.check_existing_configuration(message)
        if bool(firewall_list_old):
            message = 'Do you want to continue? '
            answer = self.firewall_manager_config_validate(message)
            if answer:
                firewall_list_new = self.get_new_firewall_list(copy.deepcopy(firewall_list_old))
                if len(firewall_list_new) != len(firewall_list_old):
                    self.update_firewall_config_file(firewall_list_new)
                    subprocess.call("sudo st2ctl reload --register-configs", shell=True)

if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-p", "--post_install", help="Post installation for configuring firewall "
                                                   "services", action="store_true")
    parser.add_option("-i", "--install_package", help="Post installation for Extreme Package on "
                                                      "firewall services", action="store_true")
    parser.add_option('-c', "--configure", help='Re-configure Firewall services',
                      action="store_true")
    parser.add_option("-a", '--add', help="Add Firewall services", action="store_true")
    parser.add_option("-d", "--delete", help="Delete Firewall services", action="store_true")

    (options, args) = parser.parse_args()

    firewall_list = {}

    if options.post_install:
        if len(args) == 0:
            san_config = SanConfig(False, True)
            san_config.post_install()
        else:
            print "Wrong number of arguments: san_config -p "
    elif options.install_package:
        if len(args) == 0:
            san_config = SanConfig(True)
            san_config.install_package()
        else:
            print "Wrong number of arguments: python san_config -i "
    elif options.configure:
        if len(args) == 0:
            san_config = SanConfig(True)
            san_config.reconfig_firewalls()
        else:
            print "Wrong number of arguments: python san_config -c "
    elif options.add:
        if len(args) == 0:
            san_config = SanConfig(True)
            san_config.add_firewalls()
        else:
            print "Wrong number of arguments: python san_config -a"
    elif options.delete:
        if len(args) == 0:
            san_config = SanConfig(True)
            san_config.delete_firewalls()
        else:
            print "Wrong number of arguments: python san_config -d"
    else:
        print "Wrong number of arguments: python san_config -<c/a/d> st2admin_password "
        print "[python san_config -c ] Re-configure firewall services, " \
              "existing firewall configuration will be removed"
        print "[python san_config -a ] Add new firewall services"
        print "[python san_config -d ] Remove individual existing firewall services"
