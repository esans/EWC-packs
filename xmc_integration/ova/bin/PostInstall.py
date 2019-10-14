#!/usr/bin/env python

import os
import os.path
import subprocess
import xml.etree.ElementTree as ET
from distutils.version import LooseVersion

from PostInstallUtils import PostInstallUtils

CURRENT_VERSION = "8.2.0"
XMC_TYPE = "Extreme Management Center"
MAX_COUNT = 3

class PostInstall(PostInstallUtils):
    """
        Post installation for getting user input.
    """

    def __init__(self):
        self.inputs = {}
        self.ztpRegistration = True
        self.st2vm_version = self.get_st2vm_version()
        self.utils = PostInstallUtils(None)

    def get_st2vm_version(self):
        tree = ET.parse('/opt/xmc/ova/ovf-env-template.xml')
        root = tree.getroot()
        st2_version = ""

        oe = '{http://schemas.dmtf.org/ovf/environment/1}'
        for node in root.iter(oe+'Property'):
            if node.attrib[oe+'key'] == 'st2Version':
                st2_version = node.attrib[oe+'value']
                break;

        return st2_version

    def is_valid_ipv4_address(self, address):
        return self.utils.is_valid_ipv4_address(address)

    def is_valid_fqdn(self, fqdn):
        return self.utils.is_valid_fqdn(fqdn)

    def validate_attempt(self):
        self.utils.validate_attempt()

    def is_valid_timezone(self, timezone):
        timezone_file = '/usr/share/zoneinfo/' + timezone
        if os.path.exists(timezone_file):
            return True
        else:
            return False

    def get_ip(self, message):
        return self.utils.get_ip(message)

    def get_list_ips(self, message):
        input_ips = ''
        count = 0
        valid = False

        while count < MAX_COUNT:
            bad_ip = False
            input_ips = raw_input(message)
            input_list_ip = input_ips.split(',')
            for ip in input_list_ip:
                if self.is_valid_ipv4_address(ip):
                    pass
                else:
                    bad_ip = True
                    break

            if bad_ip:
                count = count + 1
                continue
            else:
                valid = True
                break

        if not valid:
            self.validate_attempt()

        return input_ips

    def get_fqdn(self, message):
        return self.utils.get_fqdn(message)

    def get_list_domain(self, message):
        input_domains = ''
        count = 0
        valid = False

        while count < MAX_COUNT:
            bad_domain = False
            input_domains = raw_input(message)
            if input_domains == '':
                return input_domains

            input_list_domains = input_domains.split(',')
            for domain in input_list_domains:
                if self.is_valid_fqdn(domain):
                    pass
                else:
                    bad_domain = True
                    break

            if bad_domain:
                count = count + 1
                continue
            else:
                valid = True
                break

        if not valid:
            self.validate_attempt()

        input_domains = input_domains.replace(',', ' ')

        return input_domains

    def get_password(self, message, password_type):
        return self.utils.get_password(message, password_type)

    def get_timezone(self, message):
        count = 0
        valid = False
        time_zone = 'America/Los_Angeles'
        valid_time_zone = {0:"America/Los_Angeles",
                        1:"America/Sao_Paulo",
                        2:"America/Manaus",
                        3:"America/Lima",
                        4:"America/Mexico_City",
                        5:"America/New_York",
                        6:"America/Chicago",
                        7:"America/Denver",
                        8:"America/Santiago",
                        9:"America/Los_Angeles",
                        10:"America/Juneau",
                        11:"Africa/Dakar",
                        12:"America/Danmarkshavn",
                        13:"Europe/London",
                        14:"Africa/Lagos",
                        15:"Europe/Paris",
                        16:"Europe/Berlin",
                        17:"Africa/Cairo",
                        18:"Africa/Johannesburg",
                        19:"Europe/Athens",
                        20:"Europe/Bucharest",
                        21:"Europe/Finland",
                        22:"Europe/Kiev",
                        23:"Africa/Dar_es_Salaam",
                        24:"Asia/Qatar",
                        25:"Europe/Moscow",
                        26:"Asia/Tehran",
                        27:"Asia/Dubai",
                        28:"Europe/Samara",
                        29:"Indian/Mauritius",
                        30:"Asia/Karachi",
                        31:"Asia/Yekaterinburg",
                        32:"Asia/Colombo",
                        33:"Asia/Kolkata",
                        34:"Asia/Kathmandu",
                        35:"Asia/Omsk",
                        36:"Asia/Dhaka",
                        37:"Asia/Jakarta",
                        38:"Asia/Hong_Kong",
                        39:"Asia/Irkutsk",
                        40:"Asia/Shanghai",
                        41:"Asia/Singapore",
                        42:"Australia/Perth",
                        43:"Asia/Yakutsk",
                        44:"Asia/Tokyo",
                        45:"Australia/Adelaide",
                        46:"Asia/Magadan",
                        47:"Australia/Sydney",
                        48:"Asia/Kamchatka"}

        while count < MAX_COUNT:
            os.system("cat /opt/xmc/ova/timezone.csv")
            input_timezone = raw_input(message)

            if input_timezone == '':
                print ("Setting timezone to default")
                valid = True
                break;
            elif input_timezone.isdigit() and int(input_timezone) >= 1 and int(
                    input_timezone) <= 48:
                time_zone = valid_time_zone.values()[int(input_timezone)]
                print ("Setting timezone to {0}".format(time_zone))
                valid = True
                break
            else:
                print "Entered timezone is out of range"

            count = count + 1

        if not valid:
            self.validate_attempt()

        return time_zone

    def vm_network_config(self):
        vm_ip = self.get_ip('Please enter the IP Address to assign to the VM: ')
        self.inputs["vm_ip"] = vm_ip
        vm_netmask = self.get_ip('Please enter the Netmask to assign to the VM: ')
        self.inputs["vm_netmask"] = vm_netmask
        vm_gateway = self.get_ip('Please enter the Gateway to assign to the VM: ')
        self.inputs["vm_gateway"] = vm_gateway
        vm_fqdn = self.get_fqdn('Please enter the FQDN to assign to the VM: ')
        self.inputs["vm_fqdn"] = vm_fqdn
        vm_dns = self.get_list_ips('Please enter the IP Address of your DNS server (Multiple IPs ' +
                                   'separated by comma): ')
        self.inputs["vm_dns"] = vm_dns
        vm_search_list = self.get_list_domain(
            'Please enter the default searching list (Multiple domains separated by comma) ' +
            '(Optional): ')
        self.inputs["vm_search_list"] = vm_search_list

    def ztp_registration_validate(self):
        not_done = True
        count = 0

        print "Do you want to register  Extreme Workflow Composer server to " + XMC_TYPE \
              + " through Cloud Connector? "
        while not_done:
            answer = raw_input("Your choice is (y/n): ")
            if answer == "Y" or answer == 'y':
                self.ztpRegistration = True
                break
            elif answer == "N" or answer == 'n':
                self.ztpRegistration = False
                break
            else:
                print 'Invalid Option'

            count = count + 1

    def xmc_info_config(self):
        if LooseVersion(self.st2vm_version) >= LooseVersion(CURRENT_VERSION):
            self.ztp_registration_validate()

        if self.ztpRegistration:
            xmc_ip = self.get_ip('Please enter the ' + XMC_TYPE + ' IP Address: ')
            self.inputs["xmc_ip"] = xmc_ip
            xmc_fqdn = self.get_fqdn('Please enter the ' + XMC_TYPE + ' FQDN: ')
            self.inputs["xmc_fqdn"] = xmc_fqdn
            xmc_user = raw_input('Please enter the ' + XMC_TYPE + ' user name: ')
            self.inputs["xmc_user"] = xmc_user
            xmc_password = self.get_password('Please enter the ' + XMC_TYPE + ' user password: ',
                                             XMC_TYPE)
            self.inputs["xmc_password"] = xmc_password

    def firewall_manager_config_validate(self, message):
        count = 0
        return_value = False

        print message
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

    def firewall_manager_config(self):
        if LooseVersion(self.st2vm_version) >= LooseVersion(CURRENT_VERSION):
            message = 'Do you want to install SAN (Security Assisted Network) pack for Extreme ' \
                      'Workflow Composer. \nIf you choose NO at this point, you can install it' \
                      ' later. Please refer to documentation for detail.'
            answer = self.firewall_manager_config_validate(message)

            if answer:
                self.inputs['firewall_install'] = "True"
                message = 'Do you want to configure Firewall servers? '
                answer = self.firewall_manager_config_validate(message)

                if answer:
                    san_config_file = '/opt/xmc/ova/bin/san_config.py'

                    subprocess.call('sudo chmod 755 {0}'.format(san_config_file), shell=True)
                    subprocess.call('sudo python {0} -p'.format(san_config_file), shell=True)
            else:
                self.inputs['firewall_install'] = "False"

    def time_zone_config(self):
        time_zone = self.get_timezone('Please enter the Time Zone (Default: America/Los_Angeles): ')
        self.inputs["time_zone"] = time_zone

    def show_network_config_menu(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print "================================================================================"
        print "Confirm Network Settings"
        print "================================================================================"
        print "These are the settings you have entered. Enter 0 or any key other than (1,2,3) a"
        print "valid selection to continue. If you need to make a change, enter the appropriate"
        print "number now or run the /opt/xmc/ova/bin/PostInstall.py script at a later time."
        print "================================================================================"
        print "\n"
        print "0. Accept settings and continue"
        print "1. Management Interface Configuration:"
        print "       Address:        " + self.inputs['vm_ip']
        print "       Netmask:        " + self.inputs['vm_netmask']
        print "       Gateway:        " + self.inputs['vm_gateway']
        print "       FQDN:           " + self.inputs['vm_fqdn']
        print "       Nameserver:     " + self.inputs['vm_dns']
        print "       Searching List: " + self.inputs['vm_search_list']
        print "2. TimeZone:           " + self.inputs['time_zone']
        print "3. Extreme Management Center Information:                    "
        if self.ztpRegistration:
            print "       Address:        " + self.inputs['xmc_ip']
            print "       FQDN:           " + self.inputs['xmc_fqdn']
            print "       User:           " + self.inputs['xmc_user']
            print "       Password:       " + "xxxxxx"
        else:
            print "    Extreme Workflow Composer server Cloud Connector registration is " \
                  "not configured."

    def show_setup(self):
        os.system('cls' if os.name == 'nt' else 'clear')

        print "================================================================================"
        print "Extreme Networks, Inc. - Extreme Workflow Composer"
        print "Welcome to the Extreme Workflow Composer Setup"
        print "================================================================================"
        print "Please enter the information as it is requested to continue with the "
        print "configuration. Typically a default value is displayed in brackets."
        print "The [enter] key may be pressed without entering data for (Optional) "
        print "items and a value must be entered for others. It provides three tries"
        print "for every items. At the end of the setup process, the existing settings "
        print "will be displayed and opportunity will be provided to correct any errors."
        print "================================================================================"

    def process_validate(self, stage):
        flag = False

        if stage == 'End':
            print "The configuration will be saved to /opt/xmc/ova/ovf-env.xml file and start " \
                  "post installation process"

        count = 0
        while count < MAX_COUNT:
            answer = raw_input('Do you want continue with this process ? [y/n] ')
            if answer == "Y" or answer == 'y':
                flag = True
                break
            elif answer == "N" or answer == 'n':
                flag = False
                if stage == 'End':
                    print 'Your configuration is not saved and will be lost'
                elif stage == 'Start':
                    print 'Exit'
                break
            else:
                if count == 2:
                    if stage == 'End':
                        print 'Your configuration is not saved and will be lost'
                    elif stage == 'Start':
                        print 'Exit'
                    break
                else:
                    print 'Invalid Option'
                flag = False

            count = count + 1

        return flag

    def post_install_setup(self):
        self.vm_network_config()
        self.time_zone_config()
        self.xmc_info_config()
        self.firewall_manager_config()

    def post_install_validate(self):
        not_done = True

        while not_done:
            self.show_network_config_menu()
            answer = raw_input("Your choice is : ")
            if answer == '1':
                self.vm_network_config()
            elif answer == '2':
                self.time_zone_config()
            elif answer == '3':
                self.xmc_info_config()
            else:
                not_done = False

    def save_to_file(self):
        ovf_file_template = '/opt/xmc/ova/ovf-env-template.xml'
        newlines = []
        with open(ovf_file_template, "r") as infile:
            for line in infile.readlines():
                if 'MYIP_REPLACE_ME' in line:
                    newlines.append(line.replace('MYIP_REPLACE_ME', self.inputs['vm_ip']))
                elif 'NETMASK_REPLACE_ME' in line:
                    newlines.append(line.replace('NETMASK_REPLACE_ME', self.inputs['vm_netmask']))
                elif 'GATEWAY_REPLACE_ME' in line:
                    newlines.append(line.replace('GATEWAY_REPLACE_ME', self.inputs['vm_gateway']))
                elif 'MYFQDN_REPLACE_ME' in line:
                    newlines.append(line.replace('MYFQDN_REPLACE_ME', self.inputs['vm_fqdn']))
                elif 'DNS_REPLACE_ME' in line:
                    newlines.append(line.replace('DNS_REPLACE_ME', self.inputs['vm_dns']))
                elif 'SEARCHLIST_REPLACE_ME' in line:
                    newlines.append(line.replace('SEARCHLIST_REPLACE_ME',
                                                 self.inputs['vm_search_list']))
                elif 'TIMEZONE_REPLACE_ME' in line:
                    newlines.append(line.replace('TIMEZONE_REPLACE_ME', self.inputs['time_zone']))
                elif 'XMCIP_REPLACE_ME' in line:
                    if self.ztpRegistration:
                        newlines.append(line.replace('XMCIP_REPLACE_ME', self.inputs['xmc_ip']))
                    else:
                        newlines.append(line)
                elif 'XMCFQDN_REPLACE_ME' in line:
                    if self.ztpRegistration:
                        newlines.append(line.replace('XMCFQDN_REPLACE_ME', self.inputs['xmc_fqdn']))
                    else:
                        newlines.append(line)
                elif 'XMCUSER_REPLACE_ME' in line:
                    if self.ztpRegistration:
                        newlines.append(line.replace('XMCUSER_REPLACE_ME', self.inputs['xmc_user']))
                    else:
                        newlines.append(line)
                elif 'XMCPASSWORD_REPLACE_ME' in line:
                    if self.ztpRegistration:
                        newlines.append(line.replace('XMCPASSWORD_REPLACE_ME',
                                                     self.inputs['xmc_password']))
                    else:
                        newlines.append(line)
                elif 'FIREWALL_INSTALL_REPLACE_ME' in line:
                    if self.inputs['firewall_install'] == 'True':
                        newlines.append(line.replace('FIREWALL_INSTALL_REPLACE_ME',
                                                     self.inputs['firewall_install']))
                    else:
                        newlines.append(line)
                else:
                    newlines.append(line)

        ovf_file = '/opt/xmc/ova/ovf-env.xml'
        with open(ovf_file, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)

        print ("Created file " + ovf_file)

    def start_post_installation_process(self):
        config_flag_file = "/opt/xmc/ova/CONFIG"
        if os.path.exists(config_flag_file):
            os.remove(config_flag_file)
        print 'Removed ' + config_flag_file
        print 'Started Post Installation ...'
        subprocess.call('sudo /opt/xmc/ova/ova_postinstall', shell=True)

if __name__ == "__main__":
    install = PostInstall()
    install.show_setup()
    if install.process_validate("Start"):
        install.post_install_setup()
        install.post_install_validate()
        if install.process_validate("End"):
            install.save_to_file()
            install.start_post_installation_process()
