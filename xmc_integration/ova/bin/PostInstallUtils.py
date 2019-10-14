#!/usr/bin/env python

import xml.etree.ElementTree as ET
import logging
import uuid
import json
import requests
import pexpect
import re
import getpass
import subprocess
import fileinput
import socket
import os.path

from st2client.client import Client
from st2client.models import KeyValuePair


ST2_CONFIG_FILE = '/etc/st2/st2.conf'
OVF_FILE = '/opt/xmc/ova/ovf-env.xml'
XMC_KEY_NAME = 'xmckey'
ST2_XMC_ADMIN = 'xmcadmin'
MAX_COUNT = 3

class PostInstallUtils:

    """
        Post installation Utils.
    """
    def __init__(self, log_file_name):
        self.logger = self.set_logger(log_file_name)
        self.st2ip = socket.gethostbyname(socket.gethostname())
        self.st2_base_path = self.read_st2_base_path()
        self.st2_info = "{0}/packs/xmc/ST2Integration/config/.st2info.json".format(self.st2_base_path)

    def set_logger(self, log_file_name):
        name = "PostInstall"
        log_format = '%(asctime)s  %(name)8s  %(levelname)5s  %(message)s'
        logging.basicConfig(level=logging.DEBUG, format=log_format, filename=log_file_name,
                            filemode='wa')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter(log_format))
        logging.getLogger(name).addHandler(console)

        return logging.getLogger(name)

    def read_st2_base_path(self):
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

    def get_st2_base_path(self):
        return self.st2_base_path

    def get_logger(self):
        return self.logger

    def is_san_pack_installed(self):
        return self.firewall_install

    def load_config_file(self, log_file=True):
        tree = ET.parse(OVF_FILE)
        root = tree.getroot()

        oe = '{http://schemas.dmtf.org/ovf/environment/1}'
        for node in root.iter(oe+'Property'):
            if node.attrib[oe+'key'] == 'xmc.ip':
                self.xmcip = node.attrib[oe+'value']
                self.print_log("xmcip=" + self.xmcip, log_file)
            if node.attrib[oe+'key'] == 'xmc.fqdn':
                self.xmcfqdn = node.attrib[oe+'value']
                self.print_log("xmcfqdn=" + self.xmcfqdn, log_file)
            if node.attrib[oe+'key'] == 'xmc.user':
                self.xmcuser = node.attrib[oe+'value']
                self.print_log("xmcuser=" + self.xmcuser, log_file)
            if node.attrib[oe+'key'] == 'xmc.password':
                self.xmcpassword = node.attrib[oe+'value']
                self.print_log("xmcpassword=*********", log_file)
            if node.attrib[oe+'key'] == 'my.ip':
                self.st2ip = node.attrib[oe+'value']
                self.print_log("st2ip=" + self.st2ip, log_file)
            if node.attrib[oe+'key'] == 'my.fqdn':
                self.st2fqdn = node.attrib[oe+'value']
                self.print_log("st2fqdn=" + self.st2fqdn, log_file)
            if node.attrib[oe+'key'] == 'DefaultDNS':
                self.dns = node.attrib[oe+'value']
                self.print_log("dns=" + self.dns, log_file)
            if node.attrib[oe+'key'] == 'DefaultGateway':
                self.gatway = node.attrib[oe+'value']
                self.print_log("gatway=" + self.gatway, log_file)
            if node.attrib[oe+'key'] == 'DefaultNetmask':
                self.netmask = node.attrib[oe+'value']
                self.print_log("netmask=" + self.netmask, log_file)
            if node.attrib[oe+'key'] == 'DefaultSearchList':
                self.searchlist = node.attrib[oe+'value']
                self.print_log("searchlist=" + self.searchlist, log_file)
            if node.attrib[oe+'key'] == 'ntp.hosts':
                self.ntphosts = node.attrib[oe+'value']
                self.print_log("ntphosts=" + self.ntphosts, log_file)
            if node.attrib[oe+'key'] == 'timezone':
                self.timezone = node.attrib[oe+'value']
                self.print_log("timezone=" + self.timezone, log_file)
            if node.attrib[oe+'key'] == 'firewall_install':
                self.firewall_install = node.attrib[oe+'value']
                self.print_log("firewall_install=" + self.firewall_install, log_file)
        env = '{http://www.vmware.com/schema/ovfenv}'
        for node in root.iter(env + 'Adapter'):
            if env + 'mac' in node.attrib:
                for key in node.attrib:
                    if key == env + 'mac':
                        self.st2mac = node.attrib[key]
                        self.print_log("st2mac=" + self.st2mac, log_file)

        if self.xmcuser != "XMCUSER_REPLACE_ME" and self.xmcpassword != "XMCPASSWORD_REPLACE_ME":
            self.xmc_configured = True
        else:
            self.xmc_configured = False

        
        self.print_log("Done for loading file " + OVF_FILE, log_file)

    def get_auth_token(self, username="st2admin", password="extreme", log_file=True, timeout=60):
        self.print_log("Generate ST2 Auth token ...", log_file)

        headers = {'Content-Type': 'application/json'}
        response = requests.post("https://" + self.st2ip + '/auth/v1/tokens', headers=headers,
                                 auth=(username, password), data=None, timeout=timeout,
                                 verify=False)

        if response.status_code == requests.codes.created:
            json_str = json.dumps(json.loads(response.text))
            resp = json.loads(json_str)
            return_token = resp['token']
            
            self.print_log("Generated ST2 Auth token: {0}".format(return_token), log_file)
            return return_token

        # raise http exception
        response.raise_for_status()

    def generate_api_key(self, input_token, username="st2admin", password="extreme", log_file=True):
        self.print_log("Generate ST2 API key with token {0} {1} {2}".format(
                input_token, username, password), log_file)
        headers = self.get_rest_headers()
        headers['X-Auth-Token'] = input_token
        metadata = '{"metadata": {"used_by": "xmc"}}'

        response = requests.post('https://' + self.st2ip + '/api/v1/apikeys', headers=headers,
                                 auth=(username, password), data=metadata, timeout=60,
                                 verify=False)

        if response.status_code == requests.codes.created:
            json_str = json.dumps(json.loads(response.text))

            resp = json.loads(json_str)
            self.apikey = resp['key']
            self.print_log("Generated ST2 API key", log_file)

        # raise http exception
        response.raise_for_status()

    def encrypt_password(self, input_token, log_file=True):
        self.print_log("Encrypt xmc password...", log_file)

        st2_client = Client(api_url='https://{0}/api'.format(self.st2ip), token=input_token)
        st2_client.keys.update(KeyValuePair(name=XMC_KEY_NAME, value=self.xmcpassword, secret=True))

    def decrypt_password(self, input_token, log_file=True):
        self.print_log("Decrypt xmc password...", log_file)
        st2_client = Client(api_url='https://{0}/api'.format(self.st2ip), token=input_token)
        password = st2_client.keys.get_by_name(XMC_KEY_NAME, decrypt=True)

        return password.value

    def update_st2schema_file(self, log_file=True):
        st2_xmc_conf = "{0}/packs/xmc/config.schema.yaml".format(self.st2_base_path)

        newlines = []
        with open(st2_xmc_conf, "r") as infile:
            for line in infile.readlines():
                if self.xmc_configured:
                    if 'IP_REPLACE_ME' in line:
                        newlines.append(line.replace('IP_REPLACE_ME', self.xmcip))
                    elif 'FQDN_REPLACE_ME' in line:
                        newlines.append(line.replace('FQDN_REPLACE_ME', self.xmcfqdn))
                    elif 'USER_REPLACE_ME' in line:
                        newlines.append(line.replace('USER_REPLACE_ME', self.xmcuser))
                    elif 'ST2KEY_REPLACE_ME' in line:
                        newlines.append(line.replace('ST2KEY_REPLACE_ME', self.apikey))
                    else:
                        newlines.append(line)
                else:
                    if 'ST2KEY_REPLACE_ME' in line:
                        newlines.append(line.replace('ST2KEY_REPLACE_ME', self.apikey))
                    else:
                        newlines.append(line)

        # open config.schema.yaml for update
        with open(st2_xmc_conf, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)
        if log_file:
            self.print_log("Updated file " + st2_xmc_conf, log_file)
        else:
            print "Updated file " + st2_xmc_conf, log_file

    def create_st2_xmc_admin(self, log_file=True):
        xmc_admin_file = '{0}/rbac/assignments/{1}.yaml'.format(self.st2_base_path, ST2_XMC_ADMIN)

        if not os.path.isfile(xmc_admin_file):
            with open(xmc_admin_file, 'w+') as outfile:
                outfile.write('---\n')
                outfile.write('username: \"{0}\"\n'.format(ST2_XMC_ADMIN))
                outfile.write('roles:\n')
                outfile.write('  - \"admin\"\n')

            cmd = 'sudo st2-apply-rbac-definitions --config-file /etc/st2/st2.conf'
            subprocess.call(cmd, shell=True)

            if log_file:
                self.print_log("Created file " + xmc_admin_file, log_file)
            else:
                print "Created file {0}".format(xmc_admin_file)
        else:
            if log_file:
                self.print_log("Found file " + xmc_admin_file, log_file)
            else:
                print 'Found file {0}'.format(xmc_admin_file)

    def create_st2info_file(self, log_file=True):
        self.create_st2_xmc_admin(log_file)

        with open(self.st2_info, 'w+') as st2file:
            st2file.write("{" + "\n")
            st2file.write(" \"ip\" : " + "\"" + self.st2ip + "\"" + ",\n")
            st2file.write(" \"st2_user\" : " + "\"" + ST2_XMC_ADMIN + "\"" + ",\n")
            st2file.write(" \"ST2-Api-Key\" : " + "\"" + self.apikey + "\"" + "\n")
            st2file.write("}")
        cmd = 'sudo chmod 700 ' + self.st2_info
        subprocess.call(cmd, shell=True)

        if log_file:
            self.print_log("Created file " + self.st2_info, log_file)
        else:
            print "Created file " + self.st2_info

    def scpy_xmcfile(self, log_file=True):
        srcdir = "{0}/packs/xmc/ST2Integration/".format(self.st2_base_path)
        destdir = "/usr/local/Extreme_Networks/NetSight"
        option = " -rp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        try:
            expcmd = "scp" + option + srcdir + " " + self.xmcuser + "@" + self.xmcip + ":" + destdir
            if log_file:
                self.print_log(expcmd, log_file)
            else:
                print expcmd
            var_child = pexpect.spawn(expcmd)

            output = var_child.expect(["password:", pexpect.EOF])
            if output == 0:  # send password
                var_child.sendline(self.xmcpassword)
                var_child.expect(pexpect.EOF)
            elif output == 1:
                print "Got the key or connection timeout"
                pass
        except Exception as e:
            self.logger.error("Something went wrong buddy", log_file)
            self.logger.error(e, log_file)

        cmd = 'sudo \\rm -rf ' + self.st2_info
        subprocess.call(cmd, shell=True)
        if log_file:
            self.print_log(self.st2_info + " is removed", log_file)
            self.print_log("Transferred files from " + srcdir + " to " + destdir, log_file)
        else:
            print self.st2_info + " is removed"
            print "Transferred files from " + srcdir + " to " + destdir

    def get_rest_headers(self):
        headers = {'Content-Type': 'application/json', 'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*',
            'User-Agent': 'python-requests/2.14.2', }

        return headers

    def config_cloudconn(self):
        subprocess.call('sudo cp /opt/xmc/ztp/cconn.service /etc/systemd/system/cconn.service',
                        shell=True)
        subprocess.call('sudo chmod 755 /etc/systemd/system/cconn.service', shell=True)
        subprocess.call('sudo cp /opt/xmc/ztp/userpassword /sbin/userpassword', shell=True)
        subprocess.call('sudo chmod 755 /sbin/userpassword', shell=True)

        for line in fileinput.FileInput("/etc/systemd/system/cconn.service", inplace=1):
            line = line.replace("XMC_IP", self.xmcip)
            print(line)
        subprocess.call('sudo systemctl daemon-reload', shell=True)
        subprocess.call('sudo systemctl enable cconn.service', shell=True)
        subprocess.call('sudo systemctl start cconn.service', shell=True)

    def is_valid_ipv4_address(self, address):
        try:
            host_bytes = address.split('.')
            valid = [int(b) for b in host_bytes]
            valid = [b for b in valid if b >= 0 and b <= 255]
            return len(host_bytes) == 4 and len(valid) == 4
        except:
            return False

    def is_valid_fqdn(self, fqdn):
        if fqdn.endswith('.'):
            fqdn = fqdn[:-1]

        if '.' not in fqdn:
            return False

        if len(fqdn) < 1 or len(fqdn) > 253:
            return False

        ldh_re = re.compile('^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

        result = all(ldh_re.match(x) for x in fqdn.split('.'))

        return result

    def validate_attempt(self, print_log=False):
        count = 0
        msg = 'Maximum retry attempts have been reached and process is canceled.'
        if print_log:
            self.print_log(msg, True)
        else:
            print msg
        exit(0)

    def get_ip(self, message, print_log=False):
        count = 0
        valid = False
        input_ip = ''

        while count < MAX_COUNT:
            input_ip = raw_input(message)
            if self.is_valid_ipv4_address(input_ip):
                valid = True
                break
            count = count + 1

        if not valid:
            self.validate_attempt(print_log)

        return input_ip

    def get_fqdn(self, message, print_log=False):
        count = 0
        valid = False
        input_fqdn = ''

        while count < MAX_COUNT:
            input_fqdn = raw_input(message)
            if self.is_valid_fqdn(input_fqdn):
                valid = True
                break
            count = count + 1

        if not valid:
            self.validate_attempt(print_log)

        return input_fqdn

    def get_password(self, message, password_type, print_log=False):
        count = 0
        valid = False
        password = ''

        while count < MAX_COUNT:
            password = getpass.getpass(message)
            password_confirm = getpass.getpass('Please re-enter the ' + password_type +
                                               ' user password:')
            if password == password_confirm:
                valid = True
                break
            else:
                print 'Password does not match'

            count = count + 1

        if not valid:
            self.validate_attempt(print_log)

        return password

    def get_ovf_file(self):
        return OVF_FILE

    def cleanup(self):
        newlines = []
        with open(OVF_FILE, "r") as infile:
            for line in infile.readlines():
                if 'xmc.password' in line:
                    newlines.append(
                        "         <Property oe:key=\"xmc.password\" oe:value=\"xxxxxxx\"/> \n")
                else:
                    newlines.append(line)

        with open(OVF_FILE, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)

    def get_uuid(self):
        x = uuid.uuid1()
        uuid_value = str(x)
        self.print_log("uuid=" + uuid_value)
        return uuid_value

    def print_log(self, message, log_file=True):
        if log_file:
            self.logger.debug(message)

if __name__ == "__main__":
    utils = PostInstallUtils('/opt/xmc/ova/log/networkPostInstall.log')
