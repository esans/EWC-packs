#!/usr/bin/env python

import getpass
from PostInstallUtils import PostInstallUtils


XMC_TYPE = "Extreme Management Center"
EWC_TYPE = "Extreme Workflow Composer"
MAX_COUNT = 3

class XmcConfig(PostInstallUtils):
    """
        xmc configuration for XMC information.
    """

    def __init__(self):
        PostInstallUtils.__init__(self, None)
        PostInstallUtils.load_config_file(self, False)
        self.username = "st2admin"
        self.password = "extreme"

        self.st2_base_path = PostInstallUtils.get_st2_base_path(self)

    def get_auth_token(self):
        return PostInstallUtils.get_auth_token(self, self.username, self.password, False)

    def generate_api_key(self, token):
        PostInstallUtils.generate_api_key(self, token, self.username, self.password, False)

    def update_st2schema_file(self):
        if self.xmc_configured:
            PostInstallUtils.update_st2schema_file(self, False)
        else:
            self.update_st2schema_file(self)

    def scpy_xmcfile(self):
        if self.xmc_configured:
            self.xmcip = self.new_xmcip
            self.xmcfqdn = self.new_xmcfqdn
            self.xmcuser = self.new_xmcuser

        PostInstallUtils.scpy_xmcfile(self, False)

    def update_st2schema_file(self):
        st2_xmc_conf = "{0}/packs/xmc/config.schema.yaml".format(self.st2_base_path)
        is_api_key = False

        newlines = []
        with open(st2_xmc_conf, "r") as infile:
            for line in infile.readlines():
                if 'IP_REPLACE_ME' in line or self.xmcip in line:
                    if 'IP_REPLACE_ME' in line:
                        newlines.append(line.replace('IP_REPLACE_ME', self.xmcip))
                    else:
                        newlines.append(line.replace(self.xmcip, self.new_xmcip))
                elif 'FQDN_REPLACE_ME' in line or self.xmcfqdn in line:
                    if 'FQDN_REPLACE_ME' in line:
                        newlines.append(line.replace('FQDN_REPLACE_ME', self.xmcfqdn))
                    else:
                        newlines.append(line.replace(self.xmcfqdn, self.new_xmcfqdn))
                elif 'USER_REPLACE_ME' in line or self.xmcuser in line:
                    if 'USER_REPLACE_ME' in line:
                        newlines.append(line.replace('USER_REPLACE_ME', self.xmcuser))
                    else:
                        newlines.append(line.replace(self.xmcuser, self.new_xmcuser))
                elif 'st2_api_key:' in line:
                        newlines.append(line)
                        is_api_key = True;
                elif 'default:' in line and is_api_key:
                    if 'ST2KEY_REPLACE_ME' in line:
                        newlines.append(line.replace('ST2KEY_REPLACE_ME', self.apikey))
                    else:
                        newlines.append('    default: {0}'.format(self.apikey))
                    is_api_key = False
                else:
                     newlines.append(line)

        with open(st2_xmc_conf, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)

        print ("Updated file " + st2_xmc_conf)
    

    def update_ovf_file(self):        
        ovf_file = '/opt/xmc/ova/ovf-env.xml'
        newlines = []

        with open(ovf_file, "r") as infile:
            for line in infile.readlines():
                if self.xmc_configured:
                    if self.xmcip in line:
                        newlines.append(line.replace(self.xmcip, self.new_xmcip))
                    elif self.xmcfqdn in line:
                        newlines.append(line.replace(self.xmcfqdn, self.new_xmcfqdn))
                    elif self.xmcuser in line:
                        newlines.append(line.replace(self.xmcuser, self.new_xmcuser))
                    else:
                        newlines.append(line)
                else:
                    if 'XMCIP_REPLACE_ME' in line:
                        newlines.append(line.replace('XMCIP_REPLACE_ME', self.xmcip))
                    elif 'XMCFQDN_REPLACE_ME' in line:
                        newlines.append(line.replace('XMCFQDN_REPLACE_ME', self.xmcfqdn))
                    elif 'XMCUSER_REPLACE_ME' in line:
                        newlines.append(line.replace('XMCUSER_REPLACE_ME', self.xmcuser))
                    elif 'XMCPASSWORD_REPLACE_ME' in line:
                        newlines.append(line.replace('XMCPASSWORD_REPLACE_ME', 'xxxxxxx'))
                    else:
                        newlines.append(line)

        with open(ovf_file, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)

        print ("Updated " + ovf_file)

    def get_xmc_info(self, token):
        return_val = False

        if self.xmc_configured:
            self.new_xmcip = PostInstallUtils.get_ip(
                self, "Please enter {0} IP address: ".format(XMC_TYPE))

            self.new_xmcfqdn = PostInstallUtils.get_fqdn(
                self, "Please enter {0} FQDN: ".format(XMC_TYPE))

            self.new_xmcuser = raw_input("Please enter {0} user name: ".format(XMC_TYPE))

            self.xmcpassword = PostInstallUtils.decrypt_password(self, token, False)
            self.new_xmcpassword = PostInstallUtils.get_password(
                self, "Please enter {0} user password: ".format(XMC_TYPE), XMC_TYPE)

            if self.new_xmcip != self.xmcip or self.new_xmcfqdn != self.xmcfqdn or \
                    self.new_xmcuser != self.xmcuser or self.new_xmcpassword != self.xmcpassword:
                self.xmcpassword = self.new_xmcpassword
                return_val = self.confirm_config('\n', True, False)
            else:
                print "Nothing changed. Process is canceled."
                return_val = False
        else:
            self.xmcip = PostInstallUtils.get_ip(
                self, "Please enter {0} IP address: ".format(XMC_TYPE))
            self.xmcfqdn = PostInstallUtils.get_fqdn(
                self, "Please enter {0} FQDN: ".format(XMC_TYPE))
            self.xmcuser = raw_input("Please enter {0} user name: ".format(XMC_TYPE))
            self.xmcpassword = PostInstallUtils.get_password(
                self, "Please enter {0} user password: ".format(XMC_TYPE), XMC_TYPE)

            if self.xmcip != '' and self.xmcfqdn != '' and self.xmcuser != '' and \
                    self.xmcpassword != '':
                return_val = self.confirm_config('\n', False, True)
            else:
                print "Missing one or more input values"
                return_val = False

        return return_val

    def user_config_validate(self, message):
        print message

        count = 0
        return_value = False
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
        
    def confirm_config(self, message, new_value=False, init_value=False):
        print message

        if new_value:
            print 'Configured {0} information: '.format(XMC_TYPE)
            print '{0} IP:              {1}'.format(XMC_TYPE, self.new_xmcip)
            print '{0} FQDN:            {1}'.format(XMC_TYPE, self.new_xmcfqdn)
            print '{0} Login User Name: {1}'.format(XMC_TYPE, self.new_xmcuser)
        else:
            if self.xmc_configured or init_value:
                print 'Current configured {0} information: '.format(XMC_TYPE)
                print '{0} IP:              {1}'.format(XMC_TYPE, self.xmcip)
                print '{0} FQDN:            {1}'.format(XMC_TYPE, self.xmcfqdn)
                print '{0} Login User Name: {1}'.format(XMC_TYPE, self.xmcuser)

        message = 'Do you want to continue? '
        answer = self.user_config_validate(message)
        
        return answer

    def get_user_credential(self):
        self.username = raw_input("Please enter {0} admin user name: (st2admin) ".format(EWC_TYPE))
        if self.username == '':
            self.username = 'st2admin'
        self.password = getpass.getpass("Please enter {0} admin user password: ".format(EWC_TYPE))
        
if __name__ == "__main__":
    xmc_config = XmcConfig()
    
    xmc_config.get_user_credential()
    token = xmc_config.get_auth_token()
    if xmc_config.confirm_config('\nYou are going to configure {0}.'.format(XMC_TYPE)):
        if xmc_config.get_xmc_info(token):
            xmc_config.generate_api_key(token)
            xmc_config.encrypt_password(token, False)
            xmc_config.update_st2schema_file()
            xmc_config.update_ovf_file()
            xmc_config.create_st2info_file(False)
            xmc_config.scpy_xmcfile()
            xmc_config.config_cloudconn()

