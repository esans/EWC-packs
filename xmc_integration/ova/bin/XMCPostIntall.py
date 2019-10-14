#!/usr/bin/env python

import subprocess
import time

from PostInstallUtils import PostInstallUtils

class XMCPostInstall(PostInstallUtils):
    """
        Post installation for updating XMC information.
    """

    def __init__(self):
        PostInstallUtils.__init__(self, '/opt/xmc/ova/log/xmcPostInstall.log')
        PostInstallUtils.load_config_file(self)
        self.st2_base_path = PostInstallUtils.get_st2_base_path(self)

        self.logger.debug("Waiting two minutes for StackStorm to up running.")
        time.sleep(120)
        subprocess.call("sudo systemctl restart rabbitmq-server", shell=True)

    def is_xmc_configured(self):
        return self.xmc_configured

    def get_auth_token(self):
        return PostInstallUtils.get_auth_token(self)

    def generate_api_key(self, token):
        PostInstallUtils.generate_api_key(self, token)

    def encrypt_password(self, input_token):
        PostInstallUtils.encrypt_password(self, input_token)
 
    def update_st2schema_file(self):
        PostInstallUtils.update_st2schema_file(self)

    def create_st2info_file(self):
        PostInstallUtils.create_st2info_file(self)

    def scpy_xmcfile(self):
        PostInstallUtils.scpy_xmcfile(self)

    def cleanup(self):
        PostInstallUtils.cleanup(self)

    def install_san_pack(self):
        if self.firewall_install == "True":
            subprocess.call("sudo cp -R /opt/xmc/packs/san {0}/packs/".format(
                self.st2_base_path), shell=True)
            subprocess.call("sudo chown -R root:st2packs {0}/packs/san".format(
                self.st2_base_path), shell=True)
            subprocess.call("sudo chmod 755 {0}/packs/san/actions/*".format(
                self.st2_base_path), shell=True)
            subprocess.call("sudo st2 run packs.setup_virtualenv packs=san", shell=True)

            self.logger.debug("san pack is installed.")

    def install_xmc_pack(self):
        subprocess.call("sudo cp -R /opt/xmc/packs/xmc {0}/packs/".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo chown -R root:st2packs {0}/packs/xmc".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo chmod 755 {0}/packs/xmc/actions/*".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo st2 run packs.setup_virtualenv packs=xmc", shell=True)

        subprocess.call("sudo chmod 755 {0}/packs/xmc/ST2Integration/*".format(
            self.st2_base_path), shell=True)
        subprocess.call("sudo chown -R root:root {0}/packs/xmc/ST2Integration/".format(
            self.st2_base_path),
                        shell=True)

        self.logger.debug("XMC pack is installed.")

    def install_packs(self):
        self.install_xmc_pack()
        self.install_san_pack()
        subprocess.call("sudo st2 pack install jira", shell=True)
        self.logger.debug("JIRA pack is installed.")
        subprocess.call("sudo st2 pack install servicenow", shell=True)
        self.logger.debug("ServiceNow pack is installed.")
        subprocess.call("sudo st2ctl reload", shell=True)
        subprocess.call("sudo st2ctl reload --register-configs", shell=True)

if __name__ == "__main__":
    post_install = XMCPostInstall()
    post_install.install_packs()

    if post_install.is_xmc_configured():
        token = post_install.get_auth_token()
        post_install.generate_api_key(token)
        post_install.encrypt_password(token)
        post_install.update_st2schema_file()
        post_install.create_st2info_file()
        post_install.scpy_xmcfile()
        post_install.config_cloudconn()
        post_install.cleanup()
