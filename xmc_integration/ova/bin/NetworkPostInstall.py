#!/usr/bin/env python

import os
import subprocess

from PostInstallUtils import PostInstallUtils


class NetworkPostInstall(PostInstallUtils):

    """
        Post installation for network.
    """
    def __init__(self):
        PostInstallUtils.__init__(self, '/opt/xmc/ova/log/networkPostInstall.log')

    def load_config_file(self):
        PostInstallUtils.load_config_file(self)

    def change_network(self):
        self.update_interfaces()
        self.update_hostname()
        self.update_hosts()

    def update_interfaces(self):
        interfaces = '/etc/network/interfaces'

        newlines = list()
        newlines.append('# This file describes the network interfaces available on your system' + "\n")
        newlines.append('# and how to activate them. For more information, see interfaces(5).' + "\n")
        newlines.append('\n')
        newlines.append('#source /etc/network/interfaces.d/*' + "\n")
        newlines.append('\n')
        newlines.append('# the loopback network interface' + '\n')
        newlines.append('auto lo' + "\n")
        newlines.append('iface lo inet loopback' + "\n")
        newlines.append('\n')
        newlines.append('# The primary network interface' + "\n")
        newlines.append('auto eth0' + "\n")
        newlines.append('iface eth0 inet static' + "\n")
        newlines.append("    address " + self.st2ip + "\n")
        newlines.append("    gateway " + self.gatway + "\n")
        newlines.append("    netmask " + self.netmask + "\n")

        if self.searchlist != '':
            newlines.append("    dns-search " + self.searchlist + "\n")

        if self.dns != '':
            dns_list = self.dns.split(',')
            for dns in dns_list:
                newlines.append("    dns-nameservers " + dns + "\n")

        newlines.append('\n')
        newlines.append('pre-up sleep 2' + "\n")

        # open config.schema.yaml for update
        with open(interfaces, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)
        self.logger.debug("Updated file " + interfaces)

    def update_hosts(self):
        hosts = '/etc/hosts'
        
        newlines = list()
        newlines.append('::1     localhost ip6-localhost ip6-loopbac' + "\n")
        newlines.append('ff02::1 ip6-allnodes' + "\n")
        newlines.append('ff02::2 ip6-allrouters' + "\n")
        
        newlines.append(self.st2ip + ' ' + self.st2fqdn + ' ' + self.st2fqdn.split('.')[0] + "\n") 
        newlines.append(self.xmcip + ' ' + self.xmcfqdn + ' ' + self.xmcfqdn.split('.')[0] + "\n")
        
        with open(hosts, 'w+') as outfile:
            for line in newlines:
                outfile.write(line)
    
        self.logger.debug("Updated file " + hosts)

    def update_hostname(self):
        hostname = '/etc/hostname'
        
        newline = self.st2fqdn.split('.')[0]
        with open(hostname, 'w+') as outfile:
            outfile.write(newline)
            
        self.logger.debug("Updated file " + hostname)

    def update_timezone(self):
        system_timezone='/usr/share/zoneinfo/'
        
        subprocess.check_call('sudo rm -f /etc/localtime', shell=True)
        new_timezone_file = system_timezone + self.timezone
        if os.path.isfile(new_timezone_file):
            self.logger.debug("New TimeZone Location = " + new_timezone_file)

            cmd = 'sudo timedatectl set-timezone ' + self.timezone
            subprocess.check_call(cmd, shell=True)
            cmd = 'sudo timedatectl set-ntp on'
            subprocess.check_call(cmd, shell=True)
            cmd = 'sudo timedatectl'
            subprocess.check_call(cmd, shell=True)

    def test_from_cmd(self):
        self.load_config_file()
        self.change_network()
        self.update_timezone()


if __name__ == "__main__":
    network_post_install = NetworkPostInstall()

    network_post_install.load_config_file()
    network_post_install.change_network()
    network_post_install.update_timezone()

