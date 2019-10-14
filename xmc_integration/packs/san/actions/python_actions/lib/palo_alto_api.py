import requests
import time
import urllib3
import xml.etree.ElementTree as ET
import json

from extreme_policy import ExtremeManagementPolicyDef
from extreme_policy import ExtremePolicy


class PaloAltoApi(object):
    def __init__(self, firewall, username, password, vsys='vsys1', prefix='Extr '):
        self.firewall = firewall
        self.username = username
        self.password = password
        self.key = None
        self.vsys = vsys
        self.prefix = prefix
        self.DEBUG = True

    def get(self, url, params=None):
        content = None
        r = requests.get(url, verify=False, auth=(self.username, self.password), params=params)
        code = r.status_code
        if code == 200:
            content = r.content
        else:
            print '{0} -> {1}'.format(str(code), r.content)
        return content

    def post(self, url, data):
        content = None
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        r = requests.post(url, verify=False, headers=headers, data=data)
        code = r.status_code
        if code == 200:
            content = r.content
        elif code != 404:
            print '{0} -> {1}'.format(str(code), r.content)
        return content

    def get_name(self, name):
        if self.prefix != '' and self.prefix in name:
            n = name
        else:
            n = self.prefix + name
        return n

    def get_tag_name(self, name):
        n = self.get_name(name)
        return n
        #return str.replace(n, ' ', '_')

    def get_api_key(self):
        if self.key is None:
            self.key = self.generate_api_key()
        return self.key

    def generate_api_key(self):
        url = 'https://{0}/api/?type=keygen&user={1}&password={2}'.format(self.firewall, self.username, self.password)
        content = self.get(url)
        key = None
        if content is not None and 'success' in content:
            # <response status = 'success'><result><key>LUFRPT1sdFJ5aFZqbitHUVlPVGJYeHFVM3lJbmhzQzg9M2tuZHZQRUt4THpTMUo5anQ0clltQT09</key></result></response>
            root = ET.fromstring(content)
            key = root.find('result').find('key').text
        else:
            print 'Unable to generate API key -> {0}'.format(content)
        return key

    def get_all_applications(self):
        key = self.get_api_key()
        content = None
        if key is not None:
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/application&key={2}'.format(self.firewall, self.vsys, key)
            content = self.get(url)
        return content

    def get_application(self, application, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(application)
            if exactName:
                name = application
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/application/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def add_application(self, rule):
        commit = False

        key = self.get_api_key()
        if key is not None:
            if self.DEBUG:
                print 'Rule -> {0}'.format(rule.get_traffic_description())

            name = ''
            if rule.get_name() is not None and rule.get_name() != '':
                name = self.get_name(rule.get_name())
            else:
                name = self.get_name(rule.get_traffic_description())

            requests = []

            if rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP4_SOURCE:
                if rule.get_data() is not None:
                    ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_data()), rule.get_mask())
                    mask = ''
                    if '/' in ipAddress:
                        split = ipAddress.split('/')
                        ipAddress = split[0]
                        mask = split[1]

                    ipRange = ''
                    if mask != '':
                        subnet = rule.get_ip_subnet(ipAddress, mask)
                        hosts = rule.get_host_count(mask)
                        if hosts > 2:
                            ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        if self.DEBUG:
                            print 'Source IPv4 rule match -> {0}'.format(ipRange)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP4_DESTINATION:
                if rule.get_data() is not None:
                    ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_data()), rule.get_mask())
                    mask = ''
                    if '/' in ipAddress:
                        split = ipAddress.split('/')
                        ipAddress = split[0]
                        mask = split[1]

                    ipRange = ''
                    if mask != '':
                        subnet = rule.get_ip_subnet(ipAddress, mask)
                        hosts = rule.get_host_count(mask)
                        if hosts > 2:
                            ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        if self.DEBUG:
                            print 'Destination IPv4 rule match -> {0}'.format(ipRange)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT:
                port = rule.get_data()
                if port is not None and port != '':
                    end = rule.get_mask()
                    socket = rule.get_formatted_port(port, end)
                    if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                        ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
                        mask = ''
                        if '/' in ipAddress:
                            split = ipAddress.split('/')
                            ipAddress = split[0]
                            mask = split[1]

                        ipRange = ''
                        if mask != '':
                            subnet = rule.network.get_ip_subnet()
                            hosts = rule.get_host_count()
                            if hosts > 2:
                                ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                        else:
                            ipRange = ipAddress

                        if ipRange != '':
                            if self.DEBUG:
                                print 'UDP source port rule match -> {0}:{1}'.format(ipRange, socket)
                    else:
                        if self.DEBUG:
                            print 'UDP source port rule match -> {0}'.format(socket)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT:
                port = rule.get_data()
                if port is not None and port != '':
                    end = rule.get_mask()
                    socket = rule.get_formatted_port(port, end)
                    if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                        ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
                        mask = ''
                        if '/' in ipAddress:
                            split = ipAddress.split('/')
                            ipAddress = split[0]
                            mask = split[1]

                        ipRange = ''
                        if mask != '':
                            subnet = rule.network.get_ip_subnet()
                            hosts = rule.get_host_count()
                            if hosts > 2:
                                ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                        else:
                            ipRange = ipAddress

                        if ipRange != '':
                            if self.DEBUG:
                                print 'UDP destination port rule match -> {0}:{1}'.format(ipRange, socket)
                    else:
                        if self.DEBUG:
                            print 'UDP destination port rule match -> {0}'.format(socket)

                    attrs = {}
                    attrs['name'] = self.get_name('UDP {0}'.format(socket))
                    attrs['description'] = name
                    attrs['xml'] = '<port><member>udp/{0}</member></port>'.format(socket)

                    application = self.get_application(attrs['name'], True)
                    if application is None or attrs['name'] not in application:
                        requests.append(attrs)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT:
                port = rule.get_data()
                if port is not None and port != '':
                    end = rule.get_mask()
                    socket = rule.get_formatted_port(port, end)
                    if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                        ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
                        mask = ''
                        if '/' in ipAddress:
                            split = ipAddress.split('/')
                            ipAddress = split[0]
                            mask = split[1]

                        ipRange = ''
                        if mask != '':
                            subnet = rule.network.get_ip_subnet()
                            hosts = rule.get_host_count()
                            if hosts > 2:
                                ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                        else:
                            ipRange = ipAddress

                        if ipRange != '':
                            if self.DEBUG:
                                print 'TCP source port rule match -> {0}:{1}'.format(ipRange, socket)
                    else:
                        if self.DEBUG:
                            print 'TCP source port rule match -> {0}'.format(socket)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT:
                port = rule.get_data()
                if port is not None and port != '':
                    end = rule.get_mask()
                    socket = rule.get_formatted_port(port, end)
                    if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                        ipAddress = rule.get_formatted_address(rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
                        mask = ''
                        if '/' in ipAddress:
                            split = ipAddress.split('/')
                            ipAddress = split[0]
                            mask = split[1]

                        ipRange = ''
                        if mask != '':
                            subnet = rule.network.get_ip_subnet()
                            hosts = rule.get_host_count()
                            if hosts > 2:
                                ipRange = rule.to_ip_address(subnet) + '-' + rule.to_ip_address((subnet + hosts) - 1)
                        else:
                            ipRange = ipAddress

                        if ipRange != '':
                            if self.DEBUG:
                                print 'TCP destination port rule match -> {0}:{1}'.format(ipRange, socket)
                    else:
                        if self.DEBUG:
                            print 'TCP destination port rule match -> {0}'.format(socket)

                    attrs = {}
                    attrs['name'] = self.get_name('TCP {0}'.format(socket))
                    attrs['description'] = name
                    attrs['xml'] = '<port><member>tcp/{0}</member></port>'.format(socket)

                    application = self.get_application(attrs['name'], True)
                    if application is None or attrs['name'] not in application:
                        requests.append(attrs)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP_TYPE_CODE:
                data = rule.get_data()
                type = (data & 0xFF00) >> 8
                code = data & 0xFF

                if self.DEBUG:
                    print 'ICMP type/code rule match -> {0}/{1}'.format(type, code)

                attrs = {}
                attrs['name'] = self.get_name('ICMP {0} {1}'.format(type, code))
                attrs['description'] = name
                attrs['xml'] = '<ident-by-icmp-type><type>{0}</type><code>{1}</code></ident-by-icmp-type>'.format(type, code)

                application = self.get_application(attrs['name'], True)
                if application is None or attrs['name'] not in application:
                    requests.append(attrs)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP_TYPE:
                end = rule.get_mask()
                if end is not None and end != '' and int(end) > 0:
                    difference = end - int(rule.get_data())
                    for i in range(0, difference + 1):
                        protocol = rule.get_data() + i

                        if self.DEBUG:
                            print 'IP protocol rule match -> {0}'.format(protocol)

                        attrs = {}
                        attrs['name'] = self.get_name('Protocol {0}'.format(protocol))
                        attrs['description'] = name
                        attrs['xml'] = '<ident-by-ip-protocol>{0}</ident-by-ip-protocol>'.format(protocol)

                        application = self.get_application(attrs['name'], True)
                        if application is None or attrs['name'] not in application:
                            requests.append(attrs)
                else:
                    protocol = rule.get_data()

                    if self.DEBUG:
                        print 'IP protocol rule match -> {0}'.format(protocol)

                    attrs = {}
                    attrs['name'] = self.get_name('Protocol {0}'.format(protocol))
                    attrs['description'] = name
                    attrs['xml'] = '<ident-by-ip-protocol>{0}</ident-by-ip-protocol>'.format(protocol)

                    application = self.get_application(attrs['name'])
                    if application is None or attrs['name'] not in application:
                        requests.append(attrs)

            elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP6_TYPE_CODE:
                data = rule.get_data()
                type = (data & 0xFF00) >> 8
                code = data & 0xFF

                if self.DEBUG:
                    print 'ICMP6 type/code rule match -> {0}/{1}'.format(type, code)

                attrs = {}
                attrs['name'] = self.get_name('ICMP6 {0} {1}'.format(type, code))
                attrs['description'] = name
                attrs['xml'] = '<ident-by-icmp6-type><type>{0}</type><code>{1}</code></ident-by-icmp6-type>'.format(type, code)

                application = self.get_application(attrs['name'], True)
                if application is None or attrs['name'] not in application:
                    requests.append(attrs)

            if len(requests) > 0:
                for request in requests:
                    name = request['name']
                    description = request['description']
                    data = request['xml']
                    xml = '<entry name=\'{0}\'><default>{1}</default><subcategory>ip-protocol</subcategory><category>networking</category><technology>network-protocol</technology><risk>1</risk><description>{2}</description></entry>'.format(name, data, description)
                    url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/application&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
                    content = self.get(url)

                    if self.DEBUG:
                        print url
                        print content
                commit = True

        return commit

    def get_all_address_groups(self):
        key = self.get_api_key()
        content = None
        if key is not None:
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group&key={2}'.format(self.firewall, self.vsys, key)
            content = self.get(url)
        return content

    def get_address_group(self, group, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(group)
            if exactName:
                name = group
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def add_address_group(self, group, address=None):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(group)

            if address is None:
                address = '127.0.0.1'
            self.add_address_if_needed(address)

            xml = '<entry name=\'{0}\'><static><member>{1}</member></static></entry>'.format(name, self.get_name(address))
            url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
            content = self.get(url)
        return content

    def add_dynamic_address_group_if_needed(self, group):
        key = self.get_api_key()
        content = None
        if key is not None:
            g = self.get_address_group(group)
            if g is None or group not in g:
                content = self.add_dynamic_address_group(group, group)
        return content

    def add_dynamic_address_group(self, group, tag, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(group)
            t = self.get_tag_name(tag)
            if exactName:
                name = group
                f = filter
                t = tag
            #xml = '<entry name=\'{0}\'><dynamic><filter>\'{1}\'</filter></dynamic><tag><member>{1}</member></tag></entry>'.format(name, t)
            xml = '<entry name=\'{0}\'><dynamic><filter>\'{1}\'</filter></dynamic></entry>'.format(name, t)
            url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
            content = self.get(url)
        return content

    def add_address_group_if_needed(self, group):
        key = self.get_api_key()
        content = None
        if key is not None:
            g = self.get_address_group(group)
            if g is None or group not in g:
                content = self.add_address_group(group)
        return content

    def add_address_to_group(self, address, group, removeFromOtherGroups=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            commit = False
            #status = self.add_tag_if_needed(group)
            #if status is not None:
            #    commit = True
            status = self.add_dynamic_address_group_if_needed(group)
            if status is not None:
                commit = True
            if commit:
                self.commit(True)

            if removeFromOtherGroups:
                groups = self.get_all_address_groups()
                if groups is not None:
                    root = ET.fromstring(groups)
                    entries = root.find('result').find('address-group').findall('entry')
                    for entry in entries:
                        name = entry.get('name')
                        if name != self.get_name(group):
                            unregister = True
                            if self.prefix is not None or self.prefix != '':
                                unregister = False
                                if name.startswith(self.prefix):
                                    unregister = True

                            if unregister:
                                self.send_unregister_tag(address, name, self.vsys, True)

            content = self.send_register_tag(address, group, self.vsys)
            if self.DEBUG:
                print content

            message = 'tag {0} already exists, ignore'.format(self.get_name(group))
            if message in content or 'success' in content:
                content = {'message': 'Message successfully sent'}
            else:
                content = {'message': 'Message was not successfully sent'}
        else:
            content = {'message': 'Unable to generate API key'}
        return content

    def remove_address_from_group(self, group, address, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            content = self.send_unregister_tag(address, group, self.vsys)
            if self.DEBUG:
                print content

            message = 'ip {0} does not exist, ignore unreg'.format(address) 
            if 'success' in content or message in content:
                content = {'message': 'Message successfully sent'}
            else:
                content = {'message': 'Message was not successfully sent'}
        else:
            content = {'message': 'Unable to generate API key'}
        return content

    """
    def add_address_to_group(self, address, group, removeFromOtherGroups=False, commit=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            self.add_address_if_needed(address)
            self.add_address_group_if_needed(group)

            members = []
            g = self.get_address_group(group)
            if g is not None and group in g:
                root = ET.fromstring(g)
                addresses = root.find('result').find('entry').find('static').findall('member')
                for a in addresses:
                    ipAddress = a.text
                    if '127.0.0.1' not in ipAddress:
                        members.append(ipAddress)

                update = False
                addr = self.get_name(address)
                if addr not in members:
                    members.append(addr)
                    update = True
                else:
                    content = '<response status="warning" code="0"><msg>Address already in group</msg></response>'

                if update:
                    addresses = ''
                    for member in members:
                        addresses += '<member>{0}</member>'.format(member)

                    name = self.get_name(group)
                    xml = '<static>{0}</static>'.format(addresses)
                    url = 'https://{0}/api/?type=config&action=edit&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group/entry[@name=\'{2}\']/static&element={3}&key={4}'.format(self.firewall, self.vsys, name, xml, key)
                    content = self.get(url)

                if removeFromOtherGroups:
                    groups = self.get_all_address_groups()
                    if groups is not None:
                        root = ET.fromstring(groups)
                        entries = root.find('result').find('address-group').findall('entry')
                        for entry in entries:
                            name = entry.get('name')
                            if name != self.get_name(group):
                                members = entry.find('static').findall('member')
                                remove = False
                                for member in members:
                                    ipAddress = member.text
                                    if ipAddress == addr:
                                        remove = True
                                        break
                                if remove:
                                    if self.DEBUG:
                                        print 'Removing {0} from group {1}'.format(addr, name)
                                        self.remove_address_from_group(name, addr, False, True)
                                        update = True

                if update and commit:
                    self.commit(True)
        else:
            content = '<response status="error" code="0"><msg>Unable to generate API key</msg></response>'

        return content

    def remove_address_from_group(self, address, group, deleteAddress=False, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            self.add_address_if_needed(address)
            self.add_address_group_if_needed(group)

            addr = self.get_name(address)
            if exactName:
                addr = address

            members = []
            g = self.get_address_group(group)
            if g is not None and group in g:
                root = ET.fromstring(g)
                addresses = root.find('result').find('entry').find('static').findall('member')
                for a in addresses:
                    ipAddress = a.text
                    members.append(ipAddress)

                if addr in members:
                    members.remove(addr)

                    if len(members) == 0:
                        self.add_address_if_needed('127.0.0.1')
                        members.append(self.get_name('127.0.0.1'))

                    addresses = ''
                    for member in members:
                        addresses += '<member>{0}</member>'.format(member)

                    name = self.get_name(group)
                    if exactName:
                        name = group

                    xml = '<static>{0}</static>'.format(addresses)
                    url = 'https://{0}/api/?type=config&action=edit&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address-group/entry[@name=\'{2}\']/static&element={3}&key={4}'.format(self.firewall, self.vsys, name, xml, key)
                    content = self.get(url)
                else:
                    content = '<response status="warning" code="0"><msg>Address not in group</msg></response>'
            else:
                content = '<response status="error" code="0"><msg>Address group does not exist</msg></response>'

            if deleteAddress:
                self.delete_address(addr, exactName)
        else:
            content = '<response status="error" code="0"><msg>Unable to generate API key</msg></response>'

        return content
    """

    def get_all_addresses(self):
        key = self.get_api_key()
        content = None
        if key is not None:
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address&key={2}'.format(self.firewall, self.vsys, key)
            content = self.get(url)
        return content

    def get_address(self, address, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(address)
            if exactName:
                name = address
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def add_address(self, address):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(address)
            xml = '<entry name=\'{0}\'><ip-netmask>{1}</ip-netmask><description>{0}</description></entry>'.format(name, address)
            url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
            content = self.get(url)
        return content

    def add_address_if_needed(self, address):
        key = self.get_api_key()
        content = None
        if key is not None:
            ipAddress = self.get_address(address)
            if ipAddress is None or address not in ipAddress:
                content = self.add_address(address)
        return content

    def delete_address(self, address, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(address)
            if exactName:
                name = address
            url = 'https://{0}/api/?type=config&action=delete&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/address/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def get_policy(self, policy, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(policy)
            if exactName:
                name = policy
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/rulebase/security/rules/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def add_policy(self, policy, to='any', sender='any', source='any', destination='any', user='any', category='any', application=['any'], service='application-default', profiles='any', action='deny', enable=True):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(policy)
            disable = 'no'
            if not enable:
                disable = 'yes'
            applications = ''
            for a in application:
                applications += '<member>{0}</member>'.format(a)

            xml = '<entry name=\'{0}\'>' \
                  '<to><member>{1}</member></to>' \
                  '<from><member>{2}</member></from>' \
                  '<source><member>{3}</member></source>' \
                  '<destination><member>{4}</member></destination>' \
                  '<source-user><member>{5}</member></source-user>' \
                  '<category><member>{6}</member></category>' \
                  '<application>{7}</application>' \
                  '<service><member>{8}</member></service>' \
                  '<hip-profiles><member>{9}</member></hip-profiles>' \
                  '<action>{10}</action>' \
                  '<disabled>{11}</disabled></entry>'.format(name, to, sender, source, destination, user, category, applications, service, profiles, action, disable)
            url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/rulebase/security/rules&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
            content = self.get(url)
        return content

    def set_policy_application(self, policy, application, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(policy)
            if exactName:
                name = policy

            applications = ''
            for a in application:
                app = self.get_name(a)
                if exactName:
                    app = a

                applications += '<member>{0}</member>'.format(app)

            xml = '<application>{0}</application>'.format(applications)
            url = 'https://{0}/api/?type=config&action=edit&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/rulebase/security/rules/entry[@name=\'{2}\']/application&element={3}&key={4}'.format(self.firewall, self.vsys, name, xml, key)
            content = self.get(url)
        return content

    def set_policy_enabled(self, policy, enable, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_name(policy)
            if exactName:
                name = policy

            disable = 'no'
            if not enable:
                disable = 'yes'
            xml = '<disabled>{0}</disabled>'.format(disable)
            url = 'https://{0}/api/?type=config&action=edit&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/rulebase/security/rules/entry[@name=\'{2}\']/disabled&element={3}&key={4}'.format(self.firewall, self.vsys, name, xml, key)
            content = self.get(url)
        return content

    def get_all_tags(self):
        key = self.get_api_key()
        content = None
        if key is not None:
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/tag&key={2}'.format(self.firewall, self.vsys, key)
            content = self.get(url)
        return content

    def get_tag(self, tag, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_tag_name(tag)
            if exactName:
                name = tag
            url = 'https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/tag/entry[@name=\'{2}\']&key={3}'.format(self.firewall, self.vsys, name, key)
            content = self.get(url)
        return content

    def add_tag_if_needed(self, tag):
        key = self.get_api_key()
        content = None
        if key is not None:
            t = self.get_tag(tag)
            if t is None or tag not in t:
                content = self.add_tag(tag)
        return content

    def add_tag(self, tag):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_tag_name(tag)
            xml = '<entry name=\'{0}\'/>'.format(name)
            url = 'https://{0}/api/?type=config&action=set&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{1}\']/tag&element={2}&key={3}'.format(self.firewall, self.vsys, xml, key)
            content = self.get(url)
        return content

    def create_firewall_rules(self, profile, commit=False):
        content = None
        key = self.get_api_key()

        if key is not None:
            if profile is not None:
                vid = profile.get_vid()

                if vid == ExtremeManagementPolicyDef.ACTION_PERMIT or vid == ExtremeManagementPolicyDef.ACTION_DROP:
                    rules = profile.get_rules()

                    update = False
                    for rule in rules:
                        if self.add_application(rule):
                            update = True

                    self.add_address_group_if_needed(profile.get_name())

                    name = self.get_name(profile.get_name())
                    acceptName = name + ' - Accept'
                    acceptPolicy = self.get_policy(acceptName, True)
                    if acceptPolicy is None or acceptName not in acceptPolicy:
                        acceptPolicy = None

                    denyName = name + ' - Deny'
                    denyPolicy = self.get_policy(denyName, True)
                    if denyPolicy is None or denyName not in denyPolicy:
                        denyPolicy = None

                    if acceptPolicy is None or denyPolicy is None:
                        if vid == ExtremeManagementPolicyDef.ACTION_PERMIT:
                            if denyPolicy is None:
                                response = self.add_policy(denyName, source=self.get_name(profile.get_name()), action='deny', enable=False)
                                update = True
                                if self.DEBUG:
                                    print response
                            if acceptPolicy is None:
                                response = self.add_policy(acceptName, source=self.get_name(profile.get_name()), action='allow', enable=True)
                                update = True
                                if self.DEBUG:
                                    print response

                        elif vid == ExtremeManagementPolicyDef.ACTION_DROP:
                            if acceptPolicy is None:
                                response = self.add_policy(acceptName, source=self.get_name(profile.get_name()), action='allow', enable=False)
                                update = True
                                if self.DEBUG:
                                    print response
                            if denyPolicy is None:
                                response = self.add_policy(denyName, source=self.get_name(profile.get_name()), action='deny', enable=True)
                                update = True
                                if self.DEBUG:
                                    print response
                        if update:
                            content = {'message': 'Message successfully sent'}

                    entries = None
                    all = self.get_all_applications()
                    if all is not None and 'entry' in all:
                        root = ET.fromstring(all)
                        entries = root.find('result').find('application').findall('entry')

                    if entries is None:
                        print 'There are no applications to filter on!'
                    else:
                        if acceptPolicy is None:
                            acceptPolicy = self.get_policy(acceptName, True)
                        members = []
                        root = ET.fromstring(acceptPolicy)
                        applications = root.find('result').find('entry').find('application').findall('member')
                        for application in applications:
                            app = application.text
                            if app != 'any':
                                members.append(app)

                        updateRules = False
                        rules = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_PERMIT)
                        for rule in rules:
                            name = self.get_name(rule.get_name())
                            for entry in entries:
                                description = entry.find('description').text
                                if name == description:
                                    if entry.get('name') not in members:
                                        members.append(entry.get('name'))
                                        updateRules = True
                        if updateRules:
                            self.set_policy_application(acceptName, members, True)
                            self.set_policy_enabled(acceptName, True, True)
                            update = True

                        if denyPolicy is None:
                            denyPolicy = self.get_policy(denyName, True)
                        members = []
                        root = ET.fromstring(denyPolicy)
                        applications = root.find('result').find('entry').find('application').findall('member')
                        for application in applications:
                            app = application.text
                            if app != 'any':
                                members.append(app)

                        updateRules = False
                        rules = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_DROP)
                        for rule in rules:
                            name = self.get_name(rule.get_name())
                            for entry in entries:
                                description = entry.find('description').text
                                if name == description:
                                    if entry.get('name') not in members:
                                        members.append(entry.get('name'))
                                        updateRules = True
                        if updateRules:
                            self.set_policy_application(denyName, members, True)
                            self.set_policy_enabled(denyName, True, True)
                            update = True

                if update:
                    if content is not None:
                        content = {'message': 'Message successfully sent'}
                    else:
                        content = {'message': 'Message successfully sent'}
                    if commit:
                        self.commit(True)
                else:
                    if content is None:
                        content = {'message': 'Message successfully sent'}
            else:
                content = {'message': 'Extreme policy profile is null'}
        else:

            content = {'message': 'Unable to generate API key'}

        return content

    def get_profile_rules_by_action(self, profile, action):
        policies = list()
        rules = profile.get_rules()
        for rule in rules:
            if rule.get_vid() == action:
                policies.append(rule)
        return policies

    def send_register_tag(self, ipAddress, tag, vsys, exactName=False):
        return self.send_user_id_tag_message(ipAddress, 'register', tag, vsys, exactName)

    def send_unregister_tag(self, ipAddress, tag, vsys, exactName=False):
        return self.send_user_id_tag_message(ipAddress, 'unregister', tag, vsys, exactName)

    def send_user_id_tag_message(self, ipAddress, state, tag, vsys, exactName=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            name = self.get_tag_name(tag)
            if exactName:
                name = tag
            xml = '<uid-message><version>1.0</version><type>update</type><payload><{0}><entry identifier="{1}" ip="{2}"></entry></{0}></payload></uid-message>'.format(state, name, ipAddress)
            url = 'https://{0}/api/?type=user-id&action=set&vsys={1}&cmd={2}&key={3}'.format(self.firewall, vsys, xml, key)
            if self.DEBUG:
                print url
            content = self.get(url)
        return content

    def commit(self, wait=False):
        key = self.get_api_key()
        content = None
        if key is not None:
            # <response status="success" code="19"><result><msg><line>Commit job enqueued with jobid 6</line></msg><job>6</job></result></response>
            url = 'https://{0}/api/?type=commit&cmd=<commit></commit>&key={1}'.format(self.firewall, key)
            content = self.get(url)

        if wait:
            # <response status = 'success'><result><key>LUFRPT1sdFJ5aFZqbitHUVlPVGJYeHFVM3lJbmhzQzg9M2tuZHZQRUt4THpTMUo5anQ0clltQT09</key></result></response>
            if content is not None and 'job' in content:
                root = ET.fromstring(content)
                job = root.find('result').find('job').text
                complete = 0
                while complete < 100:
                    status = self.get_job_status(job)
                    if status is not None and 'progress' in status:
                        root = ET.fromstring(status)
                        complete = int(root.find('result').find('job').find('progress').text)
                        if self.DEBUG:
                            print 'Progress percentage: {0}'.format(complete)
                        if complete < 100:
                            time.sleep(1)
                    else:
                        complete = 100
        return content

    def get_job_status(self, job):
        key = self.get_api_key()
        content = None
        if key is not None:
            # <response status="success"><result><job><tenq>2018/07/11 03:48:23</tenq><tdeq>03:48:23</tdeq><id>7</id><user>admin</user><type>Commit</type><status>ACT</status><queued>NO</queued><stoppable>yes</stoppable><result>PEND</result><tfin>Still Active</tfin><description/><positionInQ>0</positionInQ><progress>55</progress><warnings/><details/></job></result></response>
            url = 'https://{0}/api/?type=op&cmd=<show><jobs><id>{1}</id></jobs></show>&key={2}'.format(self.firewall, job, key)
            content = self.get(url)
        return content

    def create_firewall_rules_by_policy(self, policy_name, policy_config, install=False):
        status = None
        
        if policy_config is not None:
            cfg = json.loads(policy_config)
            if 'data' in cfg:
                data = cfg['data']
                converter = ExtremePolicy()
                if 'policy' in data:
                    profiles = converter.get_policy_profiles(data)
                    if profiles is not None:
                        for profile in profiles:
                            name = profile.get_name()
                            if name == policy_name:
                                status = self.create_firewall_rules(profile)
                                break;
         
        return status
