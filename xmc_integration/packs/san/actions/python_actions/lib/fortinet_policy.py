import json
import random
import requests
from extreme_policy import ExtremeManagementPolicyDef
from extreme_policy import ExtremePolicy

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortinetApi(object):
    def __init__(self, fortinet, username, password, prefix='Extr '):
        self.fortinet = fortinet
        self.username = username
        self.password = password

        # All rule names and address groups will be prefix'd with the 'prefix' value

        self.prefix = prefix
        self.session = None

        self.DEBUG = False

    def get_session_id(self):
        if self.session is None:
            id = self.get_random_id()
            data = {'params': [{'url': 'sys/login/user',
                                'data': [{'user': self.username,
                                          'passwd': self.password}]}],
                    'session': 1, 'id': id, 'method': 'exec'}
            content = self.post(data)
            if content is not None and 'session' in content:
                response = json.loads(content)
                self.session = response['session']
        return self.session

    def get_managed_devices(self):
        devices = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'dvmdb/device'}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            devices = data['data']
        return devices

    def install_policy_package_on_all(self, package='default'):
        status = None
        
        packages = self.get_policy_packages()
        devices = self.get_managed_devices()
        for device in devices:
            name = device['name']
            platform = device['platform_str']
            if self.DEBUG:
                print '{0} -> {1}'.format(name, platform)

            if 'fortigate' in platform.lower():
                pkg = None
                for pack in packages:
                    pkgName = pack['name']
                    if 'scope member' in pack:
                        members = pack['scope member']
                        for member in members:
                            memberName = member['name']
                            if memberName == name:
                                pkg = pkgName
                                break
                if pkg is None:
                    pkg = package
                status = self.install_policy_package(name, pkg)
                
        return status

    def install_policy_package(self, fortigate, package='default'):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': '/securityconsole/install/package',
                'data': [{'adom': 'root', 'pkg': package, 'scope': [{'name': fortigate, 'vdom': 'root'}]}]}],
                'session': session, 'id': id, 'method': 'exec'}
        status = self.post(data)
        if self.DEBUG:
            print 'install package -> {0}'.format(data)
            print 'install package results -> {0}'.format(status)
        return status

    def get_addresses(self):
        addresses = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/address'}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            addresses = data['data']
        return addresses

    def add_address(self, address, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/address',
                            'data': [{'color': 21, 'name': address,
                                      'type': 0, 'associated-interface': 'any',
                                      'subnet': [address, '255.255.255.255']
                                      }]}], 'session': session, 'id': id,
                'method': 'add'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def delete_address(self, address, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/obj/firewall/address/{0}'.format(address)
        data = {'params': [{'url': url}], 'session': session,
                'id': id, 'method': 'delete'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def get_address_groups(self):
        groups = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/addrgrp'}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            groups = data['data']
        return groups

    def add_address_group(self, group, members, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/addrgrp',
                            'data': [{'color': 21, 'name': self.get_name(group),
                                      'member': members}]}], 'session': session,
                'id': id, 'method': 'add'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def update_group(self, group, members, exactName=False, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        name = self.get_name(group)
        if exactName:
            name = group
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/addrgrp',
                            'data': [{'name': name, 'member': members}]}],
                'session': session, 'id': id, 'method': 'update'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def get_policy_packages(self):
        packages = None
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/pkg/adom/root'
        data = {'params': [{'url': url}], 'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            packages = data['data']
        return packages

    def get_policies(self, package):
        policies = None
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {'params': [{'url': url}], 'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            policies = data['data']
        return policies

    def logout(self):
        status = None
        if self.session is not None:
            id = self.get_random_id()
            data = {'verbose': 1, 'params': [{'url': 'sys/logout'}], 'session': self.session,
                    'id': id, 'method': 'exec'}
            status = self.post(data)
        return status

    def get_name(self, name):
        if self.prefix != '' and self.prefix in name:
            n = name
        else:
            n = (self.prefix + name).replace('\'', '').replace('(', '').replace(')', '').replace('"', '')
        return n

    def get_random_id(self):
        return random.randint(1, 0xFFFF)

    def post(self, data):
        content = None
        url = 'https://{0}/jsonrpc'.format(self.fortinet)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        r = requests.post(url, verify=False, headers=headers, json=data)
        code = r.status_code
        if code == 200:
            content = r.content
        else:
            print '{0} -> {1}'.format(str(code), r.content)
        return content

    def get_group_members(self, group, exactName=False):
        members = None
        groups = self.get_address_groups()
        if groups is not None:
            name = self.get_name(group)
            if exactName:
                name = group
            for g in groups:
                n = g['name']
                if n == name:
                    members = g['member']
                    break
        return members

    def add_address_to_group(self, address, group, removeFromOtherGroups=True, install=False):
        status = None
        session = self.get_session_id()
        if session is not None:
            self.add_address_if_needed(address)
            self.add_group_if_needed(group)
            members = self.get_group_members(group)

            update = False

            if address not in members:
                placeholder = '127.0.0.1'
                if placeholder in members:
                    members.remove(placeholder)

                if self.DEBUG:
                    print 'Adding address object: {0} to group: {1}'.format(address, group)
                members.append(address)
                status = self.update_group(group, members)
                update = True
            else:
                status = json.dumps({"result": [{"status": {"code": 0,"message": "Address is already in."}}]})

            if removeFromOtherGroups:
                groups = self.get_address_groups()
                if groups is not None:
                    for g in groups:
                        name = g['name']
                        if name != self.get_name(group):
                            members = g['member']
                            if address in members:
                                members.remove(address)

                                placeholder = '127.0.0.1'
                                self.add_address_if_needed(placeholder)
                                if len(members) == 0 and placeholder not in members:
                                    members.append(placeholder)

                                status = self.update_group(name, members, True)
                                update = True
        else:
            print 'Unable to authenticate user and generate session ID'
            status = json.dumps({"result": [{"status": {"code": 1,"message": "Unable to authenticate user and generate session ID"}}]})

        if update and install:
            self.install_policy_package_on_all()

        return status

    def remove_address_from_group(self, address, group, deleteAddress=True, install=False):
        status = None
        session = self.get_session_id()
        if session is not None:
            members = self.get_group_members(group)

            if members is not None:
                if self.DEBUG:
                    print 'Removing address: {0} from group: {1}'.format(address, group)
                if address in members:
                    members.remove(address)

                    placeholder = '127.0.0.1'
                    self.add_address_if_needed(placeholder)
                    if len(members) == 0 and placeholder not in members:
                        members.append(placeholder)
                    status = self.update_group(group, members)

                    if deleteAddress:
                        self.delete_address(address)

                    if install:
                        self.install_policy_package_on_all()
                else:
                    status = json.dumps({"result": [{"status": {"code": 0,"message": "Threat IP is already removed from FW"}}]})
        return status

    def add_address_if_needed(self, address, install=False):
        add = True
        addresses = self.get_addresses()
        if addresses is not None:
            for a in addresses:
                name = a['name']
                if name == address:
                    add = False
                    break
            if add:
                if self.DEBUG:
                    print 'Creating address object for: {0}'.format(address)
                self.add_address(address)
                if install:
                    self.install_policy_package_on_all()

    def add_group_if_needed(self, group, install=False):
        groups = self.get_address_groups()
        if groups is not None:
            add = True
            for g in groups:
                name = g['name']
                if name == self.get_name(group):
                    add = False
                    break

        status = False
        if add:
            ipAddress = '127.0.0.1'
            self.add_address_if_needed(ipAddress)
            members = [ipAddress]
            self.add_address_group(group, members)
            status = True
            if install:
                self.install_policy_package_on_all()
        return status

    def get_service_groups(self):
        services = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/service/group'}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            services = data['data']
        return services

    def get_custom_services(self):
        services = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/service/custom'}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            services = data['data']
        return services

    def get_custom_service(self, name):
        services = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {'params':
                    [{'url': 'pm/config/adom/root/obj/firewall/service/custom/{0}'.format(name)}],
                'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            services = data['data']
        return services

    def add_custom_service(self, rule, category='Network Services', install=False):
        requests = list()

        name = ''
        if rule.get_name() is not None and rule.get_name() != '':
            name = self.get_name(rule.get_name())
        else:
            name = self.get_name(rule.get_traffic_description())

        if rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP4_DESTINATION:
            if rule.get_data() is not None:
                ipAddress = \
                    rule.get_formatted_address(rule.to_ip_address(rule.get_data()), rule.get_mask())
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
                        ipRange = rule.to_ip_address(subnet) + \
                                  '-' + rule.to_ip_address((subnet + hosts) - 1)
                else:
                    ipRange = ipAddress

                if ipRange != '':

                    attrs = {}
                    attrs['iprange'] = ipRange
                    attrs['tcp-portrange'] = '0:0'
                    attrs['udp-portrange'] = '0:0'
                    attrs['name'] = name

                    add = True
                    service = self.get_custom_service(attrs['name'])
                    if service is not None:
                        value = service['iprange']
                        if value == ipRange:
                            add = False

                    if add:
                        requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['udp-portrange'] = '0:' + socket
                if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                    ipAddress = rule.get_formatted_address(
                        rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
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
                            ipRange = rule.to_ip_address(subnet) + \
                                      '-' + rule.to_ip_address((subnet + hosts) - 1)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        attrs['iprange'] = ipRange

                attrs['name'] = name

                add = True
                service = self.get_custom_service(attrs['name'])
                if service is not None:
                    value = service['udp-portrange']
                    portRange = attrs['udp-portrange']
                    if portRange in value:
                        add = False
                    else:
                        value.append(portRange)
                        attrs['udp-portrange'] = value
                        attrs['method'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['udp-portrange'] = socket + ':0'
                if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                    ipAddress = rule.get_formatted_address(
                        rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
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
                            ipRange = rule.to_ip_address(subnet) \
                                      + '-' + rule.to_ip_address((subnet + hosts) - 1)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        attrs['iprange'] = ipRange

                attrs['name'] = name

                add = True
                service = self.get_custom_service(attrs['name'])
                if service is not None:
                    value = service['udp-portrange']
                    portRange = attrs['udp-portrange']
                    if portRange in value:
                        add = False
                    else:
                        value.append(portRange)
                        attrs['udp-portrange'] = value
                        attrs['method'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['tcp-portrange'] = '0:' + socket
                if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                    ipAddress = rule.get_formatted_address(
                        rule.to_ip_address(rule.get_expanded_data()), rule.get_expanded_mask())
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
                            ipRange = rule.to_ip_address(subnet + 1) + \
                                      '-' + rule.to_ip_address((subnet + hosts) - 2)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        attrs['iprange'] = ipRange

                attrs['name'] = name

                add = True
                service = self.get_custom_service(attrs['name'])
                if service is not None:
                    value = service['tcp-portrange']
                    portRange = attrs['tcp-portrange']
                    if portRange in value:
                        add = False
                    else:
                        value.append(portRange)
                        attrs['tcp-portrange'] = value
                        attrs['method'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['tcp-portrange'] = socket + ':0'
                if rule.get_expanded_data() is not None and rule.get_expanded_data() != '':
                    ipAddress = rule.get_formatted_address(rule.to_ip_address(
                        rule.get_expanded_data()), rule.get_expanded_mask())
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
                            ipRange = rule.to_ip_address(subnet + 1) + '-' + \
                                      rule.to_ip_address((subnet + hosts) - 2)
                    else:
                        ipRange = ipAddress

                    if ipRange != '':
                        attrs['iprange'] = ipRange

                attrs['name'] = name

                add = True
                service = self.get_custom_service(attrs['name'])
                if service is not None:
                    value = service['tcp-portrange']
                    portRange = attrs['tcp-portrange']
                    if portRange in value:
                        add = False
                    else:
                        value.append(portRange)
                        attrs['tcp-portrange'] = value
                        attrs['method'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.policy == ExtremeManagementPolicyDef.POLICY_IP_TTL:
            end = rule.get_mask()
            if end is not None and end != '' and int(end) > 0:
                difference = end - int(rule.get_data())
                for i in range(0, difference + 1):
                    attrs = {}
                    ttl = rule.get_data() + i
                    attrs['session-ttl'] = ttl
                    attrs['name'] = name + ' TTL: ' + str(ttl)

                    #service = self.get_custom_service(attrs['name'])
                    #service = self.get_custom_service(attrs['name'])
                    #if service is None:
                    #    requests.append(attrs)
            else:
                attrs = {}
                attrs['session-ttl'] = rule.get_data()
                attrs['name'] = name

                #service = self.get_custom_service(attrs['name'])
                #if service is None:
                #    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP_TYPE_CODE:
            data = rule.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            attrs = {}
            attrs['protocol'] = 'ICMP'
            attrs['icmptype'] = type
            attrs['icmpcode'] = code
            attrs['name'] = name

            service = self.get_custom_service(attrs['name'])
            if service is None:
                requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP_TYPE:
            end = rule.get_mask()
            if end is not None and end != '' and int(end) > 0:
                difference = end - int(rule.get_data())
                for i in range(0, difference + 1):
                    attrs = {}
                    protocol = rule.get_data() + i
                    attrs['protocol'] = 'IP'
                    attrs['protocol-number'] = protocol
                    attrs['name'] = name + ' protocol: ' + str(protocol)

                    service = self.get_custom_service(attrs['name'])
                    if service is None:
                        requests.append(attrs)
            else:
                attrs = {}
                protocol = rule.get_data()
                attrs['protocol'] = 'IP'
                attrs['protocol-number'] = protocol
                attrs['name'] = name

                service = self.get_custom_service(attrs['name'])
                if service is None:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP6_TYPE_CODE:
            data = rule.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            attrs = {}
            attrs['protocol'] = 'ICMP6'
            attrs['icmptype'] = type
            attrs['icmpcode'] = code
            attrs['name'] = name

            service = self.get_custom_service(attrs['name'])
            if service is None:
                requests.append(attrs)

        status = False
        if len(requests) > 0:
            status = True
            for request in requests:
                method = 'add'
                if 'method' in request:
                    method = request.pop('method')

                session = self.get_session_id()
                id = self.get_random_id()
                request['category'] = category
                request['color'] = 21
                request['comment'] = rule.get_name()
                data = {'params': [{'url': 'pm/config/adom/root/obj/firewall/service/custom',
                                    'data': [request]}],
                        'session': session, 'id': id, 'method': method}

                content = self.post(data)
                if content is not None:
                    if 'result' in content:
                        response = json.loads(content)
                        result = response['result']
                        if 'status' in result[0]:
                            status = result[0]['status']
                            code = status['code']
                            if code != 0:
                                print 'Error {0} -> {1}'.format(code, result[0])

            if install:
                self.install_policy_package_on_all()

        return status

    def get_policies(self, package):
        policies = None
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {'params': [{'url': url}], 'session': session, 'id': id, 'method': 'get'}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            policies = data['data']
        return policies
    
    def create_deny_policy(self, package, name, srcAddressGroup, srcInterface, dstAddressGroup,
                           dstInterface, comments, services, install=False):
        return self.create_policy(package, 'deny', name, srcAddressGroup, srcInterface,
                                  dstAddressGroup, dstInterface, comments, services, 'enable', install)

    def create_accept_policy(self, package, name, srcAddressGroup, srcInterface, dstAddressGroup,
                             dstInterface, comments, services, install=False):
        return self.create_policy(package, 'accept', name, srcAddressGroup, srcInterface,
                                  dstAddressGroup, dstInterface, comments, services, 'enable', install)

    def create_policy(self, package, name, action, srcAddressGroup, srcInterface,
                      dstAddressGroup, dstInterface, comments, services, status, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {'params': [{'url': url,
                            'data': [{'action': action, 'comments': comments,
                                      'dstaddr': dstAddressGroup,
                                      'dstintf': dstInterface,
                                      'name': name,
                                      'ippool': 'enable',
                                      'logtraffic': 'disable',
                                      'nat': 'disable',
                                      'schedule': ['always'],
                                      'service': services,
                                      'srcaddr': srcAddressGroup,
                                      'srcintf': srcInterface,
                                      'status': status}]}],
                'session': session, 'id': id, 'method': 'add'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def set_policy_services(self, package, policyId, services, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {'params': [{'url': url,
                            'data': [{'policyid': policyId,
                                      'service': services}]}],
                'session': session, 'id': id, 'method': 'update'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def set_policy_status(self, package, policyId, status, install=False):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {'params': [{'url': url,
                            'data': [{'policyid': policyId,
                                      'status': status}]}],
                'session': session, 'id': id, 'method': 'update'}
        status = self.post(data)
        if install:
            self.install_policy_package_on_all()
        return status

    def get_profile_rules_by_action(self, profile, action):
        policies = list()
        rules = profile.get_rules()
        for rule in rules:
            if rule.get_vid() == action:
                policies.append(rule)
        return policies

    def get_matching_services(self, services, comment):
        matches = list()
        for service in services:
            if 'comment' in service:
                c = service['comment']
                if comment in c:
                    matches.append(service['name'])
        return matches

    def create_all_firewall_rules(self, profiles, install=False):
        if profiles is not None:
            for profile in profiles:
                self.create_firewall_rules(profile, install)
            if install:
                self.install_policy_package_on_all()

    def create_firewall_rules(self, profile, install=False):
        return_value = None
        update = False
        if profile is not None:
            packages = self.get_policy_packages()

            if packages is not None:
                for package in packages:
                    packageName = package['name']

                    if packageName is not None:
                        policies = self.get_policies(packageName)

                        rules = profile.get_rules()
                        for rule in rules:
                            if self.add_custom_service(rule):
                                update = True

                        if self.add_group_if_needed(profile.get_name()):
                            update = True
                        profileName = self.get_name(profile.get_name())

                        acceptPolicy = None
                        denyPolicy = None

                        if policies is not None:
                            for policy in policies:
                                label = policy['name']
                                if label ==  profileName + ' (Accept)':
                                    acceptPolicy = policy
                                elif label ==  profileName + ' (Deny)':
                                    denyPolicy = policy

                        if acceptPolicy is None or denyPolicy is None:
                            update = True
                            vid = profile.get_vid()
                            if vid == ExtremeManagementPolicyDef.ACTION_PERMIT:
                                if denyPolicy is None:
                                    response = self.create_policy(packageName, profileName + ' (Deny)', 'deny', [profileName], ['any'], ['all'], ['any'], profile.get_name(), ['ALL'], 'disable')
                                    if self.DEBUG:
                                        print '{0} -> {1}'.format(profileName + ' (Deny)', response)
                                if acceptPolicy is None:
                                    response = self.create_policy(packageName, profileName + ' (Accept)', 'accept', [profileName], ['any'], ['all'], ['any'], profile.get_name(), ['ALL'], 'enable')
                                    if self.DEBUG:
                                        print '{0} -> {1}'.format(profileName + ' (Accept)', response)
                            elif vid == ExtremeManagementPolicyDef.ACTION_DROP:
                                if acceptPolicy is None:
                                    response = self.create_policy(packageName, profileName + ' (Accept)', 'accept', [profileName], ['any'], ['all'], ['any'], profile.get_name(), ['ALL'], 'disable')
                                    if self.DEBUG:
                                        print '{0} -> {1}'.format(profileName + ' (Accept)', response)
                                if denyPolicy is None:
                                    response = self.create_policy(packageName, profileName + ' (Deny)', 'deny', [profileName], ['any'], ['all'], ['any'], profile.get_name(), ['ALL'], 'enable')
                                    if self.DEBUG:
                                        print '{0} -> {1}'.format(profileName + ' (Deny)', response)
                            policies = self.get_policies(packageName)
                            if policies is not None:
                                for policy in policies:
                                    label = policy['name']
                                    if label == profileName + ' (Accept)':
                                        acceptPolicy = policy
                                    elif label == profileName + ' (Deny)':
                                        denyPolicy = policy

                        services = self.get_custom_services()

                        vid = profile.get_vid()
                        if vid == ExtremeManagementPolicyDef.ACTION_PERMIT or vid == ExtremeManagementPolicyDef.ACTION_DROP:
                            acceptServices = acceptPolicy['service']
                            acceptPolicyId = acceptPolicy['policyid']
                            denyServices = denyPolicy['service']
                            denyPolicyId = denyPolicy['policyid']

                            if acceptPolicyId >= 0:
                                acceptRules = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_PERMIT)
                                status = 'disable'
                                updateServices = False
                                for acceptRule in acceptRules:
                                    name = acceptRule.get_name()
                                    matches = self.get_matching_services(services, name)
                                    if len(matches) > 0:
                                        if 'ALL' in acceptServices:
                                            acceptServices.remove('ALL')
                                            updateServices = True
                                        for match in matches:
                                            if match not in acceptServices:
                                                acceptServices.append(match)
                                                updateServices = True
                                        status = 'enable'

                                if updateServices:
                                    update = True
                                    return_value = self.set_policy_services(packageName, acceptPolicyId, acceptServices)
                                    if vid == ExtremeManagementPolicyDef.ACTION_DROP:
                                        return_value = self.set_policy_status(packageName, acceptPolicyId, status)
                                else:
                                    return_value = json.dumps({"result": [{"status": {"code": 0, "message": "Services is already updated"}}]})
                            else:
                                print 'Error, unable to find policy rule: {0}'.format(profileName + ' (Accept)')
                                return_value = json.dumps({"result": [{"status": {"code": 0, "message": "Unable to find policy rule"}}]})

                            if denyPolicyId >= 0:
                                denyRules = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_DROP)
                                status = 'disable'
                                updateServices = False
                                for denyRule in denyRules:
                                    name = denyRule.get_name()
                                    matches = self.get_matching_services(services, name)
                                    if len(matches) > 0:
                                        if 'ALL' in denyServices:
                                            denyServices.remove('ALL')
                                        for match in matches:
                                            if match not in denyServices:
                                                denyServices.append(match)
                                                updateServices = True
                                        status = 'enable'

                                if updateServices:
                                    update = True
                                    return_value = self.set_policy_services(packageName, denyPolicyId, denyServices)
                                    if vid == ExtremeManagementPolicyDef.ACTION_PERMIT:
                                        return_value = self.set_policy_status(packageName, denyPolicyId, status)
                            else:
                                print 'Error, unable to find policy rule: {0}'.format(profileName + ' (Deny)')
                                return_value = json.dumps({"result": [{"status": {"code": 0, "message": "Unable to find policy rule"}}]})
            else:
                return_value = json.dumps({"result": [{"status": {"code": 1, "message": "Package is None"}}]})
        else:
            return_value = json.dumps({"result": [{"status": {"code": 1, "message": "Profile is None"}}]})

        if update and install:
            if self.DEBUG:
                print 'Installing policy package on FortiGate(s)'
            self.install_policy_package_on_all()

        return return_value
        
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
                                status = self.create_firewall_rules(profile, install)
                                break;
         
        return status
