import json
import requests
import time
from extreme_policy import ExtremeManagementPolicyDef

class CheckpointApi(object):
    def __init__(self, checkpoint, username, password, prefix='Extr '):
        self.checkpoint = checkpoint
        self.username = username
        self.password = password
        self.session = None
        self.prefix = prefix
        self.DEBUG = True

    def get_session_id(self):
        if self.session is None:
            data = {'user': self.username, 'password': self.password}
            content = self.post('https://{0}/web_api/login'.format(self.checkpoint), data)
            if content is not None and 'sid' in content:
                response = json.loads(content)
                self.session = response['sid']
        return self.session

    def logout(self):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {}
            status = self.post('https://{0}/web_api/logout'.format(self.checkpoint), data)
        return status

    def add_host(self, host):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': host, 'ip-address': host}
            status = self.post('https://{0}/web_api/add-host'.format(self.checkpoint), data)
        return status

    def get_host(self, host):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': host}
            status = self.post('https://{0}/web_api/show-host'.format(self.checkpoint), data)
        return status

    def delete_host(self, host):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': host}
            status = self.post('https://{0}/web_api/delete-host'.format(self.checkpoint), data)
        return status

    def add_group(self, group, members):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(group), 'members': members}
            status = self.post('https://{0}/web_api/add-group'.format(self.checkpoint), data)
        return status

    def get_group(self, group, exactName=False):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            name = self.get_name(group)
            if exactName:
                name = group
            data = {'name': name}
            status = self.post('https://{0}/web_api/show-group'.format(self.checkpoint), data)
        return status

    def get_groups(self):
        groups = None
        sid = self.get_session_id()
        if sid is not None:
            offset = 0
            limit = 100
            query = True
            while query:
                data = {'limit': limit, 'offset': offset}
                s = self.post('https://{0}/web_api/show-groups'.format(self.checkpoint), data)
                if s is not None and 'objects' in s:
                    if groups is None:
                        groups = list()
                    j = json.loads(s)
                    objects = j['objects']
                    groups.extend(objects)
                    offset += limit
                    total = j['total']
                    if len(groups) == total:
                        query = False
                else:
                    query = False

        return groups

    def set_group(self, group, members, exactName=False):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            name = self.get_name(group)
            if exactName:
                name = group
            data = {'name': name, 'members': members}
            status = self.post('https://{0}/web_api/set-group'.format(self.checkpoint), data)
        return status

    def delete_group(self, group):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(group)}
            status = self.post('https://{0}/web_api/delete-group'.format(self.checkpoint), data)
        return status

    def add_access_rule(self, name, sip, dip, position='top', action='Drop', layer='Network'):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(name), 'source': sip, 'destination': dip, 'position': position, 'action': action, 'layer': layer}
            status = self.post('https://{0}/web_api/add-access-rule'.format(self.checkpoint), data)
        return status

    def set_access_rule_services(self, name, services, layer='Network'):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(name), 'layer': layer, 'service': services}
            status = self.post('https://{0}/web_api/set-access-rule'.format(self.checkpoint), data)
        return status

    def set_access_rule_status(self, name, enabled, layer='Network'):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(name), 'layer': layer, 'enabled': enabled}
            status = self.post('https://{0}/web_api/set-access-rule'.format(self.checkpoint), data)
        return status

    def get_access_rule(self, name, layer='Network'):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(name), 'layer': layer}
            status = self.post('https://{0}/web_api/show-access-rule'.format(self.checkpoint), data)
        return status

    def delete_access_rule(self, name, layer='Network'):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': self.get_name(name), 'layer': layer}
            status = self.post('https://{0}/web_api/delete-access-rule'.format(self.checkpoint), data)
        return status

    def publish(self):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {}
            status = self.post('https://{0}/web_api/publish'.format(self.checkpoint), data)
            if 'task-id' in status:
                task = json.loads(status)
                taskId = task['task-id']
                complete = 0
                while complete < 100:
                    s = self.get_task_status(taskId)
                    if s is not None and 'tasks' in s:
                        response = json.loads(s)
                        tasks = response['tasks']
                        t = tasks[0]
                        complete = t['progress-percentage']
                        if self.DEBUG:
                            print 'Task: {0} progress percentage: {1}'.format(taskId, complete)
                        if complete < 100:
                            time.sleep(1)
                    else:
                        complete = 100
        return status

    def get_task_status(self, id):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'task-id': id}
            status = self.post('https://{0}/web_api/show-task'.format(self.checkpoint), data)
        return status

    # Suspicious Activity Monitoring (SAM)
    """
    def add_sam_rule(self, source, timeout=0, targets=None):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            to = ''
            if timeout > 0:
                to = '-t {0}'.format(str(timeout))
            if targets is None:
                gateways = self.get_gateways()
                if gateways is not None:
                    targets = []
                for gateway in gateways:
                    type = gateway['type']
                    if type == 'simple-gateway':
                        targets.append(gateway['name'])
            script = 'fw sam -v -s {0} -f all {1} -J src {2}'.format(self.checkpoint, to, source)
            data = {'script-name': 'add-sam-rule', 'script': script, 'targets': targets}
            status = self.post('https://{0}/web_api/run-script'.format(self.checkpoint), data)
        return status
    """

    """
    NAME: fw samp add - add a new SAM policy rule
        USAGE:
                fw samp add [-u] [-f <target>] [-t <timeout>] {[-a <d|r|n|b|q|i>]} [-l <r |a>] [-n <name>] [-c <comment>] [-o <originator>] <subcommand>
        OPTIONS:
        -u: user-defined
        -t: expiration timeout (seconds)
        -f: install on target (host or group). default is all
        -a: action: either d/rop, r/eject, n/otify, b/ypass (quota only) or i/nspect
        -l: log: either r/egular or a/lert
        -n: name
        -c: comment
        -o: originator
        SUBCOMMANDS:
        ip: add a rule with IP filter arguments
        quota: add a rule with quota limits
        
        fw samp add -a d -t 300 quota service any source range:10.10.10.10 pkt-rate 0
    """

    def add_samp_rule(self, source, timeout=0, targets=None):
        status = None
        sid = self.get_session_id()
        print 'sid -> {0}'.format(sid)
        if sid is not None:
            to = ''
            if timeout > 0:
                to = '-t {0}'.format(str(timeout))
            if targets is None:
                gateways = self.get_gateways()
                if gateways is not None:
                    targets = []
                for gateway in gateways:
                    type = gateway['type']
                    if type == 'simple-gateway':
                        targets.append(gateway['name'])
            script = 'fw samp add -a d {0} quota service any source range:{1} pkt-rate 0'.format(to, source)

            data = {'script-name': 'add samp rule', 'script': script, 'targets': targets}
            status = self.post('https://{0}/web_api/run-script'.format(self.checkpoint), data)
            if 'tasks' in status:
                response = json.loads(status)
                tasks = response['tasks']
                for task in tasks:
                    taskId = task['task-id']
                    complete = 0
                    while complete < 100:
                        s = self.get_task_status(taskId)
                        if s is not None and 'tasks' in s:
                            response = json.loads(s)
                            tasks = response['tasks']
                            t = tasks[0]
                            complete = t['progress-percentage']
                            if self.DEBUG:
                                print 'Task: {0} progress percentage: {1}'.format(taskId, complete)
                            if complete < 100:
                                time.sleep(1)
                        else:
                            complete = 100
                status = {'message': 'samp rule created to block: {0}'.format(source)}
            else:
                status = {'message': 'samp rule task failed for: {0}'.format(source)}
        return status

    def get_gateways(self):
        gateways = None
        sid = self.get_session_id()
        if sid is not None:
            data = {}
            content = self.post('https://{0}/web_api/show-gateways-and-servers'.format(self.checkpoint), data)
            if content is not None and 'objects' in content:
                response = json.loads(content)
                gateways = response['objects']
        return gateways

    def post(self, url, data):
        content = None
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.session is not None:
            headers['X-chkp-sid'] = self.session
        r = requests.post(url, verify=False, headers=headers, json=data)
        code = r.status_code
        if code == 200:
            content = r.content
        elif code != 404:
            print '{0} -> {1}'.format(str(code), r.content)
        return content

    def add_host_if_needed(self, host):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            address = self.get_host(host)
            if address is None:
                if self.DEBUG:
                    print 'Adding host object: {0}'.format(host)
                status = self.add_host(host)
        return status

    def add_group_if_needed(self, group):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            g = self.get_group(group)
        if g is None:
            if self.DEBUG:
                print 'Adding address group: {0}'.format(group)
            status = self.add_group(group, [])
        return status

    def add_host_to_group(self, host, group, removeFromOtherGroups=True):
        status = None
        publish = False
        sid = self.get_session_id()
        if sid is not None:
            h = self.add_host_if_needed(host)
            if h is not None:
                publish = True
            g = self.add_group_if_needed(group)
            if g is not None:
                publish = True

            g = self.get_group(group)

            response = json.loads(g)
            list = []
            members = response['members']
            for member in members:
                name = member['name']
                list.append(name)

            if host not in list:
                list.append(host)
                if self.DEBUG:
                    print 'Updating address group: {0} with members: {1}'.format(group, list)
                status = self.set_group(group, list)
                publish = True
            else:
                status = {'message': 'threat: {0} already in group'.format(host)}

            if removeFromOtherGroups:
                groups = self.get_groups()
                for g in groups:
                    name = g['name']
                    if name != self.get_name(group):
                        grp = self.get_group(name, True)

                        response = json.loads(grp)
                        list = []
                        members = response['members']
                        for member in members:
                            n = member['name']
                            list.append(n)

                        if host in list:
                            list.remove(host)
                            if self.DEBUG:
                                print 'Updating address group: {0} with members: {1}'.format(name, list)
                            self.set_group(name, list, True)
                            publish = True

            if publish:
                self.publish()
        else:
            status = {'message': 'Unable to generate session ID'}

        return status

    def remove_host_from_group(self, host, group):
        status = None
        sid = self.get_session_id()
        if sid is not None:
            g = self.get_group(group)
            if g is not None:
                response = json.loads(g)
                list = []
                members = response['members']
                for member in members:
                    n = member['name']
                    list.append(n)
                if host in list:
                    list.remove(host)
                    status = self.set_group(group, list)
                    self.delete_host(host)
                    if self.DEBUG:
                        print 'Updating address group: {0} with members: {1}'.format(group, list)
                        print 'Deleted host object: {0}'.format(host)
                    self.publish()
        else:
            status = {'message': 'Unable to generate session ID'}

        return status

    def add_address_to_group(self, address, group, removeFromOtherGroups=False, timeout=900):
        return self.add_samp_rule(address, timeout)

    def remove_address_from_group(self, group, address, exactName=False):
        return {'message', 'Method not supported'}

    def get_name(self, name, removeSpecialCharacters=False):
        if self.prefix != '' and self.prefix in name:
            n = name
        else:
            n = self.prefix + name

        n = n.replace('"', '')

        if removeSpecialCharacters:
            n = n.replace(' ', '_').replace('(', '_').replace(')', '_')
        return n

    def get_all_tcp_services(self):
        return self.get_services('show-services-tcp')

    def get_tcp_service(self, name):
        return self.get_service('show-service-tcp', name)

    def add_tcp_service(self, data):
        return self.modify_service('add-service-tcp', data)

    def set_tcp_service(self, data):
        return self.modify_service('set-service-tcp', data)

    def get_all_udp_services(self):
        return self.get_services('show-services-udp')

    def get_udp_service(self, name):
        return self.get_service('show-service-udp', name)

    def add_udp_service(self, data):
        return self.modify_service('add-service-udp', data)

    def set_udp_service(self, data):
        return self.modify_service('set-service-udp', data)

    def get_all_icmp_services(self):
        return self.get_services('show-services-icmp')

    def get_icmp_service(self, name):
        return self.get_service('show-service-icmp', name)

    def add_icmp_service(self, data):
        return self.modify_service('add-service-icmp', data)

    def set_icmp_service(self, data):
        return self.modify_service('set-service-icmp', data)

    def get_all_icmp6_services(self):
        return self.get_services('show-services-icmp6')

    def get_icmp6_service(self, name):
        return self.get_service('show-service-icmp6', name)

    def add_icmp6_service(self, data):
        return self.modify_service('add-service-icmp6', data)

    def set_icmp6_service(self, data):
        return self.modify_service('set-service-icmp6', data)

    def get_all_other_services(self):
        return self.get_services('show-services-other')

    def get_other_service(self, name):
        return self.get_service('show-service-other', name)

    def add_other_service(self, data):
        return self.modify_service('add-service-other', data)

    def set_other_service(self, data):
        return self.modify_service('set-service-other', data)

    def modify_service(self, syntax, data):
        sid = self.get_session_id()
        if sid is not None:
            url = 'https://{0}/web_api/{1}'.format(self.checkpoint, syntax)
            status = self.post(url, data)
            if self.DEBUG:
                print '{0} -> {1}'.format(url, status)
        return status

    def get_services(self, syntax):
        services = None
        sid = self.get_session_id()
        if sid is not None:
            offset = 0
            limit = 100
            query = True
            while query:
                data = {'limit': limit, 'offset': offset}
                s = self.post('https://{0}/web_api/{1}'.format(self.checkpoint, syntax), data)
                if s is not None and 'objects' in s:
                    if services is None:
                        services = list()
                    j = json.loads(s)
                    objects = j['objects']
                    services.extend(objects)
                    offset += limit
                    total = j['total']
                    if len(services) == total:
                        query = False
                else:
                    query = False
        return services

    def get_service(self, syntax, name):
        service = None
        sid = self.get_session_id()
        if sid is not None:
            data = {'name': name}
            s = self.post('https://{0}/web_api/{1}'.format(self.checkpoint, syntax), data)
            if s is not None:
                service = json.loads(s)
        return service

    def add_service(self, rule):
        if self.DEBUG:
            print 'Rule -> {0}'.format(rule.get_traffic_description())

        publish = False

        requests = list()

        name = ''
        if rule.get_name() is not None and rule.get_name() != '':
            name = self.get_name(rule.get_name(), True)
        else:
            name = self.get_name(rule.get_traffic_description(), True)

        # Other rule match keywords
        # action - Action taken by a security rule
        # blade - Software blade
        # destination - Traffic destination IP address, DNS name or Check Point network object name
        # ipproto - IP Protocol number
        # origin - Name of originating Security Gateway
        # port - Destination TCP/UDP port
        # rule - Security rule that generated the log entry
        # service - Service that generated the log entry
        # source - Traffic source IP address, DNS name or Check Point network object name
        # source_port - Source TCP/UDP port
        # user - User name

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

                    attrs = {}
                    attrs['service'] = 'other'
                    attrs['task'] = 'add'
                    attrs['name'] = name
                    attrs['match'] = 'source: ' + ipRange

                    add = True
                    service = self.get_other_service(attrs['name'])
                    if service is not None:
                        attrs['task'] = 'update'
                        if attrs['match'] in service['match']:
                            add = False

                    if add:
                        requests.append(attrs)

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

                    attrs = {}
                    attrs['service'] = 'other'
                    attrs['task'] = 'add'
                    attrs['name'] = name
                    attrs['match'] = 'destination: ' + ipRange

                    add = True
                    service = self.get_other_service(attrs['name'])
                    if service is not None:
                        attrs['task'] = 'update'
                        if attrs['match'] in service['match']:
                            add = False

                    if add:
                        requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['service'] = 'other'
                attrs['ip-protocol'] = 17
                attrs['match'] = 'source-port: ' + socket
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
                        attrs['match'] = 'source: ' + ipRange + ' and source-port: ' + socket

                attrs['name'] = name

                add = True
                service = self.get_other_service(attrs['name'])
                if service is not None:
                    if attrs['ip-protocol'] == service['ip-protocol'] and attrs['match'] in service['match']:
                        add = False;
                    else:
                        attrs['task'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['service'] = 'udp'
                attrs['port'] = socket
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
                        attrs = {}
                        attrs['service'] = 'other'
                        attrs['ip-protocol'] = 17
                        attrs['match'] = 'destination: ' + ipRange + ' and port: ' + socket

                attrs['name'] = name

                add = True
                if attrs['service'] == 'udp':
                    service = self.get_udp_service(attrs['name'])
                    if service is not None:
                        if attrs['port'] == service['port']:
                            add = False
                        else:
                            attrs['task'] = 'update'
                else:
                    service = self.get_other_service(attrs['name'])
                    if service is not None:
                        if attrs['ip-protocol'] == service['ip-protocol'] and attrs['match'] in service['match']:
                            add = False;
                        else:
                            attrs['task'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['service'] = 'other'
                attrs['ip-protocol'] = 6
                attrs['match'] = 'source-port: ' + socket
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
                        attrs['match'] = 'source: ' + ipRange + ' and source-port: ' + socket

                attrs['name'] = name

                add = True
                service = self.get_other_service(attrs['name'])
                if service is not None:
                    if attrs['ip-protocol'] == service['ip-protocol'] and attrs['match'] in service['match']:
                        add = False;
                    else:
                        attrs['task'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT:
            port = rule.get_data()
            if port is not None and port != '':
                end = rule.get_mask()
                socket = rule.get_formatted_port(port, end)
                attrs = {}
                attrs['service'] = 'tcp'
                attrs['port'] = socket
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
                        attrs = {}
                        attrs['service'] = 'other'
                        attrs['ip-protocol'] = 6
                        attrs['match'] = 'destination: ' + ipRange + ' and port: ' + socket

                attrs['name'] = name

                add = True
                if attrs['service'] == 'tcp':
                    service = self.get_tcp_service(attrs['name'])
                    if service is not None:
                        if attrs['port'] == service['port']:
                            add = False
                        else:
                            attrs['task'] = 'update'
                else:
                    service = self.get_other_service(attrs['name'])
                    if service is not None:
                        if attrs['ip-protocol'] == service['ip-protocol'] and attrs['match'] in service['match']:
                            add = False;
                        else:
                            attrs['task'] = 'update'

                if add:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP_TYPE_CODE:
            data = rule.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            attrs = {}
            attrs['service'] = 'icmp'
            attrs['task'] = 'add'
            attrs['icmp-type'] = type
            attrs['icmp-code'] = code
            attrs['name'] = name

            service = self.get_icmp_service(attrs['name'])
            if service is None:
                requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_IP_TYPE:
            end = rule.get_mask()
            if end is not None and end != '' and int(end) > 0:
                difference = end - int(rule.get_data())
                for i in range(0, difference + 1):
                    attrs = {}
                    protocol = rule.get_data() + i
                    attrs['service'] = 'other'
                    attrs['task'] = 'add'
                    attrs['ip-protocol'] = protocol
                    attrs['name'] = name + '_protocol_' + str(protocol)

                    service = self.get_other_service(attrs['name'])
                    if service is None:
                        requests.append(attrs)
            else:
                attrs = {}
                protocol = rule.get_data()
                attrs['service'] = 'other'
                attrs['task'] = 'add'
                attrs['ip-protocol'] = protocol
                attrs['name'] = name

                service = self.get_other_service(attrs['name'])
                if service is None:
                    requests.append(attrs)

        elif rule.get_policy_type() == ExtremeManagementPolicyDef.POLICY_ICMP6_TYPE_CODE:
            data = rule.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            attrs = {}
            attrs['service'] = 'icmp6'
            attrs['task'] = 'add'
            attrs['icmp-type'] = type
            attrs['icmp-code'] = code
            attrs['name'] = name

            service = self.get_icmp6_service(attrs['name'])
            if service is None:
                requests.append(attrs)

        for request in requests:
            task = 'add'
            if 'task' in request:
                task = request.pop('task')

            if 'service' in request:
                service = request.pop('service')

                request['color'] = 'purple'
                request['comments'] = rule.get_name()

                status = None
                if task == 'add':
                    if service == 'tcp':
                        status = self.add_tcp_service(request)
                    elif service == 'udp':
                        status = self.add_udp_service(request)
                    elif service == 'icmp':
                        status = self.add_icmp_service(request)
                    elif service == 'icmp6':
                        status = self.add_icmp6_service(request)
                    elif service == 'other':
                        status = self.add_other_service(request)
                else:
                    if service == 'tcp':
                        status = self.set_tcp_service(request)
                    elif service == 'udp':
                        status = self.set_udp_service(request)
                    elif service == 'icmp':
                        status = self.set_icmp_service(request)
                    elif service == 'icmp6':
                        status = self.set_icmp6_service(request)
                    elif service == 'other':
                        status = self.set_other_service(request)

                if status is not None:
                    publish = True

        return publish

    def create_firewall_rules(self, profile):
        return {'message', 'Method not supported'}

    def create_access_control_firewall_rules(self, profile):
        if profile is not None:
            vid = profile.get_vid()

            if vid == ExtremeManagementPolicyDef.ACTION_PERMIT or vid == ExtremeManagementPolicyDef.ACTION_DROP:
                rules = profile.get_rules()

                publish = False
                for rule in rules:
                    if self.add_service(rule):
                        publish = True

                self.add_group_if_needed(profile.get_name())

                name = self.get_name(profile.get_name())
                acceptName = name + ' (Accept)'
                acceptRule = self.get_access_rule(acceptName)

                denyName = name + ' (Deny)'
                denyRule = self.get_access_rule(denyName)

                if acceptRule is None or denyRule is None:
                    if vid == ExtremeManagementPolicyDef.ACTION_PERMIT:
                        if acceptRule is None:
                            response = self.add_access_rule(acceptName, name, 'Any', 'top', 'Accept')
                            publish = True
                            if self.DEBUG:
                                print response
                        if denyRule is None:
                            response = self.add_access_rule(denyName, name, 'Any', 'top', 'Drop')
                            self.set_access_rule_status(denyName, False)
                            publish = True
                            if self.DEBUG:
                                print response
                    elif vid == ExtremeManagementPolicyDef.ACTION_DROP:
                        if denyRule is None:
                            response = self.add_access_rule(denyName, name, 'Any', 'top', 'Drop')
                            publish = True
                            if self.DEBUG:
                                print response
                        if acceptRule is None:
                            response = self.add_access_rule(acceptName, name, 'Any', 'top', 'Accept')
                            self.set_access_rule_status(acceptName, False)
                            publish = True
                            if self.DEBUG:
                                print response

                all = self.get_all_services()
                services = list()
                if acceptRule is not None:
                    j = json.loads(acceptRule)
                    cfgServices = j['service']
                    for cfgService in cfgServices:
                        services.append(cfgService['name'])

                accept = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_PERMIT)
                update = False
                for rule in accept:
                    matches = self.get_matching_services(rule, all)
                    if len(matches) > 0:
                        for match in matches:
                            if match not in services:
                                services.append(match)
                                update = True
                if update:
                    enabled = False
                    if len(services) > 0 or vid == ExtremeManagementPolicyDef.ACTION_PERMIT:
                        if len(services) > 0:
                            self.set_access_rule_services(acceptName, services)
                        enabled = True
                        publish = True
                    self.set_access_rule_status(acceptName, enabled)

                services = list()
                if denyRule is not None:
                    j = json.loads(denyRule)
                    cfgServices = j['service']
                    for cfgService in cfgServices:
                        services.append(cfgService['name'])

                deny = self.get_profile_rules_by_action(profile, ExtremeManagementPolicyDef.ACTION_DROP)
                update = False
                for rule in deny:
                    matches = self.get_matching_services(rule, all)
                    if len(matches) > 0:
                        for match in matches:
                            if match not in services:
                                services.append(match)
                                update = True
                if update:
                    enabled = False
                    if len(services) > 0 or vid == ExtremeManagementPolicyDef.ACTION_DROP:
                        if len(services) > 0:
                            self.set_access_rule_services(denyName, services)
                        enabled = True
                        publish = True
                    self.set_access_rule_status(denyName, enabled)

                if publish:
                    self.publish()

    def get_profile_rules_by_action(self, profile, action):
        policies = list()
        rules = profile.get_rules()
        for rule in rules:
            if rule.get_vid() == action:
                policies.append(rule)
        return policies

    def get_all_services(self):
        all = list()
        syntax = ['show-services-tcp', 'show-services-udp', 'show-services-icmp', 'show-services-icmp6', 'show-services-other']
        for s in syntax:
            services = self.get_services(s)
            for service in services:
                n = service['name']
                all.append(n)
        return all

    def get_matching_services(self, rule, services):
        matches = list()
        name = self.get_name(rule.get_name(), True)
        for service in services:
            if name in service:
                matches.append(service)
        return matches
