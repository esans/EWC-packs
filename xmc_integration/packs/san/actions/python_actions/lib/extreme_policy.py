import json

class ExtremeManagementPolicyDef(object):
    # Classification rule types from the ctPriClassifyDataMeaning MIB.  GraphQL returns
    # these values in trafDesc object.

    NO_CLASS = 0
    ETHER_TYPE = 1
    LLC_DSAP_SSAP = 2
    IP_TYPE_OF_SERVICE = 3
    IP_PROTOCOL_TYPE = 4
    IPX_CLASS_OF_SERVICE = 5
    IPX_PACKET_TYPE = 6
    IP_ADDRESS_SOURCE = 7
    IP_ADDRESS_DESTINATION = 8
    IP_ADDRESS_BILATERAL = 9
    IPX_NETWORK_SOURCE = 10
    IPX_NETWORK_DESTINATION = 11
    IPX_NETWORK_BILATERAL = 12
    IP_UDP_PORT_SOURCE = 13
    IP_UDP_PORT_DESTINATION = 14
    IP_UDP_PORT_BILATERAL = 15
    IP_TCP_PORT_SOURCE = 16
    IP_TCP_PORT_DESTINATION = 17
    IP_TCP_PORT_BILATERAL = 18
    IPX_SOCKET_SOURCE = 19
    IPX_SOCKET_DESTINATION = 20
    IPX_SOCKET_BILATERAL = 21
    MAC_ADDRESS_SOURCE = 22
    MAC_ADDRESS_DESTINATION = 23
    MAC_ADDRESS_BILATERAL = 24
    IP_FRAGMENT = 25

    # Additional classification types that are used by GraphQL.

    IP_UDP_PORT_SOURCE_RANGE = 26
    IP_UDP_PORT_DESTINATION_RANGE = 27
    IP_UDP_PORT_BILATERAL_RANGE = 28
    IP_TCP_PORT_SOURCE_RANGE = 29
    IP_TCP_PORT_DESTINATION_RANGE = 30
    IP_TCP_PORT_BILATERAL_RANGE = 31
    ICMP_TYPE = 32
    VLAN_ID = 33
    TCI = 34
    IP_ADDRESS_SOURCE_BEST_MATCH = 35
    IP_ADDRESS_DESTINATION_BEST_MATCH = 36
    IP_SOCKET_SOURCE = 37
    IP_SOCKET_DESTINATION = 38
    IP_SOCKET_BILATERAL = 39
    IPV6_ADDRESS_SOURCE = 43
    IPV6_ADDRESS_DESTINATION = 44
    IPV6_ADDRESS_BILATERAL = 45
    IPV6_SOCKET_SOURCE = 46
    IPV6_SOCKET_DESTINATION = 47
    IPV6_SOCKET_BILATERAL = 48
    ICMP6_TYPE = 49
    IPV6_FLOW_LABEL = 50
    TTL = 51
    APPLICATION = 52
    BRIDGE_PORT = 99

    # Policy rule types from the etsysPolicyRuleType MIB.

    POLICY_MAC_SOURCE = 1
    POLICY_MAC_DESTINATION = 2
    POLICY_IPX_SOURCE = 3
    POLICY_IPX_DESTINATION = 4
    POLICY_IPX_SOURCE_PORT = 5
    POLICY_IPX_DESTINATION_PORT = 6
    POLICY_IPX_COS = 7
    POLICY_IPX_TYPE = 8
    POLICY_IP6_SOURCE = 9
    POLICY_IP6_DESTINATION = 10
    POLICY_IP6_FLOW_LABEL = 11
    POLICY_IP4_SOURCE = 12
    POLICY_IP4_DESTINATION = 13
    POLICY_IP_FRAGMENT = 14
    POLICY_UDP_SOURCE_PORT = 15
    POLICY_UDP_DESTINATION_PORT = 16
    POLICY_TCP_SOURCE_PORT = 17
    POLICY_TCP_DESTINATION_PORT = 18
    POLICY_ICMP_TYPE_CODE = 19
    POLICY_IP_TTL = 20
    POLICY_IP_TOS = 21
    POLICY_IP_TYPE = 22
    POLICY_ICMP6_TYPE_CODE = 23
    POLICY_ETHER_TYPE = 25
    POLICY_LLC_DSAP_SSAP = 26
    POLICY_VLAN_ID = 27
    POLICY_IEEE_8021D_TCI = 28
    POLICY_APPLICATION = 29
    POLICY_ACL = 30
    POLICY_BRIDGE_PORT = 31

    BILATERAL_CREATE_TWO_RULES = 100  # Special condition to create a source and destination rule.
    # Special condition to create a source and destination rule#  for TCP and UDP.
    BILATERAL_CREATE_FOUR_RULES = 200

    MAPPING = {
        ETHER_TYPE: POLICY_ETHER_TYPE,
        LLC_DSAP_SSAP: POLICY_LLC_DSAP_SSAP,
        IP_TYPE_OF_SERVICE: POLICY_IP_TOS,
        IP_PROTOCOL_TYPE: POLICY_IP_TYPE,
        IPX_CLASS_OF_SERVICE: POLICY_IPX_COS,
        IPX_PACKET_TYPE: POLICY_IPX_TYPE,
        IP_ADDRESS_SOURCE: POLICY_IP4_SOURCE,
        IP_ADDRESS_DESTINATION: POLICY_IP4_DESTINATION,
        IPX_NETWORK_SOURCE: POLICY_IPX_SOURCE,
        IPX_NETWORK_DESTINATION: POLICY_IPX_DESTINATION,
        IP_UDP_PORT_SOURCE: POLICY_UDP_SOURCE_PORT,
        IP_UDP_PORT_DESTINATION: POLICY_UDP_DESTINATION_PORT,
        IP_TCP_PORT_SOURCE: POLICY_TCP_SOURCE_PORT,
        IP_TCP_PORT_DESTINATION: POLICY_TCP_DESTINATION_PORT,
        IPX_SOCKET_SOURCE: POLICY_IPX_SOURCE_PORT,
        IPX_SOCKET_DESTINATION: POLICY_IPX_DESTINATION_PORT,
        MAC_ADDRESS_SOURCE: POLICY_MAC_SOURCE,
        MAC_ADDRESS_DESTINATION: POLICY_MAC_DESTINATION,
        IP_FRAGMENT: POLICY_IP_FRAGMENT,
        IP_UDP_PORT_SOURCE_RANGE: POLICY_UDP_SOURCE_PORT,
        IP_UDP_PORT_DESTINATION_RANGE: POLICY_UDP_DESTINATION_PORT,
        IP_TCP_PORT_SOURCE_RANGE: POLICY_TCP_SOURCE_PORT,
        IP_TCP_PORT_DESTINATION_RANGE: POLICY_TCP_DESTINATION_PORT,
        ICMP_TYPE: POLICY_ICMP_TYPE_CODE,
        VLAN_ID: POLICY_VLAN_ID,
        TCI: POLICY_IEEE_8021D_TCI,
        IP_ADDRESS_SOURCE_BEST_MATCH: POLICY_IP4_SOURCE,
        IP_ADDRESS_DESTINATION_BEST_MATCH: POLICY_IP4_DESTINATION,
        IPV6_ADDRESS_SOURCE: POLICY_IP6_SOURCE,
        IPV6_ADDRESS_DESTINATION: POLICY_IP6_DESTINATION,
        IPV6_SOCKET_SOURCE: POLICY_IP6_SOURCE,
        IPV6_SOCKET_DESTINATION: POLICY_IP6_DESTINATION,
        ICMP6_TYPE: POLICY_ICMP6_TYPE_CODE,
        IPV6_FLOW_LABEL: POLICY_IP6_FLOW_LABEL,
        TTL: POLICY_IP_TTL,
        APPLICATION: POLICY_APPLICATION,
        BRIDGE_PORT: POLICY_BRIDGE_PORT,

        # Special ExtremeManagement conversion cases where a source and destination policy
        # rules need to be created.

        IP_SOCKET_SOURCE: BILATERAL_CREATE_TWO_RULES,
        IP_SOCKET_DESTINATION: BILATERAL_CREATE_TWO_RULES,
        IP_ADDRESS_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IPX_NETWORK_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        MAC_ADDRESS_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IP_UDP_PORT_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IP_TCP_PORT_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IPX_SOCKET_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IP_UDP_PORT_BILATERAL_RANGE: BILATERAL_CREATE_TWO_RULES,
        IP_TCP_PORT_BILATERAL_RANGE: BILATERAL_CREATE_TWO_RULES,
        IP_SOCKET_BILATERAL: BILATERAL_CREATE_FOUR_RULES,
        IPV6_ADDRESS_BILATERAL: BILATERAL_CREATE_TWO_RULES,
        IPV6_SOCKET_BILATERAL: BILATERAL_CREATE_TWO_RULES,
    }

    ACTION_NOT_DEFINED = -1
    ACTION_DROP = 0
    ACTION_PERMIT = 4095
    ACTION_PRECEDENCE = ACTION_PERMIT

    def __init__(self):
        self.precedence = range(1, 32)
        self.granular = (ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT,
                         ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT,
                         ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT,
                         ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT)

    def get_policy_rule_precedence(self):
        return self.precedence

    def get_granular_precedence(self):
        return self.granular

    def get_policy_type(self, classification):
        type = self.NO_CLASS
        if classification in self.MAPPING:
            type = self.MAPPING[classification]
        return type


class ExtremePolicyProfile(object):
    def __init__(self, name, vid):
        self.name = name
        self.vid = vid
        self.rules = list()
        self.groups = list()
        self.services = list()

    def get_name(self):
        return self.name

    def get_vid(self):
        return self.vid

    def add_rule(self, rule):
        self.rules.append(rule)

    def get_rules(self):
        return self.rules

    def set_rules(self, rules):
        self.rules = rules

    def to_string(self):
        return 'profile: {0}, action: {1}'.format(self.name, self.vid)

    def get_service_groups(self):
        return self.groups

    def add_service_group(self, group):
        if group not in self.groups:
            self.groups.append(group)

    def get_services(self):
        return self.services

    def add_service(self, service):
        if service not in self.services:
            self.services.append(service)


class ExtremePolicyRule(object):
    def __init__(self, name, rule, vid=0, cos=-1, enabled=True):
        self.name = name
        self.rule = rule
        self.classification = ExtremeManagementPolicyDef.NO_CLASS
        self.mask = None
        self.value = None
        self.expandedMask = None
        self.expandedValue = None
        self.ipv6Address = None

        if type(self.rule).__name__ == 'dict':
            if 'trafDesc' in rule:
                self.classification = rule['trafDesc']
            if 'trafDescMask' in rule:
                self.mask = rule['trafDescMask']
            if 'trafDescValue' in rule:
                self.value = rule['trafDescValue']
            if 'trafDescExpandedMask' in rule:
                self.expandedMask = rule['trafDescExpandedMask']
            if 'trafDescExpandedValue' in rule:
                self.expandedValue = rule['trafDescExpandedValue']
            if 'iPv6Address' in rule:
                self.ipv6Address = rule['iPv6Address']

        self.vid = vid
        self.cos = cos
        self.enabled = enabled
        self.policy = ExtremeManagementPolicyDef.NO_CLASS
        self.ruleId = 0
        self.previousId = 0
        self.precedence = -1
        self.ignore = False

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name

    def get_rule(self):
        return self.rule

    def set_rule(self, rule):
        self.rule = rule

    def get_classification_type(self):
        return self.classification

    def set_classification_type(self, classification):
        self.classification = classification

    def get_data(self):
        return self.value

    def set_data(self, value):
        self.value = value

    def get_mask(self):
        return self.mask

    def set_mask(self, mask):
        self.mask = mask

    def get_expanded_data(self):
        return self.expandedValue

    def set_expanded_data(self, expandedValue):
        self.expandedValue = expandedValue

    def get_expanded_mask(self):
        return self.expandedMask

    def set_expanded_mask(self, expandedMask):
        self.expandedMask = expandedMask

    def get_ipv6_address(self):
        return self.ipv6Address

    def set_ipv6_address(self, ipv6Address):
        self.ipv6Address = ipv6Address

    def get_vid(self):
        return self.vid

    def set_vid(self, vid):
        self.vid = vid

    def get_cos(self):
        return self.cos

    def set_cos(self, cos):
        self.cos = cos

    def get_policy_type(self):
        return self.policy

    def set_policy_type(self, policy):
        self.policy = policy

    def get_status(self):
        return self.enabled

    def set_status(self, enabled):
        self.enabled = enabled

    def get_ignore_flag(self):
        return self.ignore

    def set_ignore_flag(self, ignore):
        self.ignore = ignore

    def to_string(self):
        return 'classification: {0}, data: {1}, mask: {2}, expanded value: {3}, ' \
               'expanded mask: {4}, IPv6 address: {5}, vlan: {6}, cos: {7}, ' \
               'policy: {8}'.format(
            self.classification, self.value, self.mask, self.expandedValue, self.expandedMask,
            self.ipv6Address, self.vid, self.cos, self.policy)

    def get_rule_id(self):
        return self.ruleId

    def set_rule_id(self, ruleId):
        self.ruleId = ruleId

    def get_previous_rule_id(self):
        return self.previousId

    def set_previous_rule_id(self, previousId):
        self.previousId = previousId

    def get_port_number(self, port):
        p = port
        if port == 'echo':
            p = '7'
        elif port == 'ftpdata':
            p = '20'
        elif port == 'ftp':
            p = '21'
        elif port == 'ssh':
            p = '22'
        elif port == 'telnet':
            p = '23'
        elif port == 'smtp':
            p = '25'
        elif port == 'domain':
            p = '53'
        elif port == 'dns':
            p = '53'
        elif port == 'dhcp':
            p = '67'
        elif port == 'tftp':
            p = '69'
        elif port == 'http':
            p = '80'
        elif port == 'pop2':
            p = '109'
        elif port == 'pop3':
            p = '110'
        elif port == 'snmp':
            p = '161'
        elif port == 'bgp':
            p = '179'
        elif port == 'ldap':
            p = '389'
        elif port == 'https':
            p = '443'
        return p

    def is_forward_rule(self):
        return self.vid is not None and self.vid == ExtremeManagementPolicyDef.ACTION_PERMIT

    def is_drop_rule(self):
        return self.vid is not None and self.vid == ExtremeManagementPolicyDef.ACTION_DROP

    def is_contain_to_vlan_rule(self):
        return self.vid is not None and self.vid != ExtremeManagementPolicyDef.ACTION_DROP \
               and self.vid != ExtremeManagementPolicyDef.ACTION_PERMIT

    def set_precedence(self, precedence):
        self.precedence = precedence

    def get_precedence(self):
        if self.precedence == -1:
            policyDef = ExtremeManagementPolicyDef()
            p = policyDef.get_policy_rule_precedence()
            self.precedence = p.index(self.policy)
        return self.precedence

    def to_mac_address(self, address):
        macAddress = ''
        for i in range(5, -1, -1):
            mask = 0xFF << (i * 8)
            value = int(address) & mask
            byte = (value >> (i * 8)) & 0xFF
            if macAddress != '':
                macAddress += ':'
            macAddress += '{:x}'.format(byte)
        return macAddress

    def to_ip_address(self, address):
        ipAddress = ''
        for i in range(3, -1, -1):
            mask = 0xFF << (i * 8)
            value = int(address) & mask
            byte = (value >> (i * 8)) & 0xFF
            if ipAddress != '':
                ipAddress += '.'
            ipAddress += str(byte)
        return ipAddress

    def get_host_count(self, mask):
        value = self.ip_to_int(mask)
        hosts = (~value & 0xFFFFFFFF)
        return hosts + 1

    def ip_to_int(self, ipAddress):
        value = 0
        bytes = ipAddress.split('.')
        for i in range(0, 4, 1):
            shift = int(bytes[i]) << ((3 - i) * 8)
            value += shift
        return value

    def get_ip_subnet(self, ipAddress, mask):
        ipToInt = self.ip_to_int(ipAddress)
        subnetToInt = self.ip_to_int(mask)
        return ipToInt & subnetToInt

    def get_formatted_address(self, ipAddress, mask):
        if mask == '' or mask == 0:
            return ipAddress
        else:
            subnet = '';
            if mask <= 32:
                subnet = self.get_formatted_mask(mask)
            else:
                subnet = self.to_ip_address(mask)
            if subnet == '':
                return ipAddress
            else:
                return ipAddress + '/' + subnet

    def get_formatted_mask(self, bits):
        shift = 32 - bits
        mask = (pow(2, bits) - 1) << shift;
        return self.to_ip_address(mask)

    def get_formatted_port(self, start, end):
        port = ''
        if end is not None and end != '' and int(end) > 0:
            port = str(start) + '-' + str(end)
        else:
            port = str(start)
        return port

    def get_rule_description(self):
        description = self.get_traffic_description()
        if description is None:
            description = self.to_string()

        action = 'Forward'
        if self.is_drop_rule():
            action = 'Drop'

        cos = ''
        if self.get_cos() != -1:
            cos = ', cos queue: ' + str(self.get_cos())

        return action + ' ' + description + cos

    def get_traffic_description(self):
        description = None

        if self.policy == ExtremeManagementPolicyDef.POLICY_MAC_SOURCE:
            if self.get_data() is not None:
                macAddress = self.to_mac_address(self.get_data())
                description = 'Source MAC: {0}'.format(macAddress)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_MAC_DESTINATION:
            if self.get_data() is not None:
                macAddress = self.to_mac_address(self.get_data())
                description = 'Destination MAC: {0}'.format(macAddress)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_SOURCE:
            if self.get_data() is not None:
                description = 'IPX source: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_DESTINATION:
            if self.get_data() is not None:
                description = 'IPX destination: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_SOURCE_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'IPX source port: {0}'.format(socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_DESTINATION_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'IPX destination port: {0}'.format(socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_COS:
            if self.get_data() is not None:
                description = 'IPX cos: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IPX_TYPE:
            if self.get_data() is not None:
                description = 'IPX type: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP6_SOURCE:
            if self.get_data() is not None:
                ipAddress = self.get_ipv6_address()
                description = 'Source IPv6: {0}'.format(ipAddress)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP6_DESTINATION:
            if self.get_data() is not None:
                ipAddress = self.get_ipv6_address()
                description = 'Destination IPv6: {0}'.format(ipAddress)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP6_FLOW_LABEL:
            if self.get_data() is not None:
                description = 'IPv6 label: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP4_SOURCE:
            if self.get_data() is not None:
                ipAddress = self.get_formatted_address(self.to_ip_address(self.get_data()),
                                                       self.get_mask())
                description = 'Source IP: {0}'.format(ipAddress)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP4_DESTINATION:
            if self.get_data() is not None:
                ipAddress = self.get_formatted_address(self.to_ip_address(self.get_data()),
                                                       self.get_mask())
                description = 'Destination IP: {0}'.format(ipAddress)

            elif self.policy == ExtremeManagementPolicyDef.POLICY_IP_FRAGMENT:
                description = 'IP fragment'

        elif self.policy == ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'UDP source port: {0}'.format(socket)
                if self.get_expanded_data() is not None and self.get_expanded_data() != '':
                    src = self.get_formatted_address(self.to_ip_address(self.get_expanded_data()),
                                                     self.get_expanded_mask())
                    description = 'Source IP: {0}, UDP source port: {1}'.format(src, socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'UDP destination port: {0}'.format(socket)
                if self.get_expanded_data() is not None and self.get_expanded_data() != '':
                    dst = self.get_formatted_address(self.to_ip_address(self.get_expanded_data()),
                                                     self.get_expanded_mask())
                    description = 'Destination IP: {0}, UDP destination port: {1}'.format(dst,
                                                                                          socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'TCP source port: {0}'.format(socket)
                if self.get_expanded_data() is not None and self.get_expanded_data() != '':
                    src = self.get_formatted_address(self.to_ip_address(self.get_expanded_data()),
                                                     self.get_expanded_mask())
                    description = 'Source IP: {0}, TCP source port: {1}'.format(src, socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT:
            port = self.get_data()
            if port is not None and port != '':
                end = self.get_mask()
                socket = self.get_formatted_port(port, end)
                description = 'TCP destination port: {0}'.format(socket)
                if self.get_expanded_data() is not None and self.get_expanded_data() != '':
                    dst = self.get_formatted_address(self.to_ip_address(self.get_expanded_data()),
                                                     self.get_expanded_mask())
                    description = 'Destination IP: {0}, TCP destination port: {1}'.format(dst,
                                                                                          socket)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_ICMP_TYPE_CODE:
            data = self.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            description = 'ICMP type: {0}, code: {1}'.format(type, code)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP_TTL:
            end = self.get_mask()
            if end is not None and end != '' and int(end) > 0:
                description = 'IP TTL: {0}-{1}'.format(self.get_data(), end)
            else:
                description = 'IP TTL: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP_TOS:
            description = 'IP TOS: {0}'.format(self.get_data())

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IP_TYPE:
            end = self.get_mask()
            if end is not None and end != '' and int(end) > 0:
                description = 'IP type: {0}-{1}'.format(self.get_data(), end)
            else:
                description = 'IP type: {0}'.format(self.get_data(), end)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_ICMP6_TYPE_CODE:
            data = self.get_data()
            type = (data & 0xFF00) >> 8
            code = data & 0xFF
            description = 'ICMP6 type: {0}, code: {1}'.format(type, code)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_ETHER_TYPE:
            data = self.get_data()
            description = 'Ether-Type: {0}'.format(hex(data))

        elif self.policy == ExtremeManagementPolicyDef.POLICY_LLC_DSAP_SSAP:
            data = self.get_data()
            description = 'DSAP/SSAP: {0}'.format(hex(data))

        elif self.policy == ExtremeManagementPolicyDef.POLICY_VLAN_ID:
            data = self.get_data()
            description = 'VLAN ID: {0}'.format(data)

        elif self.policy == ExtremeManagementPolicyDef.POLICY_IEEE_8021D_TCI:
            data = self.get_data()
            description = '802.1D TCI: {0}'.format(data)

        return description


class ExtremePolicy(object):
    def __init__(self):
        self.policyDef = ExtremeManagementPolicyDef()
        self.timeout = 60
        self.debug = False

    # Parse NBI policy rule object.

    def get_service_rules(self, response):
        mappings = {}
        if 'policy' in response:
            policy = response['policy']
            if 'domain' in policy:
                domain = policy['domain']
                if 'PolicyServiceDataList' in domain:
                    services = domain['PolicyServiceDataList']
                    cosList = self.get_policy_cos(response)
                    for service in services:
                        rules = list()
                        name = service['name']
                        ruleList = service['rules']
                        if ruleList is not None:
                            for rule in ruleList:
                                vid = None
                                ruleName = rule['name']
                                vlanAction = rule['policyVlan']
                                if vlanAction is not None:
                                    if 'vid' in vlanAction:
                                        vid = vlanAction['vid']
                                cos = -1
                                cosName = rule['cosName']
                                if cosName is not None:
                                    if cosName in cosList:
                                        cos = cosList[cosName]
                                    else:
                                        print 'Warning, unable to find matching cos {0}' \
                                              ' in the cos list'.format(cosName)
                                enabled = rule['enabled']
                                rules.append(ExtremePolicyRule(ruleName, rule['trafDesc'],
                                                               vid, cos, enabled))
                        mappings[name] = rules;
        return mappings

    # Parse NBI policy service group and find all service group to service associations.

    def get_service_groups(self, response):
        mappings = {}
        if 'policy' in response:
            policy = response['policy']
            if 'domain' in policy:
                domain = policy['domain']
                if 'PolicyServiceGroupDataList' in domain:
                    serviceGroups = domain['PolicyServiceGroupDataList']
                    for serviceGroup in serviceGroups:
                        services = list()
                        name = serviceGroup['name']
                        servicesUsed = serviceGroup['services']
                        for service in servicesUsed:
                            serviceName = service['name']
                            services.append(serviceName)
                        mappings[name] = services;
        return mappings

    # Parse NBI policy profile and all enabled rules.

    def get_policy_profiles(self, response):
        profiles = list()

        if 'policy' in response:
            policy = response['policy']
            if 'domain' in policy:
                domain = policy['domain']

                if 'PolicyRoleList' in domain:
                    services = self.get_service_rules(response)
                    serviceGroups = self.get_service_groups(response)

                    policyProfiles = domain['PolicyRoleList']
                    for policyProfile in policyProfiles:
                        vid = 0
                        if 'policyVlan' in policyProfile:
                            policyVlan = policyProfile['policyVlan']
                            if policyVlan is not None:
                                vid = policyVlan['vid']

                        profile = ExtremePolicyProfile(policyProfile['name'], vid)
                        required = list()

                        servicesUsed = policyProfile['services']
                        for serviceUsed in servicesUsed:
                            name = serviceUsed['name']
                            profile.add_service(name)
                            if name not in required:
                                required.append(name)

                        serviceGroupsUsed = policyProfile['serviceGroups']
                        for serviceGroupUsed in serviceGroupsUsed:
                            name = serviceGroupUsed['name']
                            profile.add_service_group(name)
                            servicesFromGroup = serviceGroups[name]
                            if servicesFromGroup is not None:
                                for serviceFromGroup in servicesFromGroup:
                                    if serviceFromGroup not in required:
                                        required.append(serviceFromGroup)
                            elif self.debug:
                                print 'Services list does not exist for group: {0}'.format(name)

                        for service in required:
                            rules = services[service]
                            if rules is not None:
                                for rule in rules:
                                    profile.add_rule(rule)
                            elif self.debug:
                                print 'Service rules does not exist for service:' \
                                      ' {0}'.format(service)

                        profiles.append(profile)

        for profile in profiles:
            self.set_policy_rule_type(profiles)
            if len(profile.get_rules()) > 0:
                rules = self.get_sorted_rules_by_precedence(profile.get_rules())
                profile.set_rules(rules)


        return profiles

    def get_policy_cos(self, response):
        mapping = {}

        if 'policy' in response:
            policy = response['policy']
            if 'domain' in policy:
                domain = policy['domain']

                if 'PolicyCosList' in domain:
                    cosList = domain['PolicyCosList']
                    for cos in cosList:
                        name = cos['name']
                        priority = cos['dot1pPriority']
                        mapping[name] = priority

        return mapping

    # XMC uses old Cabletron classfication types, rules need to be updated
    # to use the correct policy type.  XMC also has
    # special types i.e. bilateral that needs multiple rules to be created.

    def set_policy_rule_type(self, profiles):
        for profile in profiles:
            rules = profile.get_rules()
            for rule in rules:
                classification = rule.get_classification_type()
                if classification != ExtremeManagementPolicyDef.NO_CLASS:
                    if rule.get_policy_type() == ExtremeManagementPolicyDef.NO_CLASS:
                        policy = self.policyDef.get_policy_type(classification)
                        if policy is not None:
                            rule.set_policy_type(policy)

                            # Special case (bilateral socket) that requires 4 rules to be created.
                            # XMC's interpretation of a socket is a source or destination TCP/UDP
                            # connection. A bilateral socket requires a source TCP, destination
                            # TCP, source UDP, and destination UDP rule.

                            if policy == ExtremeManagementPolicyDef.BILATERAL_CREATE_FOUR_RULES:
                                if classification == ExtremeManagementPolicyDef.IP_SOCKET_BILATERAL:
                                    rule.set_classification_type(
                                        ExtremeManagementPolicyDef.IP_SOCKET_SOURCE)
                                    other = ExtremePolicyRule(rule.get_name(),
                                                              rule.get_rule(), rule.get_vid(),
                                                              rule.get_cos(), rule.get_status())
                                    other.set_classification_type(
                                        ExtremeManagementPolicyDef.IP_SOCKET_DESTINATION)
                                    rules.append(other)
                                    classification = rule.get_classification_type()
                                    policy = self.policyDef.get_policy_type(classification)

                            # Bilateral rule, create a source and destination rule.

                            if policy == ExtremeManagementPolicyDef.BILATERAL_CREATE_TWO_RULES:
                                name = rule.get_name()
                                rule.set_name(name + ' (Src)')
                                other = ExtremePolicyRule(name + ' (Dst)',
                                                          rule.get_rule(), rule.get_vid(),
                                                          rule.get_cos(), rule.get_status())
                                rules.append(other)

                                # XMC socket rule requires TCP and UDP rules.  The socket rule's
                                # data and expanded data are stored in different fields so the
                                # fields are updated to be consistent with the TCP/UDP rules.

                                if classification == ExtremeManagementPolicyDef.IP_SOCKET_SOURCE:
                                    port = rule.get_expanded_data()
                                    end = rule.get_expanded_mask()
                                    ipAddress = rule.get_data()
                                    mask = rule.get_mask()
                                    rule.set_data(port)
                                    rule.set_mask(end)
                                    rule.set_expanded_data(ipAddress)
                                    rule.set_expanded_mask(mask)
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT)
                                    other.set_data(port)
                                    other.set_mask(end)
                                    other.set_expanded_data(ipAddress)
                                    other.set_expanded_mask(mask)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_SOCKET_DESTINATION:
                                    port = rule.get_expanded_data()
                                    end = rule.get_expanded_mask()
                                    ipAddress = rule.get_data()
                                    mask = rule.get_mask()
                                    rule.set_data(port)
                                    rule.set_mask(end)
                                    rule.set_expanded_data(ipAddress)
                                    rule.set_expanded_mask(mask)
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT)
                                    other.set_data(port)
                                    other.set_mask(end)
                                    other.set_expanded_data(ipAddress)
                                    other.set_expanded_mask(mask)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_ADDRESS_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP4_SOURCE)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP4_DESTINATION)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IPX_NETWORK_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IPX_SOURCE)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IPX_DESTINATION)

                                elif classification == \
                                        ExtremeManagementPolicyDef.MAC_ADDRESS_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_MAC_SOURCE)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_MAC_DESTINATION)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_UDP_PORT_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_TCP_PORT_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IPX_SOCKET_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IPX_SOURCE_PORT)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IPX_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_UDP_PORT_BILATERAL_RANGE:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_SOURCE_PORT)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_UDP_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IP_TCP_PORT_BILATERAL_RANGE:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_SOURCE_PORT)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_TCP_DESTINATION_PORT)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IPV6_ADDRESS_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP6_SOURCE)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP6_DESTINATION)

                                elif classification == \
                                        ExtremeManagementPolicyDef.IPV6_SOCKET_BILATERAL:
                                    rule.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP6_SOURCE)
                                    other.set_policy_type(
                                        ExtremeManagementPolicyDef.POLICY_IP6_DESTINATION)

                                else:
                                    if self.debug:
                                        print 'Unable to convert the ' \
                                              'classification rule {0}'.format(classification)
                else:
                    if self.debug:
                        print 'Classification rule {0} is not set'.format(classification)

    # Sort rules by policy precedence.

    def get_sorted_rules_by_precedence(self, rules):
        sorted = list()
        ipAndPort = {}

        precedence = self.policyDef.get_granular_precedence()
        for p in precedence:
            ipAndPortRules = list()
            ipAndPort[p] = ipAndPortRules

            for rule in rules:
                if rule.get_policy_type() == p and rule.get_expanded_data() is not None\
                        and rule.get_expanded_data() != '':
                    if rule.get_status():
                        rule.set_ignore_flag(True)
                        ipAndPortRules.append(rule)

        precedence = self.policyDef.get_policy_rule_precedence()

        # Forwarding precedence is set to permit so order is as follows:
        # Permit
        # Contain to VLAN
        # Drop

        if ExtremeManagementPolicyDef.ACTION_PRECEDENCE == ExtremeManagementPolicyDef.ACTION_PERMIT:
            for p in precedence:
                if p in ipAndPort:
                    ipAndPortRules = ipAndPort[p]
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_forward_rule():
                            sorted.append(ipAndPortRule)
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_contain_to_vlan_rule():
                            sorted.append(ipAndPortRule)
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_drop_rule():
                            sorted.append(ipAndPortRule)

                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_forward_rule():
                            sorted.append(rule)
                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_contain_to_vlan_rule():
                            sorted.append(rule)
                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_drop_rule():
                            sorted.append(rule)

        # Forwarding precedence is set to drop so order is as follows:
        # Drop
        # Permit
        # Contain to VLAN

        else:
            for p in precedence:
                if p in ipAndPort:
                    ipAndPortRules = ipAndPort[p]
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_drop_rule():
                            sorted.append(ipAndPortRule)
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_forward_rule():
                            sorted.append(ipAndPortRule)
                    for ipAndPortRule in ipAndPortRules:
                        if ipAndPortRule.is_contain_to_vlan_rule():
                            sorted.append(ipAndPortRule)

                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_drop_rule():
                            sorted.append(rule)
                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_forward_rule():
                            sorted.append(rule)
                for rule in rules:
                    if rule.get_status() and rule.get_ignore_flag() == False and rule.get_policy_type() == p:
                        if rule.is_contain_to_vlan_rule():
                            sorted.append(rule)

        return sorted
