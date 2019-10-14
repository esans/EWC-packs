#!/usr/bin/env python

import json
from st2actions.runners.pythonrunner import Action

from lib.firewall_action import BaseAction

class CreateFirewallActions(BaseAction):
    def run(self, firewall_name=None, threat_ip=None,  policy_name=None, policy_config=None):
        conn = self.establish_connection(firewall_name)        
        if conn is not None:
            type = self.get_type(firewall_name)
            if type is not None:
                if type == 'fortinet':
                    return self.fortinet_create_firewall(conn, threat_ip, policy_name,
                                                         policy_config)
                elif type == 'paloalto':
                    return self.paloalto_create_firewall(conn, threat_ip, policy_name,
                                                         policy_config)
                elif type == 'checkpoint':
                    return self.checkpoint_create_firewall(conn, threat_ip, policy_name,
                                                           policy_config)
                else:
                    return False, json.dumps({"result": [{"status": {"code": 0, "message":
                        "Firewall type is not supported"}}]})
            else:
                return False, json.dumps({"result": [{"status": {"code": 0, "message":
                    "Could not get firewall type"}}]})
        else:
            return False, json.dumps({"result": [{"status": {"code": 0, "message":
                "Could get firewall connection"}}]})

        
    def fortinet_create_firewall(self, conn, threat_ip, policy_name, policy_config):
        status = conn.add_address_to_group(threat_ip, policy_name, True)
        if status is not None:
            data = json.loads(status)['result'][0]
            if data['status']['code'] == 0:
                status = conn.create_firewall_rules_by_policy(policy_name, policy_config)
                if status is not None:
                    data = json.loads(status)['result'][0]
                    if data['status']['code'] == 0:
                        return True, status
                        
        return False, status
       
    def paloalto_create_firewall(self, conn, threat_ip, policy_name, policy_config):
        SUCCESS = 'Message successfully sent'
        
        status = conn.add_address_to_group(threat_ip, policy_name, True)
        if status is not None:
            if status['message'] == SUCCESS:
                status = conn.create_firewall_rules_by_policy(policy_name, policy_config)
                if status is not None:
                    if status['message'] == SUCCESS:
                        return True, status
                    
        return False, status

    def checkpoint_create_firewall(self, conn, threat_ip, policy_name, policy_config):
        SUCCESS = 'samp rule created to block'

        status = conn.add_address_to_group(threat_ip, policy_name, True)
        if status is not None:
            if SUCCESS in status['message']:
                return True, status

        return False, status
