#!/usr/bin/env python

import json
from st2actions.runners.pythonrunner import Action

from lib.firewall_action import BaseAction

class RemoveFirewallActions(BaseAction):
    def run(self, firewall_name=None, threat_ip=None,  policy_name=None):
        conn = self.establish_connection(firewall_name)
        if conn is not None:
            type = self.get_type(firewall_name)
            if type is not None:
                if type == 'fortinet':
                    return self.fortinet_remove_firewall(conn, threat_ip, policy_name)
                elif type == 'paloalto':
                    return self.paloalto_remove_firewall(conn, threat_ip, policy_name)
                elif type == 'checkpoint':
                    return self.checkpoint_remove_firewall(conn, threat_ip, policy_name)
                else:
                    return False, json.dumps({"result": [{"status": {"code": 0, "message":
                        "Firewall type is not supported"}}]})
            else:
                return False, json.dumps({"result": [{"status": {"code": 0, "message":
                    "Could not get firewall type"}}]})
        else:
            return False, json.dumps({"result": [{"status": {"code": 0, "message":
                "Could get firewall connection"}}]})

        
    def fortinet_remove_firewall(self, conn, threat_ip, policy_name):
        status = conn.remove_address_from_group(threat_ip, policy_name, True)
        if status is not None:
            data = json.loads(status)['result'][0]
            if data['status']['code'] == 0:
                return True, status
       
        return False, status
       
    def paloalto_remove_firewall(self, conn, threat_ip, policy_name):
        SUCCESS = 'Message successfully sent'
        
        status = conn.remove_address_from_group(policy_name, threat_ip, True)
        if status is not None:
            if status['message'] == SUCCESS:
                return True, status
                    
        return False, status

    def checkpoint_remove_firewall(self, conn, threat_ip, policy_name):                     
        return True, {"message": "The rule will age out"}
