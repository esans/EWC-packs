#!/usr/bin/env python


from st2actions.runners.pythonrunner import Action


class ParseDnsMessage(Action):
    def run(self, message=None):
        found_ip = False
        threat_ip = None

        if message is not None:
            threat_ip_str = None
            str_list = message.split(" ")
            for str in str_list:
                if found_ip:
                    threat_ip_str = str
                    found_ip = False
                    break;

                if str =='IP':
                    found_ip = True

            if threat_ip_str is not None and ':' in threat_ip_str:
                found_ip = True
                ip_list = threat_ip_str.split(":")
                threat_ip = ip_list[0] 

        return found_ip, {"threat_ip":threat_ip}

