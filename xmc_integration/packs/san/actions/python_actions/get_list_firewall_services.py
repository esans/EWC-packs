#!/usr/bin/env python

from lib.firewall_action import BaseAction


class GetListFirewallServices(BaseAction):
    def run(self):
        conns = list()

        for fw in self.list_fws:
            conns.append(fw)

        return True, {"list_firewall_services": conns}
