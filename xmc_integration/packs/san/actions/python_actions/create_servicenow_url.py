#!/usr/bin/env python

from lib.firewall_action import BaseAction


class CreateServicenowUrl (BaseAction):
    def run(self, domain_link=None, table=None, sys_id=None):
        link_strs = domain_link.split('/')
        base_url = '{0}//{1}/'.format(link_strs[0], link_strs[2])
        servicenow_url = '{0}nav_to.do?uri={1}.do?sys_id={2}'.format(base_url, table, sys_id)

        return True, {"servicenow_url": servicenow_url}
