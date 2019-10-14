#!/usr/bin/env python


import requests
import json
from st2actions.runners.pythonrunner import Action

from emc_nbi import ExtremeNBI
from CommonUtils import CommonUtils


class GetDeviceInfo(Action):

    """
        XMC NBI client to get device SSH credentail and family.
    """
    def run(self, deviceip, xmckey):
        self.deviceip = deviceip
        self.xmcpassword = xmckey

        self.utils = CommonUtils()
        self.xmcinfo = self.utils.load_config_schema()

        payload = self.query_device_info()

        return (True, payload)

    def query_device_info(self):
        self.query_device_auth()
        device_family = self.query_device_family()
        payload = dict()
        payload['user'] = self.user
        payload['password'] = self.password
        payload['devicefamily'] = device_family

        return payload

    def query_device_auth(self):
        return_value = False

        query = '{administration {deviceProfile(user: '  \
            '"' + self.xmcinfo['xmcuser'] + '"' + ', ip: ' + '"' + self.deviceip + '"'  \
            ') {authCred {userName,loginPassword}}}}'

        resp = self.nbi_call(query)
        if resp['data']["administration"]["deviceProfile"] is not None:
            self.user = resp['data']["administration"]["deviceProfile"]["authCred"]["userName"]
            self.password = resp['data']["administration"]["deviceProfile"]["authCred"]["loginPassword"]
            return_value = True
        else:
            self.user = None
            self.password = None
            self.logger.warning("Failed to query " + self.deviceip + " credential")

        return return_value

    def query_device_family(self):
        query = "{network {device(ip: " + "\"" + self.deviceip + "\"" + ") {deviceDisplayFamily}}}"
        device_family = None

        resp = self.nbi_call(query)
        if resp['data']["network"]["device"] is not None:
            self.logger.debug(resp)
            device_family = resp['data']["network"]["device"]["deviceDisplayFamily"]
        else:
            self.logger.warning("Failed to query " + self.deviceip + " device_family")

        return device_family

    def nbi_call(self, query):
        ExtremeApi = "query ExtremeApi "
        query = ExtremeApi + query

        xmc_api = ExtremeNBI(self.xmcinfo['xmcip'], self.xmcinfo['xmcuser'], self.xmcpassword)
        response = xmc_api.send(query, None, 60)
        json_str = json.dumps(response)
        resp = json.loads(json_str)

        return resp
