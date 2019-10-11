"""
Copyright (C) 2017 Extreme Networks. All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
# pylint: disable-all (older)
# flake8: noqa

import json
import requests

from CommonUtils import CommonUtils
#
# This class contains the specifics of constructing a Stackstorm APIs message and
# returning the results as a json object


class ST2ApiUtils:

    """
        REST API Client for Stackstrom CLI and Key managments.
    """

    def __init__(self, ipaddress=None, username=None, password=None):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
                
        if self.ipaddress is not None:
            self.url = "https://" + self.ipaddress
        
        self.utils = CommonUtils()
        
    def get_auth_token(self, timeout=60):
        #requests.packages.urllib3.disable_warnings()
        headers = {'Content-Type': 'application/json'}
        return_response = requests.post(self.url + '/auth/v1/tokens', headers=headers,
                                        auth=(self.username, self.password), data=None, timeout=timeout, verify=False)
 
        if return_response.status_code == requests.codes.created:
            json_str = json.dumps(json.loads(return_response.text))
            resp = json.loads(json_str)
            self.token = resp['token']
            
            return self.token

        # raise http exception
        return_response.raise_for_status()
       
    def generate_api_key(self):
        self.get_auth_token()
       
        #requests.packages.urllib3.disable_warnings()
        headers = self.get_rest_headers()
        headers['X-Auth-Token'] = self.token       
        metadata = '{"metadata": {"used_by": "xmc"}}'
        
        return_response = requests.post(self.url + '/api/v1/apikeys', headers=headers,
                                        auth=(self.username, self.password), data=metadata, timeout=60, verify=False)
 
        if return_response.status_code == requests.codes.created:
            json_str = json.dumps(json.loads(return_response.text))

            resp = json.loads(json_str)
            self.apikey = resp['key']

            return self.apikey

        # raise http exception
        return_response.raise_for_status()

    def get_st2_info(self, pack, query):
        self.st2info = self.utils.get_st2info()
        if bool(self.st2info):
            headers = self.get_rest_headers()
            headers['ST2-Api-Key'] = self.st2info['st2api_key']
  
            #requests.packages.urllib3.disable_warnings()
            self.url = "https://" + self.st2info['st2ip'] + "/api/v1/" + query + '/?pack=' + pack

            return_response = requests.get(self.url, headers=headers, timeout=60, verify=False)
            reture_value = return_response.text
            
            file_name = self.utils.get_webhook_infofile() + "_" + query + ".json"
            with open(file_name, 'w') as outfile:
                outfile.write(reture_value)
            
            return reture_value
        else:
            print "Fail to get StackStorm information"
        
    def create_st2_action_list_v1(self, pack):
        response_return = self.get_st2_info(pack, "rules")
        reture_value = json.loads(response_return)
        with open(self.utils.get_webhook_action_listfile(), 'w') as outfile:
            for query in reture_value:
                action = query["trigger"]["parameters"]["url"]
                outfile.write("[" + action + "] \n")
                # For parameters, Stackstrom pack name and webhook action name, deviceip, message, severity, alarmName and deviceFirmware
                # are mandatory and have to be in sequence.
                # user, password and devicefamily will be queried at runtime

                outfile.write("   " + "pack" + "\n")
                outfile.write("   " + "action" + "\n")
                outfile.write("   " + "deviceip" + "\n")
                outfile.write("   " + "message" + "\n")
                outfile.write("   " + "severity" + "\n")
                outfile.write("   " + "alarmName" + "\n")
                outfile.write("   " + "deviceFirmware" + "\n")
             
                for param in query["action"]["parameters"]:
                    print action + " " + param
                    outfile.write("   " + param + "\n")

    def create_st2_action_list_v2(self, pack):
        response_return = self.get_st2_info(pack, "rules")
        retval = json.loads(response_return)

        with open(self.utils.get_webhook_action_listfile(), 'w') as outfile:
            for query in retval:
                action = query["trigger"]["parameters"]["url"]
                outfile.write("[" + action + "] \n")

                print action
                for param in query["action"]["parameters"]:
                    print " " + param
                    outfile.write("   " + param + "\n")
        
    def get_st2_webhook_action_params(self, pack, action):
        self.st2info = self.utils.get_st2info()
        if bool(self.st2info):
            headers = self.get_rest_headers()
            headers['ST2-Api-Key'] = self.st2info['st2api_key']
               
            #requests.packages.urllib3.disable_warnings()
            self.url = "https://" + self.st2info['st2ip'] + "/api/v1/" + "rules/" + pack + "." + action

            response_return = requests.get(self.url, headers=headers, timeout=60, verify=False)

            if response_return.status_code == requests.codes.ok:
                retval = json.loads(response_return.text)
        
                param_list = []
                index = 0
                if retval != None:
                    for param in retval["action"]["parameters"]:
                        param_list.insert(index, param)
                        index = index + 1
                        print param
                    return param_list

                response_return.raise_for_status()
        else:
            print "Fail to get StackStorm information"
            
    def get_rest_headers(self):
        headers = {
            'Content-Type': 'application/json', 
            'Connection' : 'keep-alive' , 
            'Accept-Encoding' : 'gzip, deflate', 
            'Accept' : '*/*' ,
            'User-Agent': 'python-requests/2.14.2',
        }
        
        return headers
        
if __name__  == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
        
    parser.add_option('-t', "--token", help='Specify the option for generating Stackstorm token', action="store_true")
    parser.add_option("-k", '--apikey', help="Specify the option for generating Stackstorm API key", action="store_true")
    parser.add_option("-i", "--st2info", help="Specify the option for getting Stackstorm information for Rules or actions or packs",action="store_true")
    parser.add_option("-l", "--actionlist", help="Specify the option for getting Stackstorm information for all Webhook actions",action="store_true")
    parser.add_option("-a", "--st2action", help="Specify the option for getting Stackstorm information for a specific  action",action="store_true")
    
    (options, args) = parser.parse_args()

    if options.token:
        if len(args) == 3:
            st2_api = ST2ApiUtils(args[0],args[1],args[2])
            response_return = st2_api.get_auth_token()
            print response_return
        else:
            print "Wrong number of arguments: ST2ApiUtils.py -t <Stackstorm IP> <Stackstorm st2admin USER> <Stackstorm Admin PASSWD>" 
    elif options.apikey:
        if len(args) == 3:
            st2_api = ST2ApiUtils(args[0],args[1],args[2])
            response_return = st2_api.generate_api_key()
            print response_return
        else:
            print "Wrong number of arguments: ST2ApiUtils.py -k <Stackstorm IP> <Stackstorm st2admin USER> <Stackstorm Admin PASSWD>" 
    elif options.st2info:
        if len(args) == 2:
            st2_api = ST2ApiUtils()
            response_return = st2_api.get_st2_info(args[0], args[1])
            print response_return
        else:
            print "Wrong number of arguments: ST2ApiUtils.py -i <PackName> <Query(rules, actions)>" 
    elif options.actionlist:
        if len(args) == 1:
            st2_api = ST2ApiUtils()
            st2_api.create_st2_action_list_v2(args[0])
        else:
            print "Wrong number of arguments: ST2ApiUtils.py -l <PackName>" 
    elif options.st2action:
        if len(args) == 2:
            st2_api = ST2ApiUtils()
            response_return = st2_api.get_st2_webhook_action_params(args[0], args[1])
        else:
            print "Wrong number of arguments: ST2ApiUtils.py -i <PackName> <ActionName)>" 
        
    else:
       print "Wrong number of arguments: ST2ApiUtils.py -<t/k/i> <Stackstorm IP> <Stackstorm st2admin USER> <Stackstorm Admin PASSWD> <PackName> <Query(rules, actions)>"

