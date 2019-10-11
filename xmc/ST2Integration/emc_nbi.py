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
import sys
import requests

#
# This class contains the specifics of constructing a ExtremeAPI message and
# returning the results as a json object
class ExtremeNBI(object):

    def __init__(self, ipaddress, username=None, password=None):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.cookie = None
        # construct a URL template for the XMC API
        self.url = 'https://{ip}:8443/nbi/graphql'.format(ip=self.ipaddress)
        self.json_request = {'query' :  None ,'variables' : None}

    def fetch_schema(self,timeout=60):
        #requests.packages.urllib3.disable_warnings()
        response = requests.get(self.url+'/schema.idl',
            auth=(self.username, self.password),
            timeout=timeout,
            verify=False)

        # interpret the response from the EXOS switch
        # first check the HTTP error code to see if HTTP was successful
        # delivering the message
        if response.status_code == requests.codes.ok:
            return response.text

        # raise http exception
        response.raise_for_status()


    def send(self, query, variables=None, timeout=60):
        # http headers
        headers = {'Content-Type': 'application/json'}

        # if we have a cookie from previsous authentication, use it
        if self.cookie is not None:
            headers['Cookie'] = 'session={0}'.format(self.cookie)

        # Extreme API defines query as a graphql string
        self.json_request['query'] = query
        self.json_request['variables'] = variables

        # send the query message to XMC server
        #requests.packages.urllib3.disable_warnings()
        response = requests.post(self.url,
            headers=headers,
            auth=(self.username, self.password),
            data=json.dumps(self.json_request),
            timeout=timeout,
            verify=False)

        # interpret the response from the EXOS switch
        # first check the HTTP error code to see if HTTP was successful
        # delivering the message
        if response.status_code == requests.codes.ok:
            # if we have a cookie, store it so we can use it later
            self.cookie = response.cookies.get('session')
            return json.loads(response.text)

        # raise http exception
        response.raise_for_status()

if __name__  == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-s", "--schema",
                  help="fetch schema IDL", action="store_true")
    parser.add_option("-t", "--timeout",
                  help="HTTP request timeout", action="store", type="int",default=60)
    # parser.add_option("-q", "--query",dest="query",
    #               help="query string", metavar="QUERY" action)

    (options, args) = parser.parse_args()
    if options.schema:
        if len(args) >=2:
            xmc_api = ExtremeNBI(args[0],args[1],args[2])
            print xmc_api.fetch_schema()
        else:
            print "Wrong number of arguments: <IP> <USER> <PASSWD>" 
    elif len(args) >=4:
       xmc_api = ExtremeNBI(args[0],args[1],args[2])
       query = args[3]
       variables = None
       if len(args) >=5:
          variables = args[4]

       #print "Sending: ",query
       response = xmc_api.send(query,variables=variables,timeout=options.timeout)
       print json.dumps(response, indent=4, sort_keys=True)
    else:
       print "Wrong number of arguments: <IP> <USER> <PASSWD> '<QUERY>'" 
