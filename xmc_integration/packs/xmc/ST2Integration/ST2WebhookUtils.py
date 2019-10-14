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

import requests
import json
import socket
import logging

from emc_nbi import ExtremeNBI
from CommonUtils import CommonUtils


class ST2WebhookUtils:

    """
        REST API Client for ST2 Webhook.
    """
    
    def __init__(self, ref):  
        self.utils = CommonUtils()
        self.logger = logging.getLogger("ST2WebhookUtils")
        
        self.st2info = self.utils.get_st2info()
        if bool(self.st2info):
            self.url = "https://" +  self.st2info['st2ip'] + "/api/v1/webhooks/" + ref
            self.headers = {'content-type': 'application/json', 'St2-Api-Key': self.st2info['st2api_key']}
        self.ref = ref
        
        self.logger.debug("Webhook URL: " + self.url)

    def post(self, payload):
        response = requests.post(self.url, data=json.dumps(payload), headers=self.headers, verify=False) 

        return response
    
    def get_xmc_ip(self):
        return ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
        
               
if __name__ == "__main__":
    #util = ST2WebhookUtils(sys.args[1])
    #ret = util.post(sys.args[2], sys.args[3])
    
    util = ST2WebhookUtils("remove_operator_limit_port")
    payload = {"cmd": "show config", "deviceip": "10.177.230.45"}
    ret = util.post(payload)
    print ret
