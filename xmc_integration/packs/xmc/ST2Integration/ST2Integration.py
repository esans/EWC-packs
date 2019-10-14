#!/usr/bin/env python

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

import sys
import logging

from ST2WebhookUtils import ST2WebhookUtils
from CommonUtils import CommonUtils


class ST2Integration():

    """
        Master ST2 XMC Integration module.
    """

    def __init__(self):
        self.utils = CommonUtils()
        self.payload = {}
        self.action = None

        self.logger = self.set_logger()
        self.logger.debug(" ########### Entering ST2 XMC Integration Main Module ##########")

    def set_logger(self):
        name = "ST2Integration"
        log_format = '%(asctime)s  %(name)8s  %(levelname)5s  %(message)s'
        logging.basicConfig(level=logging.DEBUG, format=log_format,
                            filename=self.utils.get_logfile(), filemode='a')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter(log_format))
        logging.getLogger(name).addHandler(console)

        return logging.getLogger(name)

    def call_st2webhook(self):
        api = ST2WebhookUtils(self.action)
        response = api.post(self.payload)

        self.logger.debug(response)

    def build_palyload(self, params):
        input_len = len(params)

        if input_len >= 2:
            for i in range(0, input_len):
                self.logger.debug("Input param " + params[i])
                param = params[i].split("=")

                if param[0] == "action":
                    self.action = param[1]
                elif param[0] == "message":
                    param0_len = len(param[0])
                    msg_str = params[i][param0_len + 1:]
                    msg_len = len(msg_str)
                    if msg_str[0] == "\"" and msg_str[msg_len - 1] == "\"":
                        msg_str = msg_str[1:msg_len-1]
                        self.payload["message"] = msg_str
                    # this part should be removed. only for demo
                    else:
                        self.payload[param[0]] = msg_str
                else:
                    # this part should be removed. only for demo
                    self.payload[param[0]] = param[1]
                i = i + 1

            self.logger.debug( "action=" + self.action)
            for k,v in self.payload.iteritems():
                self.logger.debug("Payload info " +  k + ": " + v )
        else:
            self.logger.debug("At least two params are required")

if __name__ == "__main__":
    params = sys.argv[1:len(sys.argv)]

    integration = ST2Integration()
    integration.build_palyload(params)
    integration.call_st2webhook()
