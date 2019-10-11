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
import logging
import os.path

ST2INTEGRATION_DIR = "/usr/local/Extreme_Networks/NetSight/ST2Integration/"
ST2_WEBHOOK_FILE = ST2INTEGRATION_DIR + "config/st2webhook"
ST2_WEBHOOK_ACTION_FILE = ST2INTEGRATION_DIR + "config/st2webhook_action_list.conf"
ST2_INFO_FILE = ST2INTEGRATION_DIR + "config/.st2info.json"
ST2_LOG_FILE = ST2INTEGRATION_DIR + "log/st2integration.log"


class CommonUtils:

    """
        Common utils for ST2Integration APIs.
    """
    
    def __init__(self):
        self.load_config()

    def load_config(self):
        self.st2info = dict()
        if os.path.isfile(ST2_INFO_FILE):
            json_data=open(ST2_INFO_FILE).read()
            data = json.loads(json_data)
            
            self.st2info['st2ip'] = data["ip"]
            self.st2info['st2api_key'] = data["ST2-Api-Key"]
            self.st2info['xmc_ip'] = data["xmc.ip"]
            self.st2info['xmc_user'] = data["xmc.user"]
            self.st2info['xmc_password'] = data["xmc.password"]
        else:
            print ST2_INFO_FILE + "doesn't exist"

    def get_st2info(self):
        return self.st2info

    def get_logging_handler(self):
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

    def get_logfile(self):
        return ST2_LOG_FILE
        
    def get_webhook_infofile(self):
        return ST2_WEBHOOK_FILE
        
    def get_webhook_action_listfile(self):
        return ST2_WEBHOOK_ACTION_FILE


if __name__ == "__main__":
    utils = CommonUtils()
    st2info = utils.get_st2info()
    if bool(st2info):
        print st2info['st2ip']
        print st2info['st2api_key']
        print st2info['xmc_ip']
        print st2info['xmc_user']
        print st2info['xmc_password']

        print utils.get_logfile()
        print utils.get_webhook_infofile()
        print utils.get_webhook_action_listfile()
