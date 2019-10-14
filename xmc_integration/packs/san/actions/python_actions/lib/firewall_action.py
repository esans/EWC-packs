import json
from st2common.runners.base_action import Action

from fortinet_policy import FortinetApi
from palo_alto_api import PaloAltoApi
from checkpoint import CheckpointApi
from st2client.client import Client
from st2client.models import KeyValuePair


CONNECTION_ITEMS = ['ip', 'username', 'password', 'type']
FIREWALLS = 'firewalls'

class BaseAction(Action): 
    def __init__(self, config=None):
        super(BaseAction, self).__init__(config)
        
        if config is None:
            raise ValueError("No connection configuration details found for san")

        if FIREWALLS in config:
            self.client = Client(base_url='http://localhost')
            self.list_fws = config[FIREWALLS]
            if self.list_fws is None:
                raise ValueError(FIREWALLS + " config defined but empty.")
            else:
                pass
        else:
            raise ValueError("No connection configuration details found")
      
    def establish_connection(self, fw_name):
        fw_conn = None

        if fw_name:
            fw_config = self.list_fws.get(fw_name)
            
            for item in CONNECTION_ITEMS:
                if item in fw_config:
                    pass
                else:
                    raise KeyError("san.yaml is missing: firewall:%s:%s"
                                % (fw_config, item))

            key_pair = self.client.keys.get_by_name(name=fw_name, decrypt=True)
            if fw_config is not None:
                try:
                    if fw_config['type'] == 'fortinet':
                        fw_conn = FortinetApi(fortinet=fw_config['ip'], username=fw_config['username'], password=key_pair.value)
                    elif fw_config['type'] == 'paloalto':
                        fw_conn = PaloAltoApi(firewall=fw_config['ip'], username=fw_config['username'], password=key_pair.value)
                    elif fw_config['type'] == 'checkpoint':
                        fw_conn = CheckpointApi(checkpoint=fw_config['ip'], username=fw_config['username'], password=key_pair.value)
                    else:
                        pass
                except Exception as e:
                    raise Exception(e)

        return fw_conn
        
    def get_type(self, fw_name):
        return_value = None
        
        if fw_name:
            fw_config = self.list_fws.get(fw_name)
            if fw_config is not None:
                return_value = fw_config['type']
                
        return return_value
                    

