# pylint: disable-all (older)
# flake8: noqa
import os.path
import yaml

ST2_CONFIG_FILE = '/etc/st2/st2.conf'

class CommonUtils:

    """A common utils for NBI APIs.
    """

    def __init__(self):
        pass

    def get_st2_base_path(self):
        base_path = '/opt/stackstorm'

        newlines = []
        with open(ST2_CONFIG_FILE, "r") as infile:
            for line in infile.readlines():
                if 'base_path' in line:
                    base_paths = line.split(' ')
                    base_path = base_paths[len(base_paths) - 1]
                    break;

        base_path = base_path.split('\n')[0]
        return base_path

    def load_config_schema(self):
        base_dir = self.get_st2_base_path()

        config_schema_file = '{0}/packs/xmc/config.schema.yaml'.format(base_dir)

        if os.path.isfile(config_schema_file):
            with open(config_schema_file, 'r') as f:
                doc = yaml.load(f)
                xmc_ip = doc['xmc_ip']['default']
                xmc_user = doc['xmc_username']['default']
                st2_api_key = doc['st2_api_key']['default']
                return {'xmcip': xmc_ip, 'xmcuser': xmc_user, 'st2_api_key': st2_api_key}


if __name__ == "__main__":
    utils = CommonUtils()
    return_value = utils.load_config_schema()
    print return_value['xmcip']
    print return_value['xmcuser']
    print return_value['st2_api_key']
