# san Integration Pack
## Configuration
Copy the example configuration in [san.yaml.example](./san.yaml.example) to 
`/opt/stackstorm/configs/san.yaml` and edit as required.

It must contain:

```
fortinet_ip - Your Fortigate appliance IP address
fortinet_username - Fortigate Firewall Username
fortinet_password - Fortigate Firewall Password
```

You can also use dynamic values from the data store. See the 
[docs](https://docs.stackstorm.com/reference/pack_configs.html) for more info.

Example configuration:

```yaml
---
  fortinet_ip: "10.10.10.10"
  fortinet_username: "admin"
  fortinet_password: "admin"
```

**Note** : When modifying the configuration in `/opt/stackstorm/configs/` please
           remember to tell StackStorm to load these new values by running
           `st2ctl reload --register-configs`

           
## Actions

The following actions are supported:
* ``fortinet_add_address_to_group``
* ``fortinet_create_firewall_rules``
* ``create_firewall_policy``
* ``get_list_firewall_services``
* ``install_policy_package``

## Workflow:

The following Workflow are supported:
* ``create_firewall_policy``
* ``fortinet_firewall_wf``
* ``checkpoint_firewall_wf``
* ``paloalto_firewall_wf``
