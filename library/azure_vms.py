#!/usr/bin/python
# -*- coding: utf-8 -*-
__version__ = "0.0.1"
DOCUMENTATION = '''
---
module: azure_vms
short_description: Create Azure VMs
description:
     - This Role allows you to create and delete role assignments
     - *** currently only supports users to be assigned to only resource groups
version_added: "0.0.1"
options:
  user_name:
    description:
      - This is the user name which will be assigned to the scope (e.g. resource group)
      Ths username is passed without the domain part (e.g. test.user)
    required: true
    default: null

  state:
    description:
      - Whether to create or delete an Azure role assignment.
    required: false
    default: present
    choices: [ "present", "absent" ]

  resource_group_name:
    description:
      - The Resource Group name to be set as the role assignment scope.
      This is the object where the above user will be assigned permissions on.
    required: true
    default: null

  client_id:
    description:
      - Azure clientID. If not set then the value of the AZURE_CLIENT_ID environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_id', 'client_id' ]

  client_secret:
    description:
      - Azure Client secret key. If not set then the value of the AZURE_CLIENT_SECRET environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_secret', 'client_secret' ]

  tenant_domain
    description:
      - This is your tenant domain name, usually something.onmicrosoft.com (e.g. AnsibleDomain.onmicrosoft.com)
    required: True
    default: null

  subscription_id:
    description:
      - Your Azure subscription id
    required: true
    default: null
'''.format(__version__)

EXAMPLES = '''
# Basic role assignment creation example
tasks:
- name: Create a new Azure user account
  azure_ad_users:
    user_name            : "ansible.test"
    state                : present
    resource_group_name  : myresourcegroup
    subscription_id      : a07a55g4-9313-4ef8-94f8-e999b3f6f64g
    role_definition_name : Owner
    tenant_domain        : "AnsibleDomain.onmicrosoft.com"
    client_id            : "6359f1g62-6543-6789-124f-398763x98112"
    client_secret        : "HhCDbhsjkuHGiNhe+RE4aQsdjjrdof8cSd/q8F/iEDhx="
'''

class AzureVMs():
    def __init__(self, module):
        self.module = module

        self.virtual_machine_name = self.module.params["virtual_machine_name"]
        self.virtual_machine_name = self.cleanup_chars(self.virtual_machine_name)

        self.virtual_machine_username = self.module.params["virtual_machine_username"]
        self.virtual_machine_username = self.cleanup_chars(self.virtual_machine_username)

        self.virtual_machine_password = self.module.params["virtual_machine_password"]
        self.virtual_machine_size = self.module.params["virtual_machine_size"]
        self.virtual_machine_image_publisher = self.module.params["virtual_machine_image_publisher"]
        self.virtual_machine_image_offer = self.module.params["virtual_machine_image_offer"]
        self.virtual_machine_image_sku = self.module.params["virtual_machine_image_sku"]
        self.virtual_machine_image_version = self.module.params["virtual_machine_image_version"]

        self.virtual_machine_os_disk_name = self.module.params["virtual_machine_os_disk_name"]
        if not self.virtual_machine_os_disk_name:
            self.virtual_machine_os_disk_name = "{}".format(self.virtual_machine_name)
        self.virtual_machine_os_disk_name = self.cleanup_chars(self.virtual_machine_os_disk_name)

        self.virtual_machine_storage_name = self.module.params["virtual_machine_storage_name"]

        self.virtual_machine_customdata = self.module.params["virtual_machine_customdata"]
        if not self.virtual_machine_customdata:
            self.virtual_machine_customdata = "bmV3LWl0ZW0gYzpcZGlyMSAtaXRlbXR5cGUgZGlyZWN0b3J5" #This is a PS script to create a folder in the C drive

        self.virtual_machine_nic = self.module.params["virtual_machine_nic"]
        if not self.virtual_machine_nic:
            self.virtual_machine_nic = "{}".format(self.virtual_machine_name)
        self.virtual_machine_nic = self.cleanup_chars(self.virtual_machine_nic)

        self.security_group = self.module.params["security_group"]
        self.virtual_network_name = self.module.params["virtual_network_name"]
        self.subnet_name = self.module.params["subnet_name"]

        self.public_ip_name = self.module.params["public_ip_name"]
        if not self.public_ip_name:
            self.public_ip_name = "{}".format(self.virtual_machine_name)
        self.public_ip_name = self.cleanup_chars(self.public_ip_name)

        self.public_dns_name = ""

        self.virtual_machine_source_image = self.module.params["virtual_machine_source_image"]

        self.location = self.module.params["location"]
        self.resource_group_name = self.module.params["resource_group_name"]
        self.state = self.module.params["state"]
        self.subscription_id = self.module.params["subscription_id"]
        self.tenant_domain = self.module.params["tenant_domain"]
        self.client_id = self.module.params["client_id"]
        self.client_secret = self.module.params["client_secret"]

        self.graph_url = self.module.params["graph_url"]
        if not self.graph_url:
            self.graph_url = "https://graph.windows.net/{}".format(self.tenant_domain)

        self.management_url = self.module.params["management_url"]
        if not self.management_url:
            self.management_url = "https://management.azure.com/subscriptions/{}".format(self.subscription_id)

        self.login_url  = self.module.params["login_url"]
        if not self.login_url:
            self.login_url = "https://login.windows.net/{}/oauth2/token?api-version=1.0".format(self.tenant_domain)

        # Geting azure cred from ENV if not defined
        if not self.client_id:
            if 'azure_client_id' in os.environ:
                self.client_id = os.environ['azure_client_id']
            elif 'AZURE_CLIENT_ID' in os.environ:
                self.client_id = os.environ['AZURE_CLIENT_ID']
            elif 'client_id' in os.environ:
                self.client_id = os.environ['client_id']
            elif 'CLIENT_ID' in os.environ:
                self.client_id = os.environ['CLIENT_ID']
            else:
                # in case client_id came in as empty string
                self.module.fail_json(msg="Client ID is not defined in module arguments or environment.")

        if not self.client_secret:
            if 'azure_client_secret' in os.environ:
                self.client_secret = os.environ['azure_client_secret']
            elif 'AZURE_CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['AZURE_CLIENT_SECRET']
            elif 'client_secret' in os.environ:
                self.client_secret = os.environ['client_secret']
            elif 'CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['CLIENT_SECRET']
            else:
                # in case secret_key came in as empty string
                self.module.fail_json(msg="Client Secret is not defined in module arguments or environment.")
        self.headers = None
        self.user_headers = None
        self.data = None
        self.azure_version = "api-version=2015-06-15"

    # TODO: might not be needed
    def convert(self, data):
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(self.convert, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(self.convert, data))
        else:
            return data

    def cleanup_chars(self, old_str):
        clean_str = ''.join(e for e in old_str if e.isalnum())
        return clean_str

    def user_id_login(self):
        headers = { 'User-Agent': 'ansible-azure-0.0.1', 'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded' }
        payload = { 'grant_type': 'client_credentials', 'client_id': self.client_id, 'client_secret': self.client_secret }
        payload = urllib.urlencode(payload)

        #print self.login_url
        try:
            r = open_url(self.login_url, method="post", headers=headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            self.module.fail_json(msg="Failed to login error code = '{}' and message = {}".format(response_code, response_msg))

        response_msg = r.read()
        # TODO: Should try and catch if failed to seriolize to json
        token_response = json.loads(response_msg)
        token = token_response.get("access_token", False)
        if not token:
            self.module.fail_json(msg="Failed to extract token type from reply")
        token_type = token_response.get("token_type", 'Bearer')
        self.user_headers = { 'Authorization' : '{} {}'.format(token_type, token),
                         'Accept' : 'application/json', "content-type": "application/json" }

    def vm_login(self):
        headers = { 'User-Agent': 'ansible-azure-0.0.1', 'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded' }
        payload = { 'grant_type': 'client_credentials', 'client_id': self.client_id, 'client_secret': self.client_secret, 'resource': 'https://management.core.windows.net/' }
        payload = urllib.urlencode(payload)

        try:
            r = open_url(self.login_url, method="post", headers=headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            self.module.fail_json(msg="Failed to login error code = '{}' and message = {}".format(response_code, response_msg))

        response_msg = r.read()
        # TODO: Should try and catch if failed to seriolize to json
        token_response = json.loads(response_msg)
        token = token_response.get("access_token", False)
        if not token:
            self.module.fail_json(msg="Failed to extract token type from reply")
        token_type = token_response.get("token_type", 'Bearer')
        self.headers = { 'Authorization' : '{} {}'.format(token_type, token),
                         'Accept' : 'application/json', "content-type": "application/json" }

    def create_vm_from_image(self):
        #https://msdn.microsoft.com/en-us/library/azure/mt163591.aspx
        self.vm_login()
        payload = {
                      "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}".format(self.subscription_id, self.resource_group_name, self.virtual_machine_name),
                      "name":"{}".format(self.virtual_machine_name),
                      "type":"Microsoft.Compute/virtualMachines",
                      "location":"{}".format(self.location),
                      "properties": {
                        "hardwareProfile": {
                          "vmSize":"{}".format(self.virtual_machine_size)
                        },
                        "storageProfile": {
                          #"imageReference": {
                            #"publisher":"{}".format(self.virtual_machine_image_publisher),
                            #"offer":"{}".format(self.virtual_machine_image_offer),
                            #"sku":"{}".format(self.virtual_machine_image_sku),
                            #"version":"{}".format(self.virtual_machine_image_version)
                          #},
                          "osDisk": {
                            "osType": "Windows",
                            "name":"{}".format(self.virtual_machine_os_disk_name),
                            "createOption": "FromImage",
                            "image": {
                              "uri": "{}".format(self.virtual_machine_source_image)
                            },
                            "vhd": {
                              "uri":"http://{}.blob.core.windows.net/vhds/{}.vhd".format(self.virtual_machine_storage_name, self.virtual_machine_os_disk_name)
                            },
                            "caching":"ReadWrite"
                          },
                        },
                        "osProfile": {
                          "computerName":"{}".format(self.virtual_machine_name),
                          "adminUsername":"{}".format(self.virtual_machine_username),
                          "adminPassword":"{}".format(self.virtual_machine_password),
                          "customData":"{}".format(self.virtual_machine_customdata),
                          "windowsConfiguration": {
                            "provisionVMAgent":True,
                            "winRM": {
                              "listeners": [ {
                                "protocol": "http",
                                #"certificateUrl": "{}".format(self.winrm_certificate_url)
                              } ]
                            },
                            #"additionalUnattendContent": {
                            #  "pass":"oobesystem",
                            #  "component":"Microsoft-Windows-Shell-Setup",
                            #  "settingName":"FirstLogonCommands|AutoLogon",
                            #  "content":"<XML unattend content>"
                            #},
                            #"enableAutomaticUpdates":False
                          },
                          #"secrets":[ {
                          #   "sourceVault": {
                          #     "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}".format(self.subscription_id, self.resource_group_name, self.vault_name)
                          #   },
                          #   "vaultCertificates": [ {
                          #     "certificateUrl": "{}".format(self.winrm_certificate_url),
                          #     "certificateStore": "My"
                          #   } ]
                          # } ]
                        },
                        "networkProfile": {
                          "networkInterfaces": [ {
                            "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkInterfaces/{}".format(self.subscription_id, self.resource_group_name, self.virtual_machine_nic)
                          } ]
                        }
                      }
                }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?validating=true&{}".format(self.resource_group_name, self.virtual_machine_name, self.azure_version)
        #print (payload)
        try:
            r = open_url(url, method="put", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "The role assignment already exists" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The role assignment already exists.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to create the role assignment. Error code='{}' msg='{}'".format(response_code, error_msg))
        self.module.exit_json(msg="The VM has been Created.", public_dns_name=self.public_dns_name, changed=True)

    def create_vm(self, image=None):
        #https://msdn.microsoft.com/en-us/library/azure/mt163591.aspx
        self.vm_login()
        payload = {
                      "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}".format(self.subscription_id, self.resource_group_name, self.virtual_machine_name),
                      "name":"{}".format(self.virtual_machine_name),
                      "type":"Microsoft.Compute/virtualMachines",
                      "location":"{}".format(self.location),
                      "properties": {
                        "hardwareProfile": {
                          "vmSize":"{}".format(self.virtual_machine_size)
                        },
                        "storageProfile": {
                          "imageReference": {
                            "publisher":"{}".format(self.virtual_machine_image_publisher),
                            "offer":"{}".format(self.virtual_machine_image_offer),
                            "sku":"{}".format(self.virtual_machine_image_sku),
                            "version":"{}".format(self.virtual_machine_image_version)
                          },
                          "osDisk": {
                            #"osType": "Windows",
                            "name":"{}".format(self.virtual_machine_os_disk_name),
                            "createOption": "FromImage",
                            #"image": {
                            #  "uri": "{}".format(self.virtual_machine_source_image)
                            #},
                            "vhd": {
                              "uri":"http://{}.blob.core.windows.net/vhds/{}.vhd".format(self.virtual_machine_storage_name, self.virtual_machine_os_disk_name)
                            },
                            "caching":"ReadWrite"
                          },
                        },
                        "osProfile": {
                          "computerName":"{}".format(self.virtual_machine_name),
                          "adminUsername":"{}".format(self.virtual_machine_username),
                          "adminPassword":"{}".format(self.virtual_machine_password),
                          "customData":"{}".format(self.virtual_machine_customdata),
                          "windowsConfiguration": {
                            "provisionVMAgent":True,
                            "winRM": {
                              "listeners": [ {
                                "protocol": "http",
                                #"certificateUrl": "{}".format(self.winrm_certificate_url)
                              } ]
                            },
                            #"additionalUnattendContent": {
                            #  "pass":"oobesystem",
                            #  "component":"Microsoft-Windows-Shell-Setup",
                            #  "settingName":"FirstLogonCommands|AutoLogon",
                            #  "content":"<XML unattend content>"
                            #},
                            #"enableAutomaticUpdates":False
                          },
                          #"secrets":[ {
                          #   "sourceVault": {
                          #     "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}".format(self.subscription_id, self.resource_group_name, self.vault_name)
                          #   },
                          #   "vaultCertificates": [ {
                          #     "certificateUrl": "{}".format(self.winrm_certificate_url),
                          #     "certificateStore": "My"
                          #   } ]
                          # } ]
                        },
                        "networkProfile": {
                          "networkInterfaces": [ {
                            "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkInterfaces/{}".format(self.subscription_id, self.resource_group_name, self.virtual_machine_nic)
                          } ]
                        }
                      }
                }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?validating=true&{}".format(self.resource_group_name, self.virtual_machine_name, self.azure_version)
        #print (payload)
        try:
            r = open_url(url, method="put", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "The VM already exists" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The role assignment already exists.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to create the VM. Error code='{}' msg='{}'".format(response_code, error_msg))
        self.module.exit_json(msg="The VM has been Created.", public_dns_name=self.public_dns_name, changed=True)

    def create_public_ip(self):
        #https://msdn.microsoft.com/en-us/library/mt163590.aspx
        self.vm_login()
        payload = {
                   "location": "{}".format(self.location),
                   "properties": {
                      "publicIPAllocationMethod": "Dynamic",
                      "dnsSettings": {
                        "domainNameLabel": "{}".format(self.virtual_machine_name) #,
                        #"reverseFqdn": "contoso.com."
                      }
                   }
                }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses/{}?{}".format(self.resource_group_name, self.public_ip_name, self.azure_version)
        #print (payload)
        try:
            r = open_url(url, method="put", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "already exists" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The Public IP Address already exists.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to create the Public IP Address. Error code='{}' msg='{}'".format(response_code, error_msg))
	out_put = json.loads(r.read())
	self.public_dns_name = out_put.get("properties").get("dnsSettings").get("fqdn")


    def create_nic(self):
        #https://msdn.microsoft.com/en-us/library/mt163668.aspx
        self.vm_login()
        payload = {
                       "location":"{}".format(self.location),
                       "properties":{
                          "networkSecurityGroup":{
                             "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkSecurityGroups/{}".format(self.subscription_id, self.resource_group_name, self.security_group)
                          },
                          "ipConfigurations":[
                             {
                                "name":"{}".format(self.virtual_machine_nic),
                                "properties":{
                                   "subnet":{
                                      "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks/{}/subnets/{}".format(self.subscription_id, self.resource_group_name, self.virtual_network_name, self.subnet_name)
                                   },
                                   "privateIPAllocationMethod":"Dynamic",
                                   "publicIPAddress":{
                                      "id":"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses/{}".format(self.subscription_id, self.resource_group_name, self.public_ip_name)
                                   },
                                }
                             }
                          ],
                       }
                }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}/providers/Microsoft.Network/networkInterfaces/{}?{}".format(self.resource_group_name, self.virtual_machine_nic, self.azure_version)
        #print (payload)
        try:
            r = open_url(url, method="put", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "The NIC already exists" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The role assignment already exists.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to create the VM NIC. Error code='{}' msg='{}'".format(response_code, error_msg))


    def main(self):
        if self.state == "present":
            if not self.virtual_machine_source_image and not self.virtual_machine_image_publisher and not self.virtual_machine_image_sku and not self.virtual_machine_image_offer:
                self.module.exit_json(msg="You need to either specify a source image URL OR a Publisher & Offer & Sku. In your case they are all not specified", changed=False)

            elif self.virtual_machine_source_image and self.virtual_machine_image_publisher and self.virtual_machine_image_sku and self.virtual_machine_image_offer:
                self.module.exit_json(msg="You need to either specify a source image URL OR a Publisher & Offer & Sku. In your case you have specified all of them", changed=False)

            elif not self.virtual_machine_image_publisher and not self.virtual_machine_image_sku and not self.virtual_machine_image_offer:
                self.create_public_ip()
                self.create_nic()
                self.create_vm_from_image()

            elif not self.virtual_machine_source_image:
                self.create_public_ip()
                self.create_nic()
                self.create_vm()

            else:
                self.module.exit_json(msg="You need to either specify a source image URL or a Publisher & Offer & Sku. Something is missing", changed=False)
            #print upn_name

        elif self.state == "absent":
            self.module.exit_json(msg="Deletion is not yet supported.", changed=False)
            #self.login()
            #self.delete_resource_group()

def main():
    module = AnsibleModule(
        argument_spec=dict(
            #user_name=dict(default=None, type="str", required=True),
            #principalId=dict(default=None, alias="principal_id", type="str", required=False),
            #role_definition_name=dict(default=None, type="str", required=True),
            #role_definition_id=dict(default=None, type="str", required=True),
            state=dict(default="present", choices=["absent", "present"]),
            virtual_machine_name=dict(default=None, type="str", required=True),
            virtual_machine_username=dict(default=None, type="str", required=True),
            virtual_machine_password=dict(default=None, type="str", no_log=True, required=True),
            virtual_machine_size=dict(default="Standard_A0", type="str"),
            virtual_machine_image_publisher=dict(default=None, required=False, type="str"),
            virtual_machine_image_offer=dict(default=None, required=False, type="str"),
            virtual_machine_image_sku=dict(default=None, required=False, type="str"),
            virtual_machine_image_version=dict(default="latest", type="str"),
            virtual_machine_os_disk_name=dict(type="str"),
            virtual_machine_storage_name=dict(type="str"),
            virtual_machine_customdata=dict(default="", type="str"),
            virtual_machine_nic=dict(default=None, type="str", required=False),
            security_group=dict(default=None, type="str", required=True),
            virtual_network_name=dict(default=None, type="str", required=True),
            subnet_name=dict(default="Default", type="str", required=False),
            public_ip_name=dict(default=None, type="str", required=False),
            virtual_machine_source_image=dict(default=None, type="str", required=False),
            #vault_name=dict(default=None, type="str", required=True),
            #winrm_certificate_url=dict(default=None, required=True, type="str"),
            location=dict(default=None, required=True, type="str"),
            tenant_domain = dict(default=None, type="str", required=True),
            resource_group_name=dict(default=None, type="str", required=True),
            subscription_id=dict(default=None, type="str", required=False),
            client_id = dict(default=None, alias="azure_client_id", type="str", no_log=True),
            client_secret = dict(default=None, alias="azure_client_secret", type="str", no_log=True),
            management_url = dict(default=None, type="str"),
            login_url  = dict(default=None, type="str"),
            graph_url = dict(default=None, type="str"),

        ),
        #mutually_exclusive=[['ip', 'mask']],
        #required_together=[['ip', 'mask']],
        #required_one_of=[['ip', 'mask']],
        supports_check_mode=False
    )

    AzureVMs(module).main()

import collections # might not be needed
import json
import urllib
import uuid

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
#from azure.mgmt.common import SubscriptionCloudCredentials
#from azure.mgmt.resource import ResourceManagementClient

main()
