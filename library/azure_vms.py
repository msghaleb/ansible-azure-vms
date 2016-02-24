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

  role_definition_name:
    description:
      - This is the role the user will be assigned on the resource group in question.
      e.g. Owner, Reader, ..etc.
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
        #self.user_name = self.module.params["user_name"]
        self.virtual_machine_name = self.module.params["virtual_machine_name"]
        self.virtual_machine_username = self.module.params["virtual_machine_username"]
        self.virtual_machine_password = self.module.params["virtual_machine_password"]
        self.virtual_machine_size = self.module.params["virtual_machine_size"]
        self.virtual_machine_image_publisher = self.module.params["virtual_machine_image_publisher"]
        self.virtual_machine_image_offer = self.module.params["virtual_machine_image_offer"]
        self.virtual_machine_image_sku = self.module.params["virtual_machine_image_sku"]
        self.virtual_machine_image_version = self.module.params["virtual_machine_image_version"]
        self.virtual_machine_os_disk_name = self.module.params["virtual_machine_os_disk_name"]
        self.virtual_machine_storage_name = self.module.params["virtual_machine_storage_name"]
        self.virtual_machine_customdata = self.module.params["virtual_machine_customdata"]
        self.virtual_machine_nic = self.module.params["virtual_machine_nic"]
        self.vault_name = self.module.params["vault_name"]
        self.winrm_certificate_url = self.module.params["winrm_certificate_url"]
        self.location = self.module.params["location"]
        self.resource_group_name = self.module.params["resource_group_name"]
        self.state = self.module.params["state"]
        #self.principalId = None
        #self.role_assignment_id = uuid.uuid1()
        #self.role_definition_id = None
        self.subscription_id = self.module.params["subscription_id"]
        self.tenant_domain = self.module.params["tenant_domain"]
        self.client_id = self.module.params["client_id"]
        self.client_secret = self.module.params["client_secret"]
        self.graph_url = self.module.params["graph_url"]
        self.management_url = self.module.params["management_url"]
        self.login_url  = self.module.params["login_url"]
        #self.role_definition_name = self.module.params["role_definition_name"]
        if not self.graph_url:
            self.graph_url = "https://graph.windows.net/{}".format(self.tenant_domain)
        if not self.management_url:
            self.management_url = "https://management.azure.com/subscriptions/{}".format(self.subscription_id)
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

    def create_vm(self):
        #https://msdn.microsoft.com/en-us/library/azure/dn906887.aspx
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
                            "name":"{}".format(self.virtual_machine_os_disk_name),
                            "vhd": {
                              "uri":"http://{}.blob.core.windows.net/vhds/{}.vhd".format(self.virtual_machine_storage_name, self.virtual_machine_os_disk_name)
                            },
                            "caching":"ReadWrite",
                            "createOption":"FromImage"
                          },
                        },
                        "osProfile": {
                          "computerName":"{}".format(self.virtual_machine_name),
                          "adminUsername":"{}".format(self.virtual_machine_username),
                          "adminPassword":"{}".format(self.virtual_machine_password),
                          #"customData":"{}".format(self.virtual_machine_customdata),
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
                print('Code: ', response_code)
                print('Message: ', response_msg)
                print(response_json)
        self.module.exit_json(msg="Role Assignment Created.", changed=True)

    def main(self):
        if self.state == "present":
        #    if self.name.find('@')==-1 or self.name.find('.')==-1:
        #        self.module.fail_json(msg="Please make sure to enter the username (UPN) in this form e.g. username@tenant_domain.onmicrosoft.com")
        #    if self.password == None:
        #        self.module.fail_json(msg="You can't create a user without specifing a password!")
        #    if self.display_name == None:
        #        i = self.name.split('@', 1)
        #        self.display_name = i[0]
        #    if self.mail_nick_name == None:
        #        i = self.name.split('@', 1)
        #        self.mail_nick_name = i[0]


            #self.principalId = self.get_user_id()
            #self.role_definition_id = self.get_role_definition()
            self.create_vm()

            #print upn_name

        elif self.state == "absent":
            self.module.exit_json(msg="Deletion is not supported.", changed=False)
            #self.login()
            #self.delete_resource_group()

def main():
    module = AnsibleModule(
        argument_spec=dict(
            #user_name=dict(default=None, type="str", required=True),
            #principalId=dict(default=None, alias="principal_id", type="str", required=False),
            #role_definition_name=dict(default=None, type="str", required=True),
            #role_definition_id=dict(default=None, type="str", required=True),
            virtual_machine_name=dict(default=None, type="str", required=True),
            virtual_machine_username=dict(default=None, type="str", required=True),
            virtual_machine_password=dict(default=None, type="str", no_log=True, required=True),
            virtual_machine_size=dict(default="Standard_A0", type="str"),
            virtual_machine_image_publisher=dict(default=None, required=True, type="str"),
            virtual_machine_image_offer=dict(default=None, required=True, type="str"),
            virtual_machine_image_sku=dict(default=None, required=True, type="str"),
            virtual_machine_image_version=dict(default="latest", type="str"),
            virtual_machine_os_disk_name=dict(default="myosdisk1", type="str"),
            virtual_machine_storage_name=dict(default="mystorage1", type="str"),
            virtual_machine_customdata=dict(default="", type="str"),
            virtual_machine_nic=dict(default="mynic1", type="str"),
            vault_name=dict(default=None, type="str", required=True),
            winrm_certificate_url=dict(default=None, required=True, type="str"),
            location=dict(default=None, required=True, type="str"),
            state=dict(default="present", choices=["absent", "present"]),
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
