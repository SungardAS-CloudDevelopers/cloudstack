# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
""" BVT tests for Virtual Network IAM effect
"""
#Import Local Modules
import marvin
from marvin.cloudstackTestCase import *
from marvin.cloudstackAPI import *
from marvin.integration.lib.utils import *
from marvin.integration.lib.base import *
from marvin.integration.lib.common import *
from nose.plugins.attrib import attr
#Import System modules
import time

_multiprocess_shared_ = True
class Services:
    """Test list networks Life Cycle Services
    """

    def __init__(self):
        self.services = {
            #data for domains and accounts
            
            "ostype": "CentOS 5.3 (64-bit)",
                            # Cent OS 5.3 (64 bit)
                            "lb_switch_wait": 10,
                            # Time interval after which LB switches the requests
                            "sleep": 60,
                            "timeout":10,
                            "network_offering": {
                                    "name": 'Test Network offering',
                                    "displaytext": 'Test Network offering',
                                    "guestiptype": 'Isolated',
                                    "supportedservices": 'Dhcp,Dns,SourceNat,PortForwarding',
                                    "traffictype": 'GUEST',
                                    "availability": 'Optional',
                                    "serviceProviderList" : {
                                            "Dhcp": 'VirtualRouter',
                                            "Dns": 'VirtualRouter',
                                            "SourceNat": 'VirtualRouter',
                                            "PortForwarding": 'VirtualRouter',
                                        },
                                },
            
            
            "domain1": {
                "name": "Domain1",
             },
            "account1A": {
                "email": "test1A@test.com",
                "firstname": "test1A",
                "lastname": "User",
                "username": "test1A",
                "password": "password",
            },
            "account1B": {
                "email": "test1B@test.com",
                "firstname": "test1B",
                "lastname": "User",
                "username": "test1B",
                "password": "password",
            },
            "domain2": {
                "name": "Domain2",
             },
            "account2A": {
                "email": "test2A@test.com",
                "firstname": "test2A",
                "lastname": "User",
                "username": "test2A",
                "password": "password",
            },
            #small service offering
            "service_offering": {
                "small": {
                    "name": "Small Instance",
                    "displaytext": "Small Instance",
                    "cpunumber": 1,
                    "cpuspeed": 100,
                    "memory": 128,
                },
            },
            "ostype": 'CentOS 5.6 (64-bit)',
            # iam group and policy information
            "service_desk_iam_net_grp" : {
                "name" : "Service Desk net",
                "description" : "Service Desk net IAM Group"
            },
            "network_readonly_iam_policy" : {
                "name" : "Network Read Only Access",
                "description" : "Network read only access iam policy"
            },
			
                            "network1A": {
                                  "name": "Test Network1A",
                                  "displaytext": "Test Network1A",
                                },
                         
                           "network2A": {
                                  "name": "Test Network2A",
                                  "displaytext": "Test Network2A",
                                },
                            "network1B": {
                                  "name": "Test Network1B",
                                  "displaytext": "Test Network1B",
                                },

                         
                            "service_offering": {
                                    "name": "Tiny Instance",
                                    "displaytext": "Tiny Instance",
                                    "cpunumber": 1,
                                    "cpuspeed": 100,
                                    # in MHz
                                    "memory": 256,
                                    # In MBs
                                    },
                            "account": {
                                    "email": "test@test.com",
                                    "firstname": "Test",
                                    "lastname": "User",
                                    "username": "test",
                                    "password": "password",
                                    },
                            "server":
                                    {
                                    "displayname": "Small Instance",
                                    "username": "root",
                                    "password": "password",
                                    "hypervisor": 'XenServer',
                                    "privateport": 22,
                                    "publicport": 22,
                                    "ssh_port": 22,
                                    "protocol": 'TCP',
                                },
                        "natrule":
                                {
                                    "privateport": 22,
                                    "publicport": 22,
                                    "protocol": "TCP"
                                },
                        "lbrule":
                                {
                                    "name": "SSH",
                                    "alg": "roundrobin",
                                    # Algorithm used for load balancing
                                    "privateport": 22,
                                    "publicport": 2222,
                                    "protocol": 'TCP'
                                }
                        }			


class TestNetworkIam(cloudstackTestCase):
    

    @classmethod
    def setUpClass(self):
        self.apiclient = super(TestNetworkIam, self).getClsTestClient().getApiClient()
        self.services = Services().services
        
        # backup default apikey and secretkey
        self.default_apikey = self.apiclient.connection.apiKey
        self.default_secretkey = self.apiclient.connection.securityKey

        # Create domains and accounts etc
        self.domain_1 = Domain.create(
                                   self.apiclient,
                                   self.services["domain1"]
                                   )
        self.domain_2 = Domain.create(
                                   self.apiclient,
                                   self.services["domain2"]
                                   )
        # Create two accounts for doamin_1
        self.account_1A = Account.create(
                            self.apiclient,
                            self.services["account1A"],
                            admin=False,
                            domainid=self.domain_1.id
                            )
        
        self.account_1B = Account.create(
                            self.apiclient,
                            self.services["account1B"],
                            admin=False,
                            domainid=self.domain_1.id
                            )        

        # Create an account for domain_2
        self.account_2A = Account.create(
                            self.apiclient,
                            self.services["account2A"],
                            admin=False,
                            domainid=self.domain_2.id
                            )
        
        # Fetch user details to register apiKey for them
        self.user_1A = User.list(
                          self.apiclient,
                          account=self.account_1A.name,
                          domainid=self.account_1A.domainid
                          )[0]
       
        user_1A_key = User.registerUserKeys(
                        self.apiclient,
                        self.user_1A.id
                      )  
        self.user_1A_apikey = user_1A_key.apikey
        self.user_1A_secretkey = user_1A_key.secretkey
        
                         
        self.user_1B = User.list(
                          self.apiclient,
                          account=self.account_1B.name,
                          domainid=self.account_1B.domainid
                          )[0]
       
        user_1B_key = User.registerUserKeys(
                        self.apiclient,
                        self.user_1B.id
                      )  
       
        self.user_1B_apikey = user_1B_key.apikey
        self.user_1B_secretkey = user_1B_key.secretkey                    

 
        self.user_2A = User.list(
                          self.apiclient,
                          account=self.account_2A.name,
                          domainid=self.account_2A.domainid
                          )[0]
       
        user_2A_key = User.registerUserKeys(
                        self.apiclient,
                        self.user_2A.id
                      )  
        self.user_2A_apikey = user_2A_key.apikey
        self.user_2A_secretkey = user_2A_key.secretkey
        
        self.zone = get_zone(self.apiclient, self.services)
        self.services['mode'] = self.zone.networktype
        self.template = get_template(self.apiclient, self.zone.id, self.services["ostype"])
        
        ############################################ Added ################################
        # create networks here 
        self.services["network1A"]["zoneid"] = self.zone.id
        self.services["network2A"]["zoneid"] = self.zone.id
        self.services["network1B"]["zoneid"] = self.zone.id

        self.network_offering = NetworkOffering.create(
                                    self.apiclient,
                                    self.services["network_offering"],
                                    )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')

        self.services["network1A"]["networkoffering"] = self.network_offering.id
        self.services["network2A"]["networkoffering"] = self.network_offering.id
        self.services["network1B"]["networkoffering"] = self.network_offering.id
        
        self.account_1A_network = Network.create(
                                             self.apiclient,
                                             self.services["network1A"],
                                             self.account_1A.name,
                                             self.account_1A.domainid
                                             )
   
        self.account_2A_network = Network.create(
                                             self.apiclient,
                                             self.services["network2A"],
                                             self.account_2A.name,
                                             self.account_2A.domainid
                                             )
        
        self.account_1B_network = Network.create(
                                             self.apiclient,
                                             self.services["network1B"],
                                             self.account_1B.name,
                                             self.account_1B.domainid
                                             )


        self.srv_desk_grp = IAMGroup.create(
            self.apiclient,
            self.services["service_desk_iam_net_grp"]
        )                             

        self.network_read_policy = IAMPolicy.create(
            self.apiclient,
            self.services["network_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.network_read_policy]
        )
                
        network_grant_policy_params = {}
        network_grant_policy_params['name'] = "policyGrantNetwork" + self.account_1A_network.id
        network_grant_policy_params['description'] = "Policy to grant permission to a Network " + self.account_1A_network.id
        self.network_grant_policy = IAMPolicy.create(
            self.apiclient,
            network_grant_policy_params
        )    
       
       
       
        self._cleanup = [
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.account_2A,
                        self.domain_2,
                        self.network_read_policy,
                        self.srv_desk_grp,
                        self.network_grant_policy
                        ]


    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestNetworkIam, self).getClsTestClient().getApiClient()
        cleanup_resources(self.apiclient, self._cleanup)
        return

    def setUp(self):
        self.apiclient = self.testClient.getApiClient()
        self.dbclient = self.testClient.getDbConnection()
        self.cleanup = []

    def tearDown(self):
        # restore back default apikey and secretkey
        self.apiclient.connection.apiKey = self.default_apikey
        self.apiclient.connection.securityKey = self.default_secretkey
        cleanup_resources(self.apiclient, self.cleanup)
        return


    @attr(tags=["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_01_list_own_network(self):
        #  list network command should return owne's network

        self.debug("Listing network for account: %s" % self.account_1A.name)

        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        
        
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check network available in List network"
                        )

        self.assertEqual(
            list_network_response[0].name,
            self.account_1A_network.name,
            "Virtual Network names do not match"
        )

        self.debug("Listing networks for account: %s" % self.account_2A.name)
        self.debug("networks[0] : %s" % list_network_response[0].name)

        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        
        
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check network available in List network"
                        )

        self.assertEqual(
            list_network_response[0].name,
            self.account_2A_network.name,
            "Virtual Network names do not match"
        )

        self.debug("Listing networks for account: %s" % self.account_2A.name)
        self.debug("networks[0] : %s" % list_network_response[0].name)

        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_account_network(self):
 
        # Validate the following
        # 1. Grant account_1A Network access to account_1B
        # 2. listNetwork command should return account_1A and account_1B Networks.

        self.debug("Granting Account %s Network read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listNetworks"
        account_permission['entitytype'] = "Network"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.network_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing networks for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.debug("networks[0] : %s" % list_network_response[0].name)
        
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            2,
                            "Check Network available in List Virtual Networks"
                        )

        list_network_names = [list_network_response[0].name, list_network_response[1].name]
        
        self.assertEqual( self.account_1B_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )
        
        self.assertEqual( self.account_1A_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )    
                
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_account_network(self):
 
        # Validate the following
        # 1. Revoke account_1A network access from account_1B
        # 2. listNetworks command should not return account_1A networks.

        self.debug("Revoking Account %s network read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listNetworks"
        account_permission['entitytype'] = "Network"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.network_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing Network for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.debug("Length : %d" % len(list_network_response))
        self.debug("Networks[0] : %s" % list_network_response[0].name)
        
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check Network available in List Virtual Networks"
                        )

        list_network_names = [list_network_response[0].name]
        
       
        self.assertEqual( self.account_1A_network.name in list_network_names,
                          False,
                          "Accessible Virtual Machine names do not match"
                          )    
        return

    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_resource_network(self):
 
        # Validate the following
        # 1. Grant a particular network access to account_1B
        # 2. listNetwork command should return account_1B networks and granted Network.

        self.debug("Granting network %s read only access to account: %s" % (self.account_1A_network.name, self.account_1B_network.name))
        
        res_permission = {}
        res_permission['action'] = "listNetworks"
        res_permission['entitytype'] = "Network"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A_network.id
        self.network_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing network for account: %s" % self.account_1B_network.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            2,
                            "Check network available in List Virtual networks"
                        )

        list_network_names = [list_network_response[0].name, list_network_response[1].name]
        
        self.assertEqual( self.account_1B_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )
        
        self.assertEqual( self.account_1A_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )    
                
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_resource_network(self):
 
        # Validate the following
        # 1. Grant a particular network access to account_1B
        # 2. listNetworks command should return account_1B VMs and granted network.

        self.debug("Revoking network %s read only access from account: %s" % (self.account_1A_network.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listNetworks"
        res_permission['entitytype'] = "Network"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A_network.id
        self.network_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing network for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check VM available in List Virtual Machines"
                        )

        self.assertEqual(
            list_network_response[0].name,
            self.account_1B_network.name,
            "Virtual network names do not match"
        )
        
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_domain_network(self):
 
        # Validate the following
        # 1. Grant domain2 network access to account_1B
        # 2. listnetworks command should return account_1B and domain_2 networks.
        # {"action":"listNetworks","entitytype":"Network","scope":"DOMAIN","scopeid":-1,"permission":"Allow"},
        self.debug("Granting Domain %s network read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listNetworks"
        domain_permission['entitytype'] = "Network"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.network_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing network for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            2,
                            "Check network available in List Virtual networks"
                        )

        list_network_names = [list_network_response[0].name, list_network_response[1].name]
        
        self.assertEqual( self.account_1B_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )
        
        self.assertEqual( self.account_2A_network.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )        
        
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_domain_network(self):
 
        # Validate the following
        # 1. Revoke account_1A network access from account_1B
        # 2. listNetworks command should not return account_1A networks.

        self.debug("Revoking Domain %s network read only access from account: %s" % (self.domain_1.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listNetworks"
        domain_permission['entitytype'] = "Network"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.network_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing VM for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check network available in List Virtual networks"
                        )

        self.assertEqual(
            list_network_response[0].name,
            self.account_1B_network.name,
            "Virtual Network names do not match"
        )
         
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular network access to account_1B by directly attaching policy to account
        # 2. listNetwork command should return account_1B Networks and granted Networks.

        self.debug("Granting Network %s read only access to account: %s by attaching policy to account" % (self.account_1A_network.name, self.account_1B_network.name))
        
        res_permission = {}
        res_permission['action'] = "listNetworks"
        res_permission['entitytype'] = "Network"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A_network.id
        self.network_grant_policy.addPermission(self.apiclient, res_permission)
        self.network_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing Network for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            2,
                            "Check Network available in List Virtual Networks"
                        )

        list_network_names = [list_network_response[0].name, list_network_response[1].name]
        list_policies = self.network_grant_policy.list(self.apiclient, res_permission)
        self.debug("list policies :::: " % (list_policies[0].name))
        
        
        self.assertEqual( self.virtual_machine_1B.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )
        
        self.assertEqual( self.virtual_machine_1A.name in list_network_names,
                          True,
                          "Accessible Virtual Network names do not match"
                          )    
                
        return
        
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular network access from account_1B by detaching policy from account
        # 2. listnetwork command should return account_1B networks.

        self.debug("Revoking network %s read only access from account: %s by detaching policy from account" % (self.account_1A_network.name, self.account_1B.name))
        
        self.network_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing network for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_network_response = list_networks(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_network_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_network_response),
                            1,
                            "Check network available in List Virtual network"
                        )

        self.assertEqual(
            list_network_response[0].name,
            self.account_1B_network.name,
            "Virtual network names do not match"
        )
        
        return
