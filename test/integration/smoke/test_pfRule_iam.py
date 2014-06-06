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
""" BVT tests for Virtual Machine IAM effect
"""
#Import Local Modules
import marvin
from marvin.cloudstackTestCase import *
from marvin.cloudstackAPI import *
from marvin.lib.utils import *
from marvin.lib.base import *
from marvin.lib.common import *
from marvin.codes import FAILED
from nose.plugins.attrib import attr
#Import System modules
import time

_multiprocess_shared_ = True
class Services:
    """Test PortFwRule Life Cycle Services
    """

    def __init__(self):
        self.services = {
            #data for domains and accounts
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
                         
            #Data required for nat rule creation
            
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
            
            "virtual_machine1A" : {
                "name" : "TestVM1A",
                "displayname" : "TestVM1A",
            },
                         
            "network1A": {
                "name": "Test Network1A",
                "displaytext": "Test Network1A",
            },
            
            "natrule1A": {
                "privateport": 22,
                "publicport": 22,
                "protocol": "TCP"
            },
                         
            "virtual_machine1B" : {
                "name" : "TestVM1B",
                "displayname" : "TestVM1B",
            },
            
            "network1B": {
                "name": "Test Network1B",
                "displaytext": "Test Network1B",
            },
            
            "natrule1B": {
                "privateport": 23,
                "publicport": 23,
                "protocol": "TCP"
            },
                         
            "virtual_machine2A" : {
                "name" : "TestVM2A",
                "displayname" : "TestVM2A",
            },
                         
             "network2A": {
                "name": "Test Network2A",
                "displaytext": "Test Network2A",
            },
            
            "natrule2A": {
                "privateport": 24,
                "publicport": 24,
                "protocol": "TCP"
            },
                         
            # iam group and policy information
            "service_desk_iam_pf_grp" : {
                "name" : "Service Desk",
                "description" : "Service Desk IAM PortForwarding Group"
            },
            "pf_readonly_iam_policy" : {
                "name" : "PF Read Only Access",
                "description" : "PF read only access iam policy"
            },
     }
        
class TestPFIam(cloudstackTestCase):

    @classmethod
    def setUpClass(self):
        testClient = super(TestPFIam, self).getClsTestClient()
        self.apiclient = testClient.getApiClient()
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
        
        #Create service offering and network offering
        
        self.service_offering = ServiceOffering.create(
                                self.apiclient,
                                self.services["service_offering"]["small"]
                                )
        
        self.zone = get_zone(self.apiclient, testClient.getZoneForTests())
        self.services['mode'] = self.zone.networktype
        self.template = get_template(self.apiclient, self.zone.id, self.services["ostype"])
        
        self.network_offering = NetworkOffering.create(
                                    self.apiclient,
                                    self.services["network_offering"],
                                    )
        
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
        
        #Create 3 nat rules for 3 accounts
        
        # Create nat rule for account 1A
        
        self.network1A = Network.create(
                                    self.apiclient,
                                    self.services["network1A"],
                                    self.account_1A.name,
                                    self.account_1A.domainid
                                    )
        
        self.debug("Network for the account: %s is %s" % (self.account_1A.name, self.network1A.name))
                                    
        self.debug("Associating public IP for network: %s" % self.network1A.id)
        self.public_ip1A = PublicIPAddress.create(
                                    self.apiclient,
                                    accountid=self.account_1A.name,
                                    zoneid=self.zone.id,
                                    domainid=self.account_1A.domainid,
                                    networkid=self.network1A.id
                                    )
        
        self.vm_1A = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine1A"],
            accountid=self.account_1A.name,
            zoneid=self.zone.id,
            domainid=self.account_1A.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )  
        
        self.nat_rule1A = NATRule.create(
                                    self.apiclient,
                                    self.vm_1A,
                                    self.services["natrule1A"],
                                    ipaddressid=self.public_ip1A.ipaddress.id
                                    )
        
        #Create nat rule for account1B
        
        self.network1B = Network.create(
                                    self.apiclient,
                                    self.services["network1B"],
                                    self.account_1B.name,
                                    self.account_1B.domainid
                                    )
        self.debug("Network for the account: %s is %s" % (self.account_1B.name, self.network1B.name))
                                    
        self.debug("Associating public IP for network: %s" % self.network1B.id)
        self.public_ip1B = PublicIPAddress.create(
                                    self.apiclient,
                                    accountid=self.account_1B.name,
                                    zoneid=self.zone.id,
                                    domainid=self.account_1B.domainid,
                                    networkid=self.network1B.id
                                    )
        
        self.vm_1B = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine1B"],
            accountid=self.account_1B.name,
            zoneid=self.zone.id,
            domainid=self.account_1B.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )
        
        self.nat_rule1B = NATRule.create(
                                    self.apiclient,
                                    self.vm_1B,
                                    self.services["natrule1B"],
                                    ipaddressid=self.public_ip1B.ipaddress.id
                                    )
        
        #Create nat rule for account2A
        
        self.network2A = Network.create(
                                    self.apiclient,
                                    self.services["network2A"],
                                    self.account_2A.name,
                                    self.account_2A.domainid
                                    )
        self.debug("Network for the account: %s is %s" % (self.account_2A.name, self.network2A.name))
                                    
        self.debug("Associating public IP for network: %s" % self.network2A.id)
        self.public_ip2A = PublicIPAddress.create(
                                    self.apiclient,
                                    accountid=self.account_2A.name,
                                    zoneid=self.zone.id,
                                    domainid=self.account_2A.domainid,
                                    networkid=self.network2A.id
                                    )
        
        self.vm_2A = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine2A"],
            accountid=self.account_2A.name,
            zoneid=self.zone.id,
            domainid=self.account_2A.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )
        
        self.nat_rule2A = NATRule.create(
                                    self.apiclient,
                                    self.vm_2A,
                                    self.services["natrule2A"],
                                    ipaddressid=self.public_ip2A.ipaddress.id
                                    )

        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_iam_pf_grp"]
        )                             

        self.pf_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["pf_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.pf_read_policy]
        )
        
        pf_grant_policy_params = {}
        pf_grant_policy_params['name'] = "policyGrantPortForwaringRule" + self.nat_rule1A.id
        pf_grant_policy_params['description'] = "Policy to grant permission to PortForwardingRule" + self.nat_rule1A.id
        self.pf_grant_policy = IAMPolicy.create(
            self.apiclient, 
            pf_grant_policy_params
        ) 
        
        self._cleanup = [
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.account_2A,
                        self.domain_2,
                        self.service_offering,
                        self.network_offering,
                        self.pf_read_policy,
                        self.srv_desk_grp,
                        self.pf_grant_policy
                        ]
         
    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestPFIam, self).getClsTestClient().getApiClient()
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
        
        
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_01_list_own_pfRule(self):
        #  listPortForwardingRules command should return own pf Rule

        self.debug("Listing PF rule for account: %s" % self.account_1A.name)

        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_nat_response = list_nat_rules(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_nat_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_nat_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        self.assertEqual(
            list_nat_response[0].privateport,
            self.nat_rule1A.privateport,
            "PF Rule ports do not match"
        )
        
        self.debug("Listing PF rule for account: %s" % self.account_1B.name)

        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_nat_response = list_nat_rules(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_nat_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_nat_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        self.assertEqual(
            list_nat_response[0].privateport,
            self.nat_rule1B.privateport,
            "PF Rule ports do not match"
        )
        
        self.debug("Listing PF rule for account: %s" % self.account_2A.name)

        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_nat_response = list_nat_rules(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_nat_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_nat_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        self.assertEqual(
            list_nat_response[0].privateport,
            self.nat_rule2A.privateport,
            "PF Rule ports do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_pfRule(self):
 
        # Validate the following
        # 1. Grant domain2 pf rule access to account_1B
        # 2. listPortForwardingRules command should return account_1B and domain_2 pfRule.

        self.debug("Granting Domain %s pfRule read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listPortForwardingRules"
        domain_permission['entitytype'] = "PortForwardingRule"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.pf_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing pf Rule for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_pfrules_response),
                            2,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        list_pfrule_names = [list_pfrules_response[0].privateport, list_pfrules_response[1].privateport]
        
        self.assertEqual( self.nat_rule1B.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )
        
        self.assertEqual( self.nat_rule2A.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_pfRule(self):
 
        # Validate the following
        # 1. Revoke domain2 pf rule access from account_1B
        # 2. listPortForwardingRules command should not return account_2A pf rule.

        self.debug("Revoking Domain %s pf read only access from account: %s" % (self.domain_2.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listPortForwardingRules"
        domain_permission['entitytype'] = "PortForwardingRule"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.pf_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_pfrules_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )
        
        self.assertEqual(
            list_pfrules_response[0].privateport,
            self.nat_rule1B.privateport,
            "PF rule ports do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_pfRule(self):
 
        # Validate the following
        # 1. Grant account_1A pf rule access to account_1B
        # 2. listPortForwardingRules command should return account_1A and account_1B pf rules.

        self.debug("Granting Account %s pf read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listPortForwardingRules"
        account_permission['entitytype'] = "PortForwardingRule"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.pf_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_pfrules_response),
                            2,
                            "Check pf rule available in List Port Forwarding Rules"
                        )
        

        list_pfrule_names = [list_pfrules_response[0].privateport, list_pfrules_response[1].privateport]
        
        self.assertEqual( self.nat_rule1B.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )
        
        self.assertEqual( self.nat_rule1A.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )    
                
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_pfRule(self):
 
        # Validate the following
        # 1. Revoke account_1A pf rule access from account_1B
        # 2. listPortForwardingRules command should not return account_1A pf rule.

        self.debug("Revoking Account %s pf read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listPortForwardingRules"
        account_permission['entitytype'] = "PortForwardingRule"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.pf_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_pfrules_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )
        
        list_pfrule_names = [list_pfrules_response[0].privateport]
        
       
        self.assertEqual(self.nat_rule1A.privateport in list_pfrule_names,
                          False,
                          "Accessible pf rule ports do not match"
                          )   
         
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_resource_pfRule(self):
 
        # Validate the following
        # 1. Grant a particular pf rule access to account_1B
        # 2. listPortForwardingRules command should return account_1B pf rules and granted pf rule.

        self.debug("Granting pf rule %s read only access to account: %s" % (self.nat_rule1A.privateport, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPortForwardingRules"
        res_permission['entitytype'] = "PortForwardingRule"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.nat_rule1A.id
        
        self.pf_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_pfrules_response),
                            2,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        list_pfrule_names = [list_pfrules_response[0].privateport, list_pfrules_response[1].privateport]
        
        self.assertEqual( self.nat_rule1B.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )
        
        self.assertEqual( self.nat_rule1A.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )    
                
        return    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_pfRule(self):
 
        # Validate the following
        # 1. Grant a particular pf rule access to account_1B
        # 2. listPortForwardingRules command should return account_1B pf rules
        self.debug("Revoking pf rule %s read only access from account: %s" % (self.nat_rule1A.privateport, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPortForwardingRules"
        res_permission['entitytype'] = "PortForwardingRule"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.nat_rule1A.id
        self.pf_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_pfrules_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        self.assertEqual(
            list_pfrules_response[0].privateport,
            self.nat_rule1B.privateport,
            "PF rule ports do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular pf rule access to account_1B by directly attaching policy to account
        # 2. listPortForwardingRules command should return account_1B pf rules and granted pf rule

        self.debug("Granting pf rule %s read only access to account: %s by attaching policy to account" % (self.nat_rule1A.privateport, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPortForwardingRules"
        res_permission['entitytype'] = "PortForwardingRule"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.nat_rule1A.id
        self.pf_grant_policy.addPermission(self.apiclient, res_permission)
        self.pf_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_pfrules_response),
                            2,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        list_pfrule_names = [list_pfrules_response[0].privateport, list_pfrules_response[1].privateport]
        
        self.assertEqual( self.nat_rule1B.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )
        
        self.assertEqual( self.nat_rule1A.privateport in list_pfrule_names,
                          True,
                          "Accessible pf rule ports do not match"
                          )    
                
        return     
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular pf rule access from account_1B by detaching policy from account
        # 2. listPortForwardingRules command should return account_1B pf rules.

        self.debug("Revoking pf rule %s read only access from account: %s by detaching policy from account" % (self.nat_rule1A.privateport, self.account_1B.name))
        
        self.pf_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing pf rule for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_pfrules_response = list_nat_rules(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_pfrules_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_pfrules_response),
                            1,
                            "Check pf rule available in List Port Forwarding Rules"
                        )

        self.assertEqual(
            list_pfrules_response[0].privateport,
            self.nat_rule1B.privateport,
            "PF rule ports do not match"
        )
        
        return