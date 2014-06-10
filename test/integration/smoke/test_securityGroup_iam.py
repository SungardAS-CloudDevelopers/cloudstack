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
""" BVT tests for Security Group IAM effect
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
    """Test SG Life Cycle Services
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
                         
            # Data required to create Security Groups
            
            "security_group1A": {
                "name": 'SSH',
            },
                         
            "security_group1B": {
                "name": 'ICMP',
            },      
                         
            "security_group2A": {
                "name": 'UDP',
            },   
                         
            "service_desk_iam_sg_grp" : {
                "name" : "Service Desk",
                "description" : "Service Desk IAM Security Group"
            },
            "sg_readonly_iam_policy" : {
                "name" : "SG Read Only Access",
                "description" : "SG read only access iam policy"
            },         
        }
        
class TestSGIam(cloudstackTestCase):

    @classmethod
    def setUpClass(self):
        testClient = super(TestSGIam, self).getClsTestClient()
        self.apiclient = testClient.getApiClient()
        self.services = Services().services
        
        self.zone = get_zone(self.apiclient, testClient.getZoneForTests())
        self.services['mode'] = self.zone.networktype
        
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
                
        # Create 3 security groups for 3 accounts
        
        self.sg1A = SecurityGroup.create(
                                         self.apiclient,
                                         self.services["security_group1A"],
                                         account=self.account_1A.name,
                                         domainid=self.account_1A.domainid,
                                         )
        self.debug("Created security group with ID: %s" % self.sg1A.id)
        
        self.sg1B = SecurityGroup.create(
                                         self.apiclient,
                                         self.services["security_group1B"],
                                         account=self.account_1B.name,
                                         domainid=self.account_1B.domainid
                                         )
        self.debug("Created security group with ID: %s" % self.sg1B.id)
        
        self.sg2A = SecurityGroup.create(
                                         self.apiclient,
                                         self.services["security_group2A"],
                                         account=self.account_2A.name,
                                         domainid=self.account_2A.domainid,
                                         )
        self.debug("Created security group with ID: %s" % self.sg2A.id)
        
        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_iam_sg_grp"]
        )                             

        self.sg_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["sg_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.sg_read_policy]
        )
        
        sg_grant_policy_params = {}
        sg_grant_policy_params['name'] = "policyGrantSecurityGroup" + self.sg1A.id
        sg_grant_policy_params['description'] = "Policy to grant permission to SecurityGroup" + self.sg1A.id
        self.sg_grant_policy = IAMPolicy.create(
            self.apiclient, 
            sg_grant_policy_params
        )   
        
        self._cleanup = [
                        self.sg1A,
                        self.sg1B,
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.sg2A,
                        self.account_2A,
                        self.domain_2,
                        self.sg_read_policy,
                        self.srv_desk_grp,
                        self.sg_grant_policy
                        ]

    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestSGIam, self).getClsTestClient().getApiClient()
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
    def test_01_list_own_sg(self):
        #  listSecurityGroups command should return owne's security group

        self.debug("Listing security group for account: %s" % self.account_1A.name)
        
        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_sg_response = list_security_groups(
                                              self.apiclient,
                                              )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg1A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        
        
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                              self.apiclient,
                                              )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        
        
        self.debug("Listing security group for account: %s" % self.account_2A.name)
        
        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_sg_response = list_security_groups(
                                              self.apiclient,
                                              )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg2A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_sg(self):
 
        # Validate the following
        # 1. Grant domain2 sg access to account_1B
        # 2. listSecurityGroups command should return account_1B and domain_2 sg.

        self.debug("Granting Domain %s sg read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listSecurityGroups"
        domain_permission['entitytype'] = "SecurityGroup"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.sg_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            4,
                            "Check security group available in List Security Groups"
                        )

        list_sg_names = [list_sg_response[0].name, list_sg_response[1].name,list_sg_response[2].name, list_sg_response[3].name]
        
        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual(self.sg2A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_sg(self):
 
        # Validate the following
        # 1. Revoke domain2 sg access from account_1B
        # 2. listSecurityGroups command should not return account_2A sg.

        self.debug("Revoking Domain %s sg read only access from account: %s" % (self.domain_2.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listSecurityGroups"
        domain_permission['entitytype'] = "SecurityGroup"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.sg_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_sg(self):
 
        # Validate the following
        # 1. Grant account_1A sg access to account_1B
        # 2. listSecurityGroups command should return account_1A and account_1B sg.

        self.debug("Granting Account %s sg read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listSecurityGroups"
        account_permission['entitytype'] = "SecurityGroup"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.sg_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            4,
                            "Check security group available in List Security Groups"
                        )
        

        list_sg_names = [list_sg_response[0].name, list_sg_response[1].name,list_sg_response[2].name, list_sg_response[3].name]
        
        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual(self.sg1A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )   
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_sg(self):
 
        # Validate the following
        # 1. Revoke account_1A sg access from account_1B
        # 2. listSecurityGroups command should not return account_1A sg.

        self.debug("Revoking Account %s sg read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listSecurityGroups"
        account_permission['entitytype'] = "SecurityGroup"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.sg_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name]
        
       
        self.assertEqual(self.sg1A.name in list_sg_names,
                          False,
                          "Accessible Security group names do not match"
                          )   
         
        return
    
    """
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_resource_sg(self):
 
        # Validate the following
        # 1. Grant a particular sg access to account_1B
        # 2. listSecurityGroups command should return account_1B sg and granted sg

        self.debug("Granting %s sg read only access to account: %s" % (self.sg1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listSecurityGroups"
        res_permission['entitytype'] = "SecurityGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.sg1A.id
        
        self.sg_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            4,
                            "Check security group available in List Security Groups"
                        )

        list_sg_names = [list_sg_response[0].name, list_sg_response[1].name,list_sg_response[2].name, list_sg_response[3].name]
        
        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual(self.sg1A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )    
                
        return    
        
        """
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_sg(self):
 
        # Validate the following
        # 1. Grant a particular sg access to account_1B
        # 2. listSecurityGroups command should return account_1B sg
        self.debug("Revoking %s sg read only access from account: %s" % (self.sg1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listSecurityGroups"
        res_permission['entitytype'] = "SecurityGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.sg1A.id
        self.sg_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing security group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )

        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        
        return
    
    
    """
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular sg access to account_1B by directly attaching policy to account
        # 2. listSecurityGroups command should return account_1B sg and granted sg

        self.debug("Granting %s sg read only access to account: %s by attaching policy to account" % (self.sg1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listSecurityGroups"
        res_permission['entitytype'] = "SecurityGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.sg1A.id
        self.sg_grant_policy.addPermission(self.apiclient, res_permission)
        self.sg_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing security group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_sg_response),
                            4,
                            "Check security group available in List Security Groups"
                        )

        list_sg_names = [list_sg_response[0].name, list_sg_response[1].name,list_sg_response[2].name, list_sg_response[3].name]
        
        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual(self.sg1A.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )  
        return     
        
        """
        
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular sg access from account_1B by detaching policy from account
        # 2. listSecurityGroups command should return account_1B sg

        self.debug("Revoking %s sg read only access from account: %s by detaching policy from account" % (self.sg1A.name, self.account_1B.name))
        
        self.sg_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing security group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_sg_response = list_security_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_sg_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_sg_response),
                            2,
                            "Check security group available in List Security Groups"
                        )
        
        list_sg_names = [list_sg_response[0].name,list_sg_response[1].name]

        self.assertEqual(self.sg1B.name in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          )
        
        self.assertEqual("default" in list_sg_names,
                          True,
                          "Accessible Security group names do not match"
                          ) 
        return
