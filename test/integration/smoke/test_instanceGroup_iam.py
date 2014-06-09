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
""" BVT tests for Instance Group IAM effect
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
    """Test IG Life Cycle Services
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
                         
            "service_desk_iam_instance_grp" : {
                "name" : "Service Desk",
                "description" : "Service Desk IAM Instance Group"
            },
            "ig_readonly_iam_policy" : {
                "name" : "IG Read Only Access",
                "description" : "IG read only access iam policy"
            },
    }
        
        
class TestIGIam(cloudstackTestCase):

    @classmethod
    def setUpClass(self):
        testClient = super(TestIGIam, self).getClsTestClient()
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
        
        # Create 3 instance groups for 3 accounts
        
        self.instancegrp1A=InstanceGroup.create(
                                 self.apiclient,
                                 name="Instance Group 1A",
                                 account=self.account_1A.name,
                                 domainid=self.account_1A.domainid,
                                 ) 
        
        self.instancegrp1B=InstanceGroup.create(
                                 self.apiclient,
                                 name="Instance Group 1B",
                                 account=self.account_1B.name,
                                 domainid=self.account_1B.domainid,
                                 )
        
        self.instancegrp2A=InstanceGroup.create(
                                 self.apiclient,
                                 name="Instance Group 2A",
                                 account=self.account_2A.name,
                                 domainid=self.account_2A.domainid,
                                 )          
                                                
        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_iam_instance_grp"]
        )                             

        self.ig_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["ig_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.ig_read_policy]
        )
        
        ig_grant_policy_params = {}
        ig_grant_policy_params['name'] = "policyGrantInstanceGroup" + self.instancegrp1A.id
        ig_grant_policy_params['description'] = "Policy to grant permission to Instance Group" + self.instancegrp1A.id
        self.ig_grant_policy = IAMPolicy.create(
            self.apiclient, 
            ig_grant_policy_params
        )   
        
        self._cleanup = [
                        self.instancegrp1A,
                        self.account_1A,
                        self.instancegrp1B,
                        self.account_1B,
                        self.domain_1,
                        self.instancegrp2A,
                        self.account_2A,
                        self.domain_2,
                        self.ig_read_policy,
                        self.srv_desk_grp,
                        self.ig_grant_policy
                        ]

    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestIGIam, self).getClsTestClient().getApiClient()
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
    def test_01_list_own_instanceGrp(self):
        #  listInstanceGroups command should return owne's instance group

        self.debug("Listing instance group for account: %s" % self.account_1A.name)

        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )
        
        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp1A.name,
            "Instance group names do not match"
        )
        
        self.debug("Listing instance group for account: %s" % self.account_1B.name)

        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )
        
        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp1B.name,
            "Instance group names do not match"
        )
        
        self.debug("Listing instance group for account: %s" % self.account_2A.name)

        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )
        
        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp2A.name,
            "Instance group names do not match"
        )
        
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_instanceGrp(self):
 
        # Validate the following
        # 1. Grant domain2 IG access to account_1B
        # 2. listInstanceGroups command should return account_1B and domain_2 instance grps.

        self.debug("Granting Domain %s IG read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listInstanceGroups"
        domain_permission['entitytype'] = "InstanceGroup"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.ig_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing instance group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            2,
                            "Check instance group available in List Instance Groups"
                        )

        list_ig_names = [list_ig_response[0].name, list_ig_response[1].name]
        
        self.assertEqual( self.instancegrp1B.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )
        
        self.assertEqual( self.instancegrp2A.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )        
        
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_instanceGrp(self):
 
        # Validate the following
        # 1. Revoke domain2 ig access from account_1B
        # 2. listInstanceGroups command should not return account_2A instance grp

        self.debug("Revoking Domain %s ig read only access from account: %s" % (self.domain_2.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listInstanceGroups"
        domain_permission['entitytype'] = "InstanceGroup"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.ig_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing instance group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )
        
        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp1B.name,
            "Instance group names do not match"
        )
        
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_instanceGrp(self):
 
        # Validate the following
        # 1. Grant account_1A IG access to account_1B
        # 2. listInstanceGroups command should return account_1A and account_1B instance grps

        self.debug("Granting Account %s IG read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listInstanceGroups"
        account_permission['entitytype'] = "InstanceGroup"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.ig_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing instance groups for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            2,
                            "Check instance group available in List Instance Groups"
                        )

        list_ig_names = [list_ig_response[0].name, list_ig_response[1].name]
        
        self.assertEqual( self.instancegrp1B.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )
        
        self.assertEqual( self.instancegrp1A.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )    
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_instanceGrp(self):
 
        # Validate the following
        # 1. Revoke account_1A ig access from account_1B
        # 2. listInstanceGroups command should not return account_1A instance grp.

        self.debug("Revoking Account %s ig read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listInstanceGroups"
        account_permission['entitytype'] = "InstanceGroup"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.ig_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing instance group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )
        
        list_ig_names = [list_ig_response[0].name]
        
       
        self.assertEqual(self.instancegrp1A.name in list_ig_names,
                          False,
                          "Accessible instance group names do not match"
                          )   
         
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_resource_instanceGrp(self):
 
        # Validate the following
        # 1. Grant a particular ig access to account_1B
        # 2. listInstanceGroups command should return account_1B and granted instance grps.

        self.debug("Granting %s ig read only access to account: %s" % (self.instancegrp1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listInstanceGroups"
        res_permission['entitytype'] = "InstanceGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.instancegrp1A.id
        
        self.ig_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing instance group for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            2,
                            "Check instance group available in List Instance Groups"
                        )

        list_ig_names = [list_ig_response[0].name, list_ig_response[1].name]
        
        self.assertEqual( self.instancegrp1B.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )
        
        self.assertEqual( self.instancegrp1A.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )    
                
        return 
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_instanceGrp(self):
 
        # Validate the following
        # 1. Grant a particular ig access to account_1B
        # 2. listInstanceGroups command should return account_1B instance grps
        self.debug("Revoking %s ig read only access from account: %s" % (self.instancegrp1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listInstanceGroups"
        res_permission['entitytype'] = "InstanceGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.instancegrp1A.id
        self.ig_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing instance group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )

        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp1B.name,
            "Instance group names do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular ig access to account_1B by directly attaching policy to account
        # 2. listInstanceGroups command should return account_1B and granted instance grps

        self.debug("Granting %s ig read only access to account: %s by attaching policy to account" % (self.instancegrp1A.name, self.account_1B.name))

        res_permission = {}
        res_permission['action'] = "listInstanceGroups"
        res_permission['entitytype'] = "InstanceGroup"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.instancegrp1A.id
        self.ig_grant_policy.addPermission(self.apiclient, res_permission)
        self.ig_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing instance group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            2,
                            "Check instance group available in List Instance Groups"
                        )

        list_ig_names = [list_ig_response[0].name, list_ig_response[1].name]
        
        self.assertEqual( self.instancegrp1B.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )
        
        self.assertEqual( self.instancegrp1A.name in list_ig_names,
                          True,
                          "Accessible instance group names do not match"
                          )    
                
        return     
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular IG access from account_1B by detaching policy from account
        # 2. listInstanceGroups command should return account_1B instance grp

        self.debug("Revoking %s ig read only access from account: %s by detaching policy from account" % (self.instancegrp1A.name, self.account_1B.name))
        
        self.ig_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing instance group for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ig_response = list_instance_groups(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ig_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ig_response),
                            1,
                            "Check instance group available in List Instance Groups"
                        )

        self.assertEqual(
            list_ig_response[0].name,
            self.instancegrp1B.name,
            "Instance group names do not match"
        )
        
        return