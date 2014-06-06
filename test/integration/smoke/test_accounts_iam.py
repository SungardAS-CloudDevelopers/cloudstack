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
"""BVT tests for Account IAM effect
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
    """Test list Accounts Life Cycle Services
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
            
            # iam group and policy information
            "service_desk_iam_account_grp" : {
                "name" : "Service Desk",
                "description" : "Service Desk IAM Account Group"
            },
            "account_readonly_iam_policy" : {
                "name" : "Account Read Only Access",
                "description" : "Account read only access iam policy"
            },
        
       }
        
class TestAccountIam(cloudstackTestCase):
    
    @classmethod
    def setUpClass(self):
        testClient = super(TestAccountIam, self).getClsTestClient()
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
        
        self.zone = get_zone(self.apiclient, testClient.getZoneForTests())
        self.services['mode'] = self.zone.networktype
        
        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_iam_account_grp"]
        )                             

        self.account_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["account_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.account_read_policy]
        )
        
        account_grant_policy_params = {}
        account_grant_policy_params['name'] = "policyGrantAccount" + self.account_1A.id
        account_grant_policy_params['description'] = "Policy to grant permission to Account" + self.account_1A.id
        self.account_grant_policy = IAMPolicy.create(
            self.apiclient, 
            account_grant_policy_params
        )   
        
        self._cleanup = [
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.account_2A,
                        self.domain_2,
                        self.account_read_policy,
                        self.srv_desk_grp,
                        self.account_grant_policy
                        ]
         
    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestAccountIam, self).getClsTestClient().getApiClient()
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
    def test_01_list_own_account(self):
        #  listAccounts command should return own Accounts

        self.debug("Listing account for account: %s" % self.account_1A.name)

        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )
        
        self.assertEqual(
            list_accounts_response[0].name,
            self.account_1A.name,
            "Account names do not match"
        )
        
        self.debug("Listing account for account: %s" % self.domain_1.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )

        self.assertEqual(
            list_accounts_response[0].name,
            self.account_1B.name,
            "Account names do not match"
        )
        
        self.debug("Listing account for account: %s" % self.domain_2.name)
        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )

        self.assertEqual(
            list_accounts_response[0].name,
            self.account_2A.name,
            "Account names do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_account(self):
 
        # Validate the following
        # 1. Grant domain2 account access to account_1B
        # 2. listAccounts command should return account_1B and domain_2 accounts.

        self.debug("Granting Domain %s account read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listAccounts"
        domain_permission['entitytype'] = "Account"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.account_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing account for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_accounts_response),
                            2,
                            "Check account available in List Accounts"
                        )

        list_account_names = [list_accounts_response[0].name, list_accounts_response[1].name]
        
        self.assertEqual( self.account_1B.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )
        
        self.assertEqual( self.account_2A.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_account(self):
 
        # Validate the following
        # 1. Revoke domain2 account access from account_1B
        # 2. listAccounts command should not return account_2A accounts.

        self.debug("Revoking Domain %s account read only access from account: %s" % (self.domain_2.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listAccounts"
        domain_permission['entitytype'] = "Account"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.account_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing Account for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )
        
        self.assertEqual(
            list_accounts_response[0].name,
            self.account_1B.name,
            "Account names do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_account(self):
 
        # Validate the following
        # 1. Grant account_1A account access to account_1B
        # 2. listAccount command should return account_1A and account_1B accounts.

        self.debug("Granting Account %s account read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listAccounts"
        account_permission['entitytype'] = "Account"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.account_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing account for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_accounts_response),
                            2,
                            "Check account available in List Accounts"
                        )
        

        list_account_names = [list_accounts_response[0].name, list_accounts_response[1].name]
        
        self.assertEqual( self.account_1B.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )
        
        self.assertEqual( self.account_1A.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )    
                
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_account(self):
 
        # Validate the following
        # 1. Revoke account_1A account access from account_1B
        # 2. listAccounts command should not return account_1A account.

        self.debug("Revoking Account %s account read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listAccounts"
        account_permission['entitytype'] = "Account"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.account_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing account for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )
        
        list_account_names = [list_accounts_response[0].name]
        
       
        self.assertEqual( self.account_1A.name in list_account_names,
                          False,
                          "Accessible Resource Account names do not match"
                          )   
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_resource_account(self):
 
        # Validate the following
        # 1. Grant a particular account access to account_1B
        # 2. listAccounts command should return account_1B account and granted account.

        self.debug("Granting account %s read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listAccounts"
        res_permission['entitytype'] = "Account"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A.id
        self.account_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing account for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
                        
        self.assertEqual(
                            len(list_accounts_response),
                            2,
                            "Check account available in List Accounts"
                        )
        
        list_account_names = [list_accounts_response[0].name, list_accounts_response[1].name]
        
        self.assertEqual( self.account_1B.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )
        
        self.assertEqual( self.account_1A.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )    
                          
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_account(self):
 
        # Validate the following
        # 1. Grant a particular account access to account_1B
        # 2. listAccounts command should return account_1B accounts and granted account.

        self.debug("Revoking account %s read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listAccounts"
        res_permission['entitytype'] = "Account"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A.id
        self.account_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing account for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )

        self.assertEqual(
            list_accounts_response[0].name,
            self.account_1B.name,
            "Account names do not match"
        )
        
        return
        
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular account access to account_1B by directly attaching policy to account
        # 2. listAccounts command should return account_1B account and granted account.

        self.debug("Granting account %s read only access to account: %s by attaching policy to account" % (self.account_1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listAccounts"
        res_permission['entitytype'] = "Account"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.account_1A.id
        self.account_grant_policy.addPermission(self.apiclient, res_permission)
        self.account_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing account for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            2,
                            "Check account available in List Accounts"
                        )

        list_account_names = [list_accounts_response[0].name, list_accounts_response[1].name]
        
        self.assertEqual( self.account_1B.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )
        
        self.assertEqual( self.account_1A.name in list_account_names,
                          True,
                          "Accessible Account names do not match"
                          )    
                
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular account access from account_1B by detaching policy from account
        # 2. listAccounts command should return account_1B account.

        self.debug("Revoking account %s read only access from account: %s by detaching policy from account" % (self.account_1A.name, self.account_1B.name))
        
        self.account_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing account for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_accounts_response = list_accounts(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_accounts_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_accounts_response),
                            1,
                            "Check account available in List Accounts"
                        )

        self.assertEqual(
            list_accounts_response[0].name,
            self.account_1B.name,
            "Account names do not match"
        )
        
        return
