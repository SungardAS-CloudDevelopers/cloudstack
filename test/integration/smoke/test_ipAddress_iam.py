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
""" BVT tests for IP Address IAM effect
"""
import marvin
from marvin.cloudstackTestCase import *
from marvin.cloudstackAPI import *
from marvin.lib.utils import *
from marvin.lib.base import *
from marvin.lib.common import *
from marvin.codes import FAILED
from nose.plugins.attrib import attr
import time

_multiprocess_shared_ = True
class Services:
    """Test IP Address Life Cycle Services
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
                         
            # Data required for IP Address Creation
            
            "network1A": {
                "name": "Test Network1A",
                "displaytext": "Test Network1A",
            },
            
            "network1B": {
                "name": "Test Network1B",
                "displaytext": "Test Network1B",
            },
                         
            "network2A": {
                "name": "Test Network2A",
                "displaytext": "Test Network2A",
            },
                         
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
                         
            # iam group and policy information
            "service_desk_iam_ip_grp" : {
                "name" : "Service Desk",
                "description" : "Service Desk IAM IP Address Group"
            },
            "ip_readonly_iam_policy" : {
                "name" : "IP Read Only Access",
                "description" : "IP read only access iam policy"
            },
     }
        
class TestIPIam(cloudstackTestCase):

    @classmethod
    def setUpClass(self):
        testClient = super(TestIPIam, self).getClsTestClient()
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
                
        # create service offering
        self.zone = get_zone(self.apiclient, testClient.getZoneForTests())
        self.services['mode'] = self.zone.networktype
        
        #Create 3 IP address for 3 accounts
        
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
        
        # Create IP Address for account 1A
        
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
        
        #Create ip address for account1B
        
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
        
        #Create ip address for account2A
        
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
        
        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_iam_ip_grp"]
        )                             

        self.ip_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["ip_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.ip_read_policy]
        )
        
        ip_grant_policy_params = {}
        ip_grant_policy_params['name'] = "policyGrantIPAddress" + self.public_ip1A.ipaddress.id
        ip_grant_policy_params['description'] = "Policy to grant permission to IP Address" + self.public_ip1A.ipaddress.id
        self.ip_grant_policy = IAMPolicy.create(
            self.apiclient, 
            ip_grant_policy_params
        ) 
        
        self._cleanup = [
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.account_2A,
                        self.domain_2,
                        self.network_offering,
                        self.ip_read_policy,
                        self.srv_desk_grp,
                        self.ip_grant_policy
                        ]
         
    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestIPIam, self).getClsTestClient().getApiClient()
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
    def test_01_list_own_ipAddress(self):
        #  listPublicIpAddresses command should return own ip address

        self.debug("Listing IP address for account: %s" % self.account_1A.name)
        
        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_ip_response = list_publicIP(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        
        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip1A.ipaddress.ipaddress,
            "IP Address do not match"
        )
        
        self.debug("Listing IP address for account: %s" % self.account_1B.name)

        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        

        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip1B.ipaddress.ipaddress,
            "IP Address do not match"
        )
        
        self.debug("Listing IP address for account: %s" % self.account_2A.name)

        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_ip_response = list_publicIP(
                                           self.apiclient
                                          )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        

        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip2A.ipaddress.ipaddress,
            "IP Address do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_ipAddress(self):
 
        # Validate the following
        # 1. Grant domain2 ip address access to account_1B
        # 2. listPublicIpAddresses command should return account_1B and domain_2 ipAddress.

        self.debug("Granting Domain %s ipAddress read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        domain_permission = {}
        domain_permission['action'] = "listPublicIpAddresses"
        domain_permission['entitytype'] = "IpAddress"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.ip_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ip_response),
                            2,
                            "Check ip address available in List Public IP Addresses"
                        )

        list_ip_names = [list_ip_response[0].ipaddress, list_ip_response[1].ipaddress]
        
        self.assertEqual( self.public_ip1B.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )
        
        self.assertEqual( self.public_ip2A.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )
        return
    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_ipAddress(self):
 
        # Validate the following
        # 1. Revoke domain2 ip address access from account_1B
        # 2. listPublicIpAddresses command should not return account_2A ip address.

        self.debug("Revoking Domain %s ip read only access from account: %s" % (self.domain_2.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listPublicIpAddresses"
        domain_permission['entitytype'] = "IpAddress"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.ip_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        
        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip1B.ipaddress.ipaddress,
            "Ip address do not match"
        )
        
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_ipAddress(self):
 
        # Validate the following
        # 1. Grant account_1A ip address access to account_1B
        # 2. listPublicIpAddresses command should return account_1A and account_1B ip addresss.

        self.debug("Granting Account %s ip read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listPublicIpAddresses"
        account_permission['entitytype'] = "IpAddress"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.ip_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ip_response),
                            2,
                            "Check ip address available in List Public IP Addresses"
                        )
        

        list_ip_names = [list_ip_response[0].ipaddress, list_ip_response[1].ipaddress]
        
        self.assertEqual( self.public_ip1B.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )
        
        self.assertEqual( self.public_ip1A.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )    
                
        return
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_ipAddress(self):
 
        # Validate the following
        # 1. Revoke account_1A ip address access from account_1B
        # 2. listPublicIpAddresses command should not return account_1A ip address.

        self.debug("Revoking Account %s ip read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listPublicIpAddresses"
        account_permission['entitytype'] = "IpAddress"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.ip_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                       self.apiclient
                                       )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        
        list_ip_names = [list_ip_response[0].ipaddress]
        
       
        self.assertEqual(self.public_ip1A.ipaddress.ipaddress in list_ip_names,
                          False,
                          "Accessible ip address do not match"
                          )   
         
        return
    
    """
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_06_grant_resource_ipAddress(self):
 
        # Validate the following
        # 1. Grant a particular ip address access to account_1B
        # 2. listPublicIpAddresses command should return account_1B ip addresss and granted ip address.

        self.debug("Granting ip address %s read only access to account: %s" % (self.public_ip1A.ipaddress.ipaddress, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPublicIpAddresses"
        res_permission['entitytype'] = "IpAddress"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.public_ip1A.ipaddress.id
        
        self.ip_read_policy.addPermission(self.apiclient, res_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )

        list_ip_names = [list_ip_response[0].ipaddress]
        
        self.assertEqual( self.public_ip1B.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )
        
        self.assertEqual( self.public_ip1A.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address do not match"
                          )
                
        return  
    
    """
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_ipAddress(self):
 
        # Validate the following
        # 1. Grant a particular ip address access to account_1B
        # 2. listPublicIpAddresses command should return account_1B ip addresss
        self.debug("Revoking ip address %s read only access from account: %s" % (self.public_ip1A.ipaddress.ipaddress, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPublicIpAddresses"
        res_permission['entitytype'] = "IpAddress"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.public_ip1A.ipaddress.id
        self.ip_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing ip address for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )
        
        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip1B.ipaddress.ipaddress,
            "ip address ports do not match"
        )
        
        return
    
    """
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular ip address access to account_1B by directly attaching policy to account
        # 2. listPublicIpAddresses command should return account_1B ip addresss and granted ip address

        self.debug("Granting ip address %s read only access to account: %s by attaching policy to account" % (self.public_ip1A.ipaddress.ipaddress, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listPublicIpAddresses"
        res_permission['entitytype'] = "IpAddress"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.public_ip1A.ipaddress.id
        self.ip_grant_policy.addPermission(self.apiclient, res_permission)
        self.ip_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing ip address for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            2,
                            "Check ip address available in List Public IP Addresses"
                        )

        list_ip_names = [list_ip_response[0].ipaddress, list_ip_response[1].ipaddress]
        
        self.assertEqual( self.public_ip1B.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address ports do not match"
                          )
        
        self.assertEqual( self.public_ip1A.ipaddress.ipaddress in list_ip_names,
                          True,
                          "Accessible ip address ports do not match"
                          )    
                
        return  
        
    """   
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular ip address access from account_1B by detaching policy from account
        # 2. listPublicIpAddresses command should return account_1B ip addresss.

        self.debug("Revoking ip address %s read only access from account: %s by detaching policy from account" % (self.public_ip1A.ipaddress.ipaddress, self.account_1B.name))
        
        self.ip_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing ip address for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_ip_response = list_publicIP(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_ip_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_ip_response),
                            1,
                            "Check ip address available in List Public IP Addresses"
                        )

        self.assertEqual(
            list_ip_response[0].ipaddress,
            self.public_ip1B.ipaddress.ipaddress,
            "ip address ports do not match"
        )
        
        return
        
