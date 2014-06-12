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
    """Test Snapshots Life Cycle Services
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
            #data reqd for virtual machine creation
            "virtual_machine1A" : {
                "name" : "test1Avm",
                "displayname" : "Test1A  VM",
            },
            "virtual_machine1B" : {
                "name" : "test1Bvm",
                "displayname" : "Test1B  VM",
            }, 
            "virtual_machine2A" : {
                "name" : "test2Avm",
                "displayname" : "Test2A  VM",
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
            "service_desk_snapshot_iam_grp" : {
                "name" : "Service Desk snapshot",
                "description" : "Service Desk snapshot IAM Group"
            },
            "snapshot_readonly_iam_policy" : {
                "name" : "snapshot Read Only Access",
                "description" : "snapshot read only access iam policy"
            },
#            "disk_offering": {
#               "name": "Disk offering",
#               "displaytext": "Disk offering",
#               "disksize": 1
#            },
        }



class TestSnapshotIam(cloudstackTestCase):

    @classmethod
    def setUpClass(self):
        testClient = super(TestSnapshotIam, self).getClsTestClient()
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
        self.service_offering = ServiceOffering.create(
                                self.apiclient,
                                self.services["service_offering"]["small"]
                                )
                                
        self.zone = get_zone(self.apiclient, testClient.getZoneForTests())
        self.services['mode'] = self.zone.networktype
        self.template = get_template(self.apiclient, self.zone.id, self.services["ostype"])

        # deploy 3 VMs for three accounts
        self.virtual_machine_1A = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine1A"],
            accountid=self.account_1A.name,
            zoneid=self.zone.id,
            domainid=self.account_1A.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )  
        
        self.virtual_machine_1B = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine1B"],
            accountid=self.account_1B.name,
            zoneid=self.zone.id,
            domainid=self.account_1B.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )  
        
        self.virtual_machine_2A = VirtualMachine.create(
            self.apiclient,
            self.services["virtual_machine2A"],
            accountid=self.account_2A.name,
            zoneid=self.zone.id,
            domainid=self.account_2A.domainid,
            serviceofferingid=self.service_offering.id,
            templateid=self.template.id
        )   

        self.volume_1A = list_volumes(
                            self.apiclient,
                            virtualmachineid=self.virtual_machine_1A.id,
                            type='ROOT',
                            listall=True
                            )

        self.volume_1B = list_volumes(
                            self.apiclient,
                            virtualmachineid=self.virtual_machine_1B.id,
                            type='ROOT',
                            listall=True
                            )

        self.volume_2A = list_volumes(
                            self.apiclient,
                            virtualmachineid=self.virtual_machine_2A.id,
                            type='ROOT',
                            listall=True
                            )
        
        self.snapshot_1A = Snapshot.create(
                                   self.apiclient,
                                   self.volume_1A[0].id,
                                   account=self.account_1A.name,
                                   domainid=self.account_1A.domainid
                                   )

        self.snapshot_1B = Snapshot.create(
                                   self.apiclient,
                                   self.volume_1B[0].id,
                                   account=self.account_1B.name,
                                   domainid=self.account_1B.domainid
                                   )

        self.snapshot_2A = Snapshot.create(
                                   self.apiclient,
                                   self.volume_2A[0].id,
                                   account=self.account_2A.name,
                                   domainid=self.account_2A.domainid
                                   )

        
        self.srv_desk_grp = IAMGroup.create(
            self.apiclient, 
            self.services["service_desk_snapshot_iam_grp"]
        )                             

        self.snapshot_read_policy = IAMPolicy.create(
            self.apiclient, 
            self.services["snapshot_readonly_iam_policy"]
        )
        
        self.srv_desk_grp.attachPolicy(
            self.apiclient, [self.snapshot_read_policy]
        )
        
        snapshot_grant_policy_params = {}
        snapshot_grant_policy_params['name'] = "policyGrantsnapshot" + self.account_1A.name
        snapshot_grant_policy_params['description'] = "Policy to grant permission to snapshot " + self.account_1A.name
        self.snapshot_grant_policy = IAMPolicy.create(
            self.apiclient, 
            snapshot_grant_policy_params
        )   
        
        self._cleanup = [
                        self.account_1A,
                        self.account_1B,
                        self.domain_1,
                        self.account_2A,
                        self.domain_2,
                        self.service_offering,
                        self.snapshot_read_policy,
                        self.srv_desk_grp,
                        self.snapshot_grant_policy,
                        self.virtual_machine_1A,
                        self.virtual_machine_1B,
                        self.virtual_machine_2A,
                        self.snapshot_1A,
                        self.snapshot_1B,
                        self.snapshot_2A
                        ]

    @classmethod
    def tearDownClass(self):
        self.apiclient = super(TestSnapshotIam, self).getClsTestClient().getApiClient()
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
    def test_01_list_own_snapshot(self):
        #  listsnapshots command should return owne's Snapshots

        self.debug("Listing snapshot for account: %s" % self.account_1A.name)

        self.apiclient.connection.apiKey = self.user_1A_apikey
        self.apiclient.connection.securityKey = self.user_1A_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List snapshots"
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_1A.name,
            "snapshot name do not match"
        )

        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List snapshots "
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_1B.name,
            "snapshot names do not match"
        )
        
        self.debug("Listing snapshot for account: %s" % self.account_2A.name)

        self.apiclient.connection.apiKey = self.user_2A_apikey
        self.apiclient.connection.securityKey = self.user_2A_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List snapshots"
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_2A.name,
            "Snapshot names do not match"
        )
                
        return
        
        
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_02_grant_domain_snapshot(self):
 
        # Validate the following
        # 1. Grant domain2 snapshot access to account_1B
        # 2. listsnapshot command should return account_1B and domain_2 snapshots.

        self.debug("Granting Domain %s snapshot read only access to account: %s" % (self.domain_2.name, self.account_1B.name))
        
        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        
        domain_permission = {}
        domain_permission['action'] = "listSnapshots"
        domain_permission['entitytype'] = "Snapshot"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.snapshot_read_policy.addPermission(self.apiclient, domain_permission)
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            2,
                            "Check snapshot available in List Snapshot"
                        )

        list_snapshot_names = [list_snapshot_response[0].name, list_snapshot_response[1].name]
        
        self.assertEqual( self.snapshot_1B.name in list_snapshot_names,
                          True,
                          "Accessible Snapshot names do not match"
                          )
        
        self.assertEqual( self.snapshot_2A.name in list_snapshot_names,
                          True,
                          "Accessible Snapshot names do not match"
                          )        
        return

        
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_03_revoke_domain_snapshot(self):
 
        # Validate the following
        # 1. Revoke account_1A snapshot access from account_1B
        # 2. listsnapshot command should not return account_1A snapshots.

        self.debug("Revoking Domain %s snapshot read only access from account: %s" % (self.domain_1.name, self.account_1B.name))
        
        domain_permission = {}
        domain_permission['action'] = "listSnapshots"
        domain_permission['entitytype'] = "Snapshot"
        domain_permission['scope'] = "DOMAIN"
        domain_permission['scopeid'] = self.domain_2.id
        self.snapshot_read_policy.removePermission(self.apiclient, domain_permission)
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List snapshots"
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_1B.name,
            "Snapshot names do not match"
        )
         
        return    


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_04_grant_account_snapshot(self):
 
        # Validate the following
        # 1. Grant account_1A snapshot access to account_1B
        # 2. listsnapshot command should return account_1A and account_1B snapshots.

        self.debug("Granting Account %s snapshot read only access to account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listSnapshots"
        account_permission['entitytype'] = "Snapshot"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.snapshot_read_policy.addPermission(self.apiclient, account_permission)
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            2,
                            "Check snapshot available in List Snapshot"
                        )

        list_snapshot_names = [list_snapshot_response[0].name, list_snapshot_response[1].name]
        
        self.assertEqual( self.snapshot_1B.name in list_snapshot_names,
                          True,
                          "Accessible Snapshot names do not match"
                          )
        
        self.assertEqual( self.snapshot_1A.name in list_snapshot_names,
                          True,
                          "Accessible Snapshot names do not match"
                          )    
                
        return


    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_05_revoke_account_snapshot(self):
 
        # Validate the following
        # 1. Revoke account_1A snapshot access from account_1B
        # 2. listsnapshot command should not return account_1A snapshots.

        self.debug("Revoking Account %s snapshot read only access from account: %s" % (self.account_1A.name, self.account_1B.name))
        
        account_permission = {}
        account_permission['action'] = "listSnapshots"
        account_permission['entitytype'] = "Snapshot"
        account_permission['scope'] = "ACCOUNT"
        account_permission['scopeid'] = self.account_1A.id
        self.snapshot_read_policy.removePermission(self.apiclient, account_permission)
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List Snapshot"
                        )

        list_snapshot_names = [list_snapshot_response[0].name]
        
       
        self.assertEqual( self.snapshot_1A.name in list_snapshot_names,
                          False,
                          "Accessible Snapshot names do not match"
                          )    
        return


#    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
#    def test_06_grant_resource_snapshot(self):
 
        # Validate the following
        # 1. Grant a particular snapshot access to account_1B
        # 2. listsnapshot command should return account_1B snapshots and granted snapshot.

#        self.debug("Granting snapshot %s read only access to account: %s" % (self.snapshot_1A.name, self.account_1B.name))
        
#        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
        
#        res_permission = {}
#        res_permission['action'] = "listSnapshots"
#        res_permission['entitytype'] = "Snapshot"
#        res_permission['scope'] = "RESOURCE"
#        res_permission['scopeid'] = self.snapshot_1A.id
#        self.snapshot_read_policy.addPermission(self.apiclient, res_permission)
#        self.snapshot_read_policy.attachAccount(self.apiclient, [self.account_1B])
        
#        self.debug("Listing snapshot for account: %s" % self.account_1B.name)
#        self.apiclient.connection.apiKey = self.user_1B_apikey
#        self.apiclient.connection.securityKey = self.user_1B_secretkey
#        list_snapshot_response = list_snapshots(
#                                            self.apiclient
#                                            )
#        self.assertEqual(
#                            isinstance(list_snapshot_response, list),
#                            True,
#                            "Check list response returns a valid list"
#                        )
#        self.debug("snapshot list length : %d" %len(list_snapshot_response))
#        self.debug("list item from the snapshot list : %s" % (list_snapshot_response[0].name))
#        self.assertEqual(
#                            len(list_snapshot_response),
#                            2,
#                            "Check snapshot available in List Snapshots"
#                        )

#        list_snapshot_names = [list_snapshot_response[0].name, list_snapshot_response[1].name]
        
#        self.assertEqual( self.snapshot_1B.name in list_snapshot_names,
#                          True,
#                          "Accessible Snapshot names do not match"
#                          )
        
#        self.assertEqual( self.snapshot_1A.name in list_snapshot_names,
#                          True,
#                          "Accessible Snapshot names do not match"
#                          )    
                
#        return    
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_07_revoke_resource_snapshot(self):
 
        # Validate the following
        # 1. Grant a particular snapshot access to account_1B
        # 2. listsnapshot command should return account_1B snapshots and granted snapshot.

        self.debug("Revoking snapshot %s read only access from account: %s" % (self.virtual_machine_1A.name, self.account_1B.name))
        
        res_permission = {}
        res_permission['action'] = "listSnapshots"
        res_permission['entitytype'] = "Snapshot"
        res_permission['scope'] = "RESOURCE"
        res_permission['scopeid'] = self.snapshot_1A.id
        self.snapshot_read_policy.removePermission(self.apiclient, res_permission)
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List Snapshots"
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_1B.name,
            "Snapshot names do not match"
        )
        
        return

#    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
#    def test_08_policy_attach_account(self):
 
        # Validate the following
        # 1. Grant a particular snapshot access to account_1B by directly attaching policy to account
        # 2. listsnapshot command should return account_1B snapshots and granted snapshot.

#        self.debug("Granting snapshot %s read only access to account: %s by attaching policy to account" % (self.snapshot_1A.name, self.account_1B.name))
        
#        self.srv_desk_grp.addAccount(self.apiclient, [self.account_1B])
#        res_permission = {}
#        res_permission['action'] = "listSnapshots"
#        res_permission['entitytype'] = "Snapshot"
#        res_permission['scope'] = "RESOURCE"
#        res_permission['scopeid'] = self.snapshot_1A.id
#        self.snapshot_grant_policy.addPermission(self.apiclient, res_permission)
#        self.snapshot_grant_policy.attachAccount(self.apiclient, [self.account_1B])
        
#        self.debug("Listing snapshot for account: %s" % self.account_1B.id)
#        self.apiclient.connection.apiKey = self.user_1B_apikey
#        self.apiclient.connection.securityKey = self.user_1B_secretkey
#        list_snapshot_response = list_snapshots(
#                                            self.apiclient
#                                            )
#        self.assertEqual(
#                            isinstance(list_snapshot_response, list),
#                            True,
#                            "Check list response returns a valid list"
#                        )
#        self.assertEqual(
#                            len(list_snapshot_response),
#                            2,
#                            "Check snapshot available in List snapshots"
#                        )

#        list_snapshot_names = [list_snapshot_response[0].name, list_snapshot_response[1].name]
        
#        self.assertEqual( self.snapshot_1B.name in list_snapshot_names,
#                          True,
#                          "Accessible snapshot names do not match"
#                          )
        
#        self.assertEqual( self.snapshot_1A.name in list_snapshot_names,
#                          True,
#                          "Accessible snapshot names do not match"
#                          )    
                
#        return     
    
    @attr(tags = ["devcloud", "advanced", "advancedns", "smoke", "basic", "sg", "selfservice"])
    def test_09_policy_detach_account(self):
 
        # Validate the following
        # 1. Revoking a particular snapshot access from account_1B by detaching policy from account
        # 2. listsnapshot command should return account_1B snapshots.

        self.debug("Revoking snapshot %s read only access from account: %s by detaching policy from account" % (self.snapshot_1A.name, self.account_1B.name))
        
        self.snapshot_grant_policy.detachAccount(self.apiclient, [self.account_1B])
        
        self.debug("Listing snapshot for account: %s" % self.account_1B.id)
        self.apiclient.connection.apiKey = self.user_1B_apikey
        self.apiclient.connection.securityKey = self.user_1B_secretkey
        list_snapshot_response = list_snapshots(
                                            self.apiclient
                                            )
        self.assertEqual(
                            isinstance(list_snapshot_response, list),
                            True,
                            "Check list response returns a valid list"
                        )
        self.assertEqual(
                            len(list_snapshot_response),
                            1,
                            "Check snapshot available in List snapshots"
                        )

        self.assertEqual(
            list_snapshot_response[0].name,
            self.snapshot_1B.name,
            "snapshot names do not match"
        )
        
        return       
        
  
