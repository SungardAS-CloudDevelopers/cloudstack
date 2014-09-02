-- Licensed to the Apache Software Foundation (ASF) under one
-- or more contributor license agreements.  See the NOTICE file
-- distributed with this work for additional information
-- regarding copyright ownership.  The ASF licenses this file
-- to you under the Apache License, Version 2.0 (the
-- "License"); you may not use this file except in compliance
-- with the License.  You may obtain a copy of the License at
--
--   http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing,
-- software distributed under the License is distributed on an
-- "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
-- KIND, either express or implied.  See the License for the
-- specific language governing permissions and limitations
-- under the License.

--;
-- Schema upgrade from 4.3.0 to 4.3.1;
--;

alter table user_ip_address add column removed datetime DEFAULT NULL COMMENT 'date removed';
alter table user_ip_address add column created datetime NULL COMMENT 'date created';

alter table vlan add column removed datetime DEFAULT NULL COMMENT 'date removed';
alter table vlan add column created datetime NULL COMMENT 'date created';

alter table user_ip_address drop key public_ip_address;
alter table user_ip_address add UNIQUE KEY public_ip_address (public_ip_address,source_network_id, removed);
