#!/usr/bin/env bash
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

# guestnw.sh -- create/destroy guest network 
# @VERSION@

source /root/func.sh
source /opt/cloud/bin/vpc_func.sh

lock="biglock"
locked=$(getLockFile $lock)
if [ "$locked" != "1" ]
then
    exit 1
fi

usage() {
  printf "Usage:\n %s -A -d <dev> -i <ip address> -g <gateway> -m <network mask> -s <dns ip> -e < domain> [-f] \n" $(basename $0) >&2
  printf " %s -D -d <dev> -i <ip address> \n" $(basename $0) >&2
#TODO add additional usage patterns to correspond to filters below.
}


destroy_acl_chain() {
  sudo iptables -t mangle -F ACL_OUTBOUND_$dev 2>/dev/null
  sudo iptables -t mangle -D PREROUTING -m state --state NEW -i $dev -s $subnet/$mask ! -d $ip -j ACL_OUTBOUND_$dev  2>/dev/null
  sudo iptables -t mangle -X ACL_OUTBOUND_$dev 2>/dev/null
  sudo iptables -F ACL_INBOUND_$dev 2>/dev/null
  sudo iptables -D FORWARD -o $dev -d $subnet/$mask -j ACL_INBOUND_$dev  2>/dev/null
  sudo iptables -X ACL_INBOUND_$dev 2>/dev/null

}

create_acl_chain() {
  destroy_acl_chain
  sudo iptables -t mangle -N ACL_OUTBOUND_$dev 2>/dev/null
  sudo iptables -t mangle -A ACL_OUTBOUND_$dev -j ACCEPT 2>/dev/null
  sudo iptables -t mangle -A PREROUTING -m state --state NEW -i $dev -s $subnet/$mask ! -d $ip -j ACL_OUTBOUND_$dev  2>/dev/null
  sudo iptables -N ACL_INBOUND_$dev 2>/dev/null
  # drop if no rules match (this will be the last rule in the chain)
  sudo iptables -A ACL_INBOUND_$dev -j DROP 2>/dev/null
  sudo iptables -A FORWARD -o $dev -d $subnet/$mask -j ACL_INBOUND_$dev  2>/dev/null
}


setup_apache2() {
  logger -t cloud "Setting up apache web server for $dev"
  cp /etc/apache2/vhostexample.conf /etc/apache2/conf.d/vhost$dev.conf
  sed -i -e "s/<VirtualHost.*:80>/<VirtualHost $ip:80>/" /etc/apache2/conf.d/vhost$dev.conf
  sed -i -e "s/<VirtualHost.*:443>/<VirtualHost $ip:443>/" /etc/apache2/conf.d/vhost$dev.conf
  sed -i -e "s/\tServerName.*/\tServerName vhost$dev.cloudinternal.com/" /etc/apache2/conf.d/vhost$dev.conf
  sed -i -e "s/Listen .*:80/Listen $ip:80/g" /etc/apache2/conf.d/vhost$dev.conf
  sed -i -e "s/Listen .*:443/Listen $ip:443/g" /etc/apache2/conf.d/vhost$dev.conf
  service apache2 restart
  sudo iptables -D INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 80 -j ACCEPT
  sudo iptables -A INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 80 -j ACCEPT
}

desetup_apache2() {
  logger -t cloud "Desetting up apache web server for $dev"
  rm -f /etc/apache2/conf.d/vhost$dev.conf
  service apache2 restart
  sudo iptables -D INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 80 -j ACCEPT
}


setup_dnsmasq() {
  logger -t cloud "Setting up dnsmasq for network $ip/$mask "
  # setup rules to allow dhcp/dns request
  sudo iptables -D INPUT -i $dev -p udp -m udp --dport 67 -j ACCEPT
  sudo iptables -D INPUT -i $dev -d $ip -p udp -m udp --dport 53 -j ACCEPT
  sudo iptables -D INPUT -i $dev -d $ip -p tcp -m tcp --dport 53 -j ACCEPT
  sudo iptables -A INPUT -i $dev -p udp -m udp --dport 67 -j ACCEPT
  sudo iptables -A INPUT -i $dev -d $ip -p udp -m udp --dport 53 -j ACCEPT
  sudo iptables -A INPUT -i $dev -d $ip -p tcp -m tcp --dport 53 -j ACCEPT
  # setup static 
  sed -i -e "/^[#]*dhcp-range=interface:$dev/d" /etc/dnsmasq.d/cloud.conf
  echo "dhcp-range=interface:$dev,set:interface-$dev,$ip,static" >> /etc/dnsmasq.d/cloud.conf
  # setup DOMAIN
  [ -z $DOMAIN ] && DOMAIN="cloudnine.internal"

  sed -i -e "/^[#]*dhcp-option=tag:interface-$dev,15.*$/d" /etc/dnsmasq.d/cloud.conf
  echo "dhcp-option=tag:interface-$dev,15,$DOMAIN" >> /etc/dnsmasq.d/cloud.conf
  service dnsmasq restart
  sleep 1
} 

desetup_dnsmasq() {
  logger -t cloud "Desetting up dnsmasq for network $ip/$mask "
  # remove rules to allow dhcp/dns request
  sudo iptables -D INPUT -i $dev -p udp -m udp --dport 67 -j ACCEPT
  sudo iptables -D INPUT -i $dev -d $ip -p udp -m udp --dport 53 -j ACCEPT
  sed -i -e "/^[#]*dhcp-option=tag:interface-$dev,option:router.*$/d" /etc/dnsmasq.d/cloud.conf
  sed -i -e "/^[#]*dhcp-option=tag:interface-$dev,6.*$/d" /etc/dnsmasq.d/cloud.conf
  sed -i -e "/^[#]*dhcp-range=interface:$dev/d" /etc/dnsmasq.d/cloud.conf
  service dnsmasq restart
  sleep 1
}

setup_passwdsvcs() {
  logger -t cloud "Setting up password service for network $ip/$mask, eth $dev "
  sudo iptables -D INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 8080 -j ACCEPT
  sudo iptables -A INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 8080 -j ACCEPT
  nohup bash /opt/cloud/bin/vpc_passwd_server $ip >/dev/null 2>&1 &
}

desetup_passwdsvcs() {
  logger -t cloud "Desetting up password service for network $ip/$mask, eth $dev "
  sudo iptables -D INPUT -i $dev -d $ip -p tcp -m state --state NEW --dport 8080 -j ACCEPT
  pid=`ps -ef | grep socat | grep $ip | grep -v grep | awk '{print $2}'`
  if [ -n "$pid" ]
  then
    kill -9 $pid
  fi 
}

# TODO add redundant router code for create/destroy
# need to check if redundant router already exists for current
#network
create_redundant_guest_network() {
	echo -t cloud "Creating Redundant Guest Network"
	
#Check if this guest network already exists.
#If it does then
#	Check if redundant router already exists on this network
#	If no redundant router
#		Stop existing router for this guest network
#		Create a redundant router for this guest network
#		Configure Keepalived
#		Configure Conntrackd
#		Reconfigure existing (master) router (???)
#		Start existing (master) Router
#		Start backup Router
#		Start Keepalived
#		Start Conntrackd
#	fi
#else
#	Create a new guest network
#	Create a redundant router for new guest network
#	Configure Keepalived
#	Configure Conntrackd
#	Start master router
#	Start backup router
#	Start Keepalived
#	Start Conntrackd
#fi
}



create_guest_network() {
  # need to wait for eth device to appear before configuring it
  timer=0
  while ! `grep -q $dev /proc/net/dev` ; do
    logger -t cloud "$(basename $0):Waiting for interface $dev to appear, $timer seconds"
    sleep 1;
    if [ $timer -gt 15 ]; then
      logger -t cloud "$(basename $0):interface $dev never appeared"
      break
    fi
    timer=$[timer + 1]
  done

  logger -t cloud " $(basename $0): Create network on interface $dev,  gateway $gw, network $ip/$mask "
  # setup ip configuration
  sudo ip addr add dev $dev $ip/$mask brd +
  sudo ip link set $dev up
  sudo arping -c 3 -I $dev -A -U -s $ip $ip
  echo 1 > /proc/sys/net/ipv4/conf/$dev/rp_filter
  # restore mark from  connection mark
  local tableName="Table_$dev"
  sudo ip route add $subnet/$mask dev $dev table $tableName proto static
  sudo iptables -t mangle -D PREROUTING -i $dev -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
  sudo iptables -t nat -D POSTROUTING -s $subnet/$mask -o $dev -j SNAT --to-source $ip
  sudo iptables -t mangle -A PREROUTING -i $dev -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
  # set up hairpin
  sudo iptables -t nat -A POSTROUTING -s $subnet/$mask -o $dev -j SNAT --to-source $ip
  create_acl_chain
  setup_dnsmasq
  setup_apache2
  setup_passwdsvcs

  #enable rps, rfs
  enable_rpsrfs $dev
}

enable_rpsrfs() {

    if [  -f /etc/rpsrfsenable ]
    then
        enable=$(cat /etc/rpsrfsenable)
        if [ $enable -eq 0 ]
        then
            return 0
        fi
    else
        return 0
    fi

    proc=$(cat /proc/cpuinfo | grep "processor" | wc -l)
    if [ $proc -le 1 ]
    then
        return 0
    fi
    dev=$1

    num=1
    num=$(($num<<$proc))
    num=$(($num-1));
    echo $num;
    hex=$(printf "%x\n" $num)
    echo $hex;
    #enable rps
    echo $hex > /sys/class/net/$dev/queues/rx-0/rps_cpus

    #enble rfs Recieved Flow Steering
    rps_flow_entries=$(cat /proc/sys/net/core/rps_sock_flow_entries)
	# enable rps Recieved Packet Steering
    if [ $rps_flow_entries -eq 0 ]
    then
        echo 256 > /proc/sys/net/core/rps_sock_flow_entries
    fi

    echo 256 > /sys/class/net/$dev/queues/rx-0/rps_flow_cnt

}

destroy_redundant_guest_network() {
	echo -t cloud "Destroying Redundant Guest Network"
#Check if guest network exists and is redundant
#If yes then
#	set up network parameters for destroy
#else

#fi

}

destroy_guest_network() {
  logger -t cloud " $(basename $0): Destroy network on interface $dev,  gateway $gw, network $ip/$mask "

  sudo ip addr del dev $dev $ip/$mask
  sudo iptables -t mangle -D PREROUTING -i $dev -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
  sudo iptables -t nat -D POSTROUTING -s $subnet/$mask -o $dev -j SNAT --to-source $ip
  destroy_acl_chain
  desetup_dnsmasq
  desetup_apache2
  desetup_passwdsvcs
}

#set -x
iflag=0
mflag=0
nflag=0
redunipflag=0
redundevflag=0
dflag=
gflag=
Cflag=
Dflag=
Rflag=

op=""
#vpc_guestnw.sh interface
#Flags
#-C Create guest network
#-D Destroy guest network
#-R Redundant router required
#Parameters $OPTARG will contain current value of parameter
#An associated flag will be set if parameter value is detected
#No tests for validity are performed on parameter values
#-n ip subnet
#-m network mask
#-d device name
#-i ip address
#-g gateway address
#-s DNS Server
#-e Domain Name
#-r Redundant Router ip address
#-p Redundant Router Device name
#added r = redundant router ip, p = redundant router device name,
# -R redundant router needed flag.

while getopts 'CDRn:m:d:i:g:s:e:r:p:' OPTION
do
  case $OPTION in
	  C)	Cflag=1
			op="-C"
			;;
	  D)	Dflag=1
			op="-D"
			;; 
	 R)     Rflag=1
			op="-R"
			;;		
	  n)	nflag=1
			in_subnet="$OPTARG"
			;;
	  m)	mflag=1
			in_mask="$OPTARG"
			;;
	  d)	dflag=1
	  		in_dev="$OPTARG"
	  		;;
	p)		redundevflag=1
	  		in_redundev="$OPTARG"
	  		;;
	  i)	iflag=1
			in_ip="$OPTARG"
	  		;;
	r)      redunipflag=1
			in_redunip="$OPTARG"
	  		;;
	  g)	gflag=1
	  		in_gw="$OPTARG"
	                ;;
	  s)    sflag=1
	        DNS="$OPTARG"
	                ;;
	  e)    eflag=1
			DOMAIN="$OPTARG"
	  		;;
	  ?)	usage
	                unlock_exit 2 $lock $locked
			;;
  esac
done

vpccidr=$(getVPCcidr)

#Filter for correct commands


#
if [ "$Cflag$Dflag$dflag" != "11" ]
then
    usage
    unlock_exit 2 $lock $locked
fi

if [ "$Cflag" == "1" ] && [ "$iflag$gflag$mflag" != "111" ]
then
    usage
    unlock_exit 2 $lock $locked
fi
if [ "$Rflag" == "1" ] && [ "$redunipflag$redundevflag$iflag$gflag$mflag" != "11111" ]
then
    usage
    unlock_exit 2 $lock $locked
fi

#Need filters for correct combinations for router/redundant router
#commands in addition to what is here.
#TODO Need to add filter for redundant router backup IP, etc.
if [ "$Rflag == "1" ]
then
	backup_ip = $in_redunip
	ip = $in_ip
	mask = $in_mask
	gw = $in_gw
	backup_dev = $in_redundev
	dev = $in_dev
	
	if [ "$Cflag" == "1" ]
	then  
	create_redundant_guest_network 
	fi	
	
	if [ "$Dflag" == "1" ]
	then
	destroy_redundant_guest_network
	fi
else
	ip = $in_ip
	mask = $in_mask
	gw = $in_gw
	dev = $in_dev
	if [ "$Cflag" == "1" ]
	then  
	  create_guest_network 
	fi
	
	if [ "$Dflag" == "1" ]
	then
	  destroy_guest_network
	fi
fi

unlock_exit 0 $lock $locked
