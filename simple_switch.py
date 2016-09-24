# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#nwen302@192.168.56.101/nwen302/mininet/ryu/ryu/app/

#sudo vim mininet/ryu/ryu/app/simple_switch.py
#:%d
#press I to insert
#Cmd shift V to paste the file
#esc, and :wq

#sh ovs-ofctl dump-flows s1 - to test if the packet was dropped


"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.packet import ipv4
from netaddr import IPAddress               
from ryu.lib import hub         


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Stores the datapath
        self.datapaths = {}
        # create a thread to periodically issue a request to switch to acquire stat info
        self.monitor_thread = hub.spawn(self.monitor)       #This creates the threads

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    # Rule for blocking traffic between h2 and h3
    def block_flow(self, datapath, in_port, ip1, ip2, actions):
        ofproto = datapath.ofproto
        
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_type=0x0800, nw_src=ip1, nw_dst=ip2)
    
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    
    # EventOFPStateChange: make sure the connected switch is monitored. It is use for detecting
    #  connection and disconnection
    # MAIN_DISPATCHER: switch is registered as the monitor target
    # DEAD_DISPATCHER: registration is deleted
    # Code Borrowed from: https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    
    # Thread function. It repeatedly request stat info for the registered switch for every 5 seconds
    # Code Borrowed from: https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)

    # Specify the desired port number to acquire information from. 
    # Here I specifically request information from port 1
    # Code Borrowed from: https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    def request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, 1)       #Port statistic request message from port 1
        datapath.send_msg(req)


    # EventOFPPortStatsReply: list of OFPFlowStats and stores the statistical information of each flow entry.
    #       In order to receive response from the switch.
    # Code Borrowed from: https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats(self, ev):
        body = ev.msg.body

        for stat in body:
            self.logger.info("Traffic going to and originating at Port_No = %d , TX_Packets = %d , RX_Packets = %d", stat.port_no, stat.rx_packets, stat.tx_packets)


    #   Allow an application to receive packets sent by the switch to the controller.
    #   The first argument of the decorator calls this function everytime a packet_in message is received. 
    #   The second argument indicates the switch state. 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #Initialise and Define the host addresses:
        h1_mac_addr = "00:00:00:00:00:01"
        h2_mac_addr = "00:00:00:00:00:02"
        h3_mac_addr = "00:00:00:00:00:03"
        h1_ip_addr = '10.0.0.1'
        h2_ip_addr = '10.0.0.2'
        h3_ip_addr = '10.0.0.3'

        msg = ev.msg                # Object representing a packet_in data structure.
        datapath = msg.datapath     # Switch Datapath ID
        ofproto = datapath.ofproto  # OpenFlow Protocol version the entities negotiated

        # Inspect the packet headers with its packet type eg. IPV6,IPV4,ARP,TCP,UDP and etc. 
        pkt = packet.Packet(msg.data)   
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # To extract Ether header details
        dst = eth.dst
        src = eth.src

        dpid = datapath.id      #datapaths are connections from switches to the controller
        self.mac_to_port.setdefault(dpid, {})
 
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD      

        #Added code to check if the pkt is IPv4
        if (pkt.get_protocol(ipv4.ipv4)):
            ip4 =  pkt.get_protocol(ipv4.ipv4)
            ipv4_dest = int(IPAddress(ip4.dst))     #Represent the IPAddress object as a single IP address
            ipv4_src = int(IPAddress(ip4.src))

             #Checks if h2 and h3 are communicating
            if (src == h2_mac_addr and dst == h3_mac_addr):
                self.logger.info("Block IP traffic between %s to %s", src, dst)
                actions = []
                self.block_flow(datapath, msg.in_port, ipv4_src, ipv4_dest, actions)

            if(src == h3_mac_addr and dst == h2_mac_addr):
                self.logger.info("Block IP traffic between %s to %s", src, dst)
                actions = []
                self.block_flow(datapath, msg.in_port, ipv4_src, ipv4_dest, actions)
  
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]   #the action to take, when it gets a packet, is to send it out to out_port
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)
            

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


