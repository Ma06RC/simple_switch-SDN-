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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.packet.ether_types import *    #Import different type of ethernet headers


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    #Initialise and Define the host addresses:
    h1_mac_addr = '00:00:00:00:00:01'
    h2_mac_addr = '00:00:00:00:00:02'
    h3_mac_addr = '00:00:00:00:00:03'

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}



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


    #   Allow an application to receive packets sent by the switch to the controller.
    #   The first argument of the decorator calls this function everytime a packet_in message is received. 
    #   The second argument indicates the switch state. 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]   #the action to take, when it gets a packet, is to send it out to out_port

        #This if statement checks the ethertype and checks if h2 and h3 are communicating
        if (ETH_TYPE_IP = eth or ETH_TYPE_IPV6 = eth
            and src = h2_mac_addr and dst = h3_mac_addr
            or src = h3_mac_addr and dst = h2_mac_addr):
                self.logger.info("Block IP traffic between host 2 and host 3")
                actions = []

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    # Returns a boolean to check if packets comes from either host 2 or 3 then return true. otherwise false
    # Block IP traffic between host 2 and host 3
    def block_traffic(self, pckt):
        data_packet = packet.Packet(pckt)
        for protocol in data_packet.protocols:
            if (protocol.protocol_name == 'ipv4' and ((ipv4_to_str(protocol.src) == SimpleSwitch.ipv4_h2 and ipv4_to_str(protocol.dst) == SimpleSwitch.ipv4_h3) or (ipv4_to_str(protocol.src) == SimpleSwitch.ipv4_h3 and ipv4_to_str(protocol.dst) == SimpleSwitch.ipv4_h2))):
                return True
        return False

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
