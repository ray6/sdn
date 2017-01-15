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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	#set member table
	#formate 'hw_addr':'dpid'
	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.vtable = {'00:00:00:00:00:01':'2', '00:00:00:00:00:02':'2', '00:00:00:00:00:03':'3', '00:00:00:00:00:04':'3'}
		self.mac_to_ip = {'00:00:00:00:00:01':'10.0.0.1', '00:00:00:00:00:02':'10.0.0.2', '00:00:00:00:00:03':'10.0.0.3',
						'00:00:00:00:00:04':'10.0.0.4', '00:00:00:00:00:05':'10.0.0.5', '00:00:00:00:00:06':'10.0.0.6'}

		self.ip_to_mac = {'10.0.0.1':'00:00:00:00:00:01', '10.0.0.2':'00:00:00:00:00:02', '10.0.0.3':'00:00:00:00:00:03',
						'10.0.0.4':'00:00:00:00:00:04', '10.0.0.5':'00:00:00:00:00:05', '10.0.0.6':'00:00:00:00:00:06'}
		self.hw_addr = None
		self.ip_addr = None
		self.stable = {}   #datapath to dpid table
		self.mac_to_port = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		dpid = datapath.id


        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
		datapath.send_msg(mod)

	def del_flow(self, datapath, match, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		cookie = cookie_mask = 0
		table_id = 0
		command = ofproto.OFPFC_DELETE
		idle_timeout = hard_timeout = 0
		priority = 1
		#buffer_id = ofproto.OFPCML_NO_BUFFER
		out_put = ofproto.OFPP_ANY
		out_group = ofproto.OFPG_ANY
		flags = 0
		instructions = []

		if buffer_id:
			mod = parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, command,
										idle_timeout, hard_timeout, priority,
										buffer_id, out_put, out_group, flags,
										match, instructions)

		else:
			buffer_id = ofproto.OFPCML_NO_BUFFER
			mod = parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, command,
										idle_timeout, hard_timeout, priority,
										buffer_id, out_put, out_group, flags,
										match, instructions)


		datapath.send_msg(mod)


	def _handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
		if arp_pkt.opcode != arp.ARP_REQUEST:
			return
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
											dst=eth_pkt.src,
											src=self.hw_addr))
		pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
								src_mac=self.hw_addr,
								src_ip=self.ip_addr,
								dst_mac=arp_pkt.src_mac,
								dst_ip=arp_pkt.src_ip))

		self._send_packet(datapath, in_port, pkt)


	def _send_packet(self, datapath, in_port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		data = pkt.data

		actions = [parser.OFPActionOutput(port=in_port)]
		out = parser.OFPPacketOut(datapath=datapath,
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=ofproto.OFPP_CONTROLLER,
									actions=actions,
									data=data)
		datapath.send_msg(out)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch


		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		actions = None  #initialize actions to None
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if not eth:
			return
		arp_pkt = pkt.get_protocol(arp.arp)
		if arp_pkt:
			self.hw_addr = self.ip_to_mac[arp_pkt.dst_ip]
			self.ip_addr = arp_pkt.dst_ip
			self._handle_arp(datapath, in_port, eth, arp_pkt)
			return

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
			return

		dst = eth.dst
		src = eth.src


		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.stable.setdefault(dpid, datapath)

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		#self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, eth)

		# learn a mac address to avoid FLOOD next time.

		if in_port != self.mac_to_port.get(dpid).get(src):
			for key, value in self.stable.items():
				print(self.mac_to_port.get(key).items())

				match = parser.OFPMatch(eth_dst=src)
				self.del_flow(value, match, msg.buffer_id)
				match = parser.OFPMatch(eth_src=src)
				self.del_flow(value, match, msg.buffer_id)

			self.mac_to_port[dpid][src] = in_port


		if dst in self.mac_to_port[dpid]:
			if self.vtable.get(src) != None and self.vtable.get(src) == self.vtable.get(dst):
				out_port = self.mac_to_port[dpid][dst]

				actions = [parser.OFPActionOutput(out_port)]
			else:
				out_port = ofproto.OFPP_FLOOD
		else:
			out_port = ofproto.OFPP_FLOOD
			actions = [parser.OFPActionOutput(out_port)]



        # install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
				match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
				# verify if we have a valid buffer_id, if yes avoid to send both
				# flow_mod & packet_out
				if msg.buffer_id != ofproto.OFP_NO_BUFFER:
					self.add_flow(datapath, 1, match, actions, msg.buffer_id)
					return
				else:
					self.add_flow(datapath, 1, match, actions)

		if actions != None:
			data = None
			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				data = msg.data

			out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
			datapath.send_msg(out)
