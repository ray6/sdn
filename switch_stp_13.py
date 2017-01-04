from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'stplib': stplib.Stp}

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.stp = kwargs['stplib']
		self.vtable = {'00:00:00:00:00:01':'2', '00:00:00:00:00:02':'2', 
			       '00:00:00:00:00:03':'3', '00:00:00:00:00:04':'3',
			       '00:00:00:00:00:05':'2','00:00:00:00:00:06':'3'}
		self.mac_to_ip = {'00:00:00:00:00:01':'10.0.0.1', '00:00:00:00:00:02':'10.0.0.2',
				  '00:00:00:00:00:03':'10.0.0.3', '00:00:00:00:00:04':'10.0.0.4',
				  '00:00:00:00:00:05':'10.0.0.5','00:00:00:00:00:06':'10.0.0.6'}
		self.ip_to_mac = {'10.0.0.1':'00:00:00:00:00:01', '10.0.0.2':'00:00:00:00:00:02',
				  '10.0.0.3':'00:00:00:00:00:03', '10.0.0.4':'00:00:00:00:00:04',
				  '10.0.0.5':'00:00:00:00:00:05','10.0.0.6':'00:00:00:00:00:06'}
		self.hw_addr=None
		self.ip_addr=None
		self.stable={} 
		#datapath to pid table
		# Sample of stplib config.
		#  please refer to stplib.Stp.set_config() for details.
		config = {dpid_lib.str_to_dpid('0000000000000001'):
		             {'bridge': {'priority': 0x8000}},
		          dpid_lib.str_to_dpid('0000000000000002'):
		             {'bridge': {'priority': 0x9000}},
		          dpid_lib.str_to_dpid('0000000000000003'):
		             {'bridge': {'priority': 0xa000}}}
		self.stp.set_config(config)

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
		# correctly.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions,buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
		                                     actions)]

		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
						match=match, instructions=inst)
		datapath.send_msg(mod)
		print("add flow!!")
		print("\n")
	def del_flow(self,datapath,match,buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		cookie = cookie_mask = 0
		table_id = 0
		command=ofproto.OFPFC_DELETE
		idle_timeout = hard_timeout =0
		priority=1
		out_port=ofproto.OFPG_ANY
		out_group=ofproto.OFPG_ANY
		flag=0
	#	match = parser.OFPMatch()
		action = None
		inst = None

		if buffer_id:
	
			req = parser.OFPFlowMod(datapath,cookie,cookie_mask,table_id,
						command,idle_timeout,hard_timeout,
						priority,buffer_id,out_port,
						out_group,0,match,inst)
		else:
			req = parser.OFPFlowMod(datapath,cookie,cookie_mask,table_id,
						command,idle_timeout,hard_timeout,
						priority,ofproto.OFPCML_NO_BUFFER,out_port,
						out_group,0,match,inst)
			
		datapath.send_msg(req)
		print("delete flow!!")
		print("\n")
	def delete_flow(self, datapath):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		for dst in self.mac_to_port[datapath.id].keys():
		    match = parser.OFPMatch(eth_dst=dst)
		    mod = parser.OFPFlowMod(
		        datapath, command=ofproto.OFPFC_DELETE,
		        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
		        priority=1, match=match)
		datapath.send_msg(mod)
	def _handle_arp(self,datapath,in_port,pkt_eth,pkt_arp):
		if pkt_arp.opcode != arp.ARP_REQUEST:
			return
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
						   dst=pkt_eth.src,src=self.hw_addr))
		pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
					 src_mac=self.hw_addr,
					 src_ip=self.ip_addr,
					 dst_mac=pkt_arp.src_mac,
					 dst_ip=pkt_arp.src_ip))
		self._send_packet(datapath,in_port,pkt)
					
	def _send_packet(self,datapath,in_port,pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		
	#	self.logger.info("packt-out %s"%(pkt,))
	#	print("\n")
		data = pkt.data
		actions = [parser.OFPActionOutput(port=in_port)]
		out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
					  in_port=ofproto.OFPP_CONTROLLER,actions=actions,
					  data=data)
		datapath.send_msg(out)
	@set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		if not eth:
			return
		pkt_arp = pkt.get_protocol(arp.arp)
		if pkt_arp:
			self.hw_addr = self.ip_to_mac[pkt_arp.dst_ip]
			self.ip_addr = pkt_arp.dst_ip
			self._handle_arp(datapath,in_port,eth,pkt_arp)
			return

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            		# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})
		self.stable.setdefault(dpid,datapath)
	#	self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		if in_port != self.mac_to_port.get(dpid).get(src):
			print("The table has changed")
			print("\n")
			for key,value in self.stable.items():
				
			#	if not key==1:
				print("Delete flow on dpid: %d\n"%(key))

				match=parser.OFPMatch(eth_dst=src)
				self.del_flow(value,match,msg.buffer_id)
				del self.mac_to_port[dpid]
				match=parser.OFPMatch(eth_src=src)
				self.del_flow(value,match,msg.buffer_id)
				del self.mac_to_port[dpid]	
				print("Match eth_dst=eth_src=%s\n"%(src))

			#	self.mac_to_port[key][src]=1				
			print("Fix the table")
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
		    	match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
		    	if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match,actions,msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)

		if actions != None:
			data = None
			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
		    		data = msg.data

			out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port,
				          actions=actions, data=data)
			datapath.send_msg(out)

	@set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
        def _topology_change_handler(self, ev):
		dp = ev.dp
		dpid_str = dpid_lib.dpid_to_str(dp.id)
		msg = 'Receive topology change event. Flush MAC table.'
		self.logger.debug("[dpid=%s] %s", dpid_str, msg)
	#	print("changed topo")
		
		if dp.id in self.mac_to_port:
		    self.delete_flow(dp)
		    del self.mac_to_port[dp.id]
		 #   print("delete flow")

	@set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
        def _port_state_change_handler(self, ev):
		dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
		of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
		            stplib.PORT_STATE_BLOCK: 'BLOCK',
		            stplib.PORT_STATE_LISTEN: 'LISTEN',
		            stplib.PORT_STATE_LEARN: 'LEARN',
		            stplib.PORT_STATE_FORWARD: 'FORWARD'}
		self.logger.debug("[dpid=%s][port=%d] state=%s",dpid_str, ev.port_no, of_state[ev.port_state])



