#===============INFO==================
#=====Flow Match:eth_src, eth_dst=====
#=====================================
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import arp, ipv4

from ryu.topology.api import get_switch, get_link, get_host

from ryu.topology import event, switches

import networkx as nx

class ShortestPath(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(ShortestPath, self).__init__(*args, **kwargs)

		self.vtable = {'00:00:00:00:00:01':'3',
						'00:00:00:00:00:02':'3',
						'00:00:00:00:00:03':'2',
						'00:00:00:00:00:04':'2',
						'00:00:00:00:00:05':'1',
						'00:00:00:00:00:06':'1'}

		self.mac_to_ip = {'00:00:00:00:00:01':'10.0.0.1',
							'00:00:00:00:00:02':'10.0.0.2',
							'00:00:00:00:00:03':'10.0.0.3',
							'00:00:00:00:00:04':'10.0.0.4',
							'00:00:00:00:00:05':'10.0.0.5',
							'00:00:00:00:00:06':'10.0.0.6'}
		self.ip_to_mac = {'10.0.0.1':'00:00:00:00:00:01',
							'10.0.0.2':'00:00:00:00:00:02',
							'10.0.0.3':'00:00:00:00:00:03',
							'10.0.0.4':'00:00:00:00:00:04',
							'10.0.0.5':'00:00:00:00:00:05',
							'10.0.0.6':'00:00:00:00:00:06'}
		self.topology_api_app = self
		self.directed_Topo = nx.DiGraph()

		self.mac_to_port = {}
		self.mac_to_dp = {}
		self.stable = {}

		self.switches = [] #all switches' dpid
		self.seitches_dp = [] #all switches' datapath

		self.switch_enter = 0
		self.host_enter = 0
		self.path_db = []
		self.default_datapath = None
		#Changed as different topo
		self.host_num = 6

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		dpid = datapath.id

		self.default_datapath = datapath

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

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		self.switch_enter += 1

		#Get Switch List
		switch_list = get_switch(self.topology_api_app, None)

		self.switches = [switch.dp.id for switch in switch_list]
		self.switches_dp = [switch.dp for switch in switch_list]

		#Add switch dpid into Directed Topology
		self.directed_Topo.add_nodes_from(self.switches)

		#Get Link List
		links_list = get_link(self.topology_api_app, None)

		#When all Link enter
		if self.switch_enter == len(self.switches):
			links = [(link.src.dpid, link.dst.dpid, {'port':link.src.port_no}) for link in links_list ]
			links.sort()

			self.directed_Topo.add_edges_from(links)

			print('****List Of Links****')
			print(self.directed_Topo.edges(data = True))

	def _handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
		if arp_pkt.opcode != arp.ARP_REQUEST:
			return
		#Browse Target hardware adress from ip_to_mac table.
		target_hw_addr = self.ip_to_mac[arp_pkt.dst_ip]
		target_ip_addr = arp_pkt.dst_ip

		pkt = packet.Packet()
		#Create ethernet packet
		pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
											dst=eth_pkt.src,
											src=target_hw_addr))
		#Create ARP Reply packet
		pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
								src_mac=target_hw_addr,
								src_ip=target_ip_addr,
								dst_mac=arp_pkt.src_mac,
								dst_ip=arp_pkt.src_ip))

		self._send_packet(datapath, in_port, pkt)

	def _send_packet(self, datapath, in_port, pkt):
		ofproto =datapath.ofproto
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

	def ShortestPathDeleteFlow(self, datapath, *args):
		parser = datapath.ofproto_parser
		for key, value in self.stable.items():
			for arg in args:
				match = parser.OFPMatch(eth_dst=arg)
				self.del_flow(value, match)
				match = parser.OFPMatch(eth_src=arg)
				self.del_flow(value, match)

	def del_flow(self, datapath, match, buffer_id=None):
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
		#match = parser.OFPMatch()
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

	def default_path_install(self, ev):
		for src in self.vtable:
			for dst in self.vtable:
				if src != dst:
					if self.vtable[src] == self.vtable[dst]:

						self.ShortestPathInstall(ev, src, dst)

					else:
						actions = []
						match = self.mac_to_dp[src].ofproto_parser.OFPMatch(eth_src=src,eth_dst=dst)
						self.add_flow(self.mac_to_dp[src], 1, match, actions, ev.msg.buffer_id)

	def ShortestPathInstall(self, ev, src, dst):
			#Compute shortest path
			path = nx.shortest_path(self.directed_Topo, src, dst)

			#Backup path
			str_path = str(path).replace(', ', ',')
			self.path_db.append(path)

			#Add Flow along with the path
			for k, sw in enumerate(self.switches):
				if sw in path:
					next = path[path.index(sw)+1]

					out_port = self.directed_Topo[sw][next]['port']

					actions = [self.switches_dp[k].ofproto_parser.OFPActionOutput(out_port)]
					match = self.switches_dp[k].ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
					self.add_flow(self.switches_dp[k], 1, match, actions, ev.msg.buffer_id)

	#Add host and adjacent switch to directed_Topo
	def AddHost(self, dpid, host, in_port):
		#Add host into directed_topo
		self.directed_Topo.add_node(host)
		#Add edge switch's port to src host
		self.directed_Topo.add_edge(dpid, host, {'port':in_port})
		#Add edge host to switch
		self.directed_Topo.add_edge(host, dpid)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):

		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		dpid = datapath.id
		in_port = msg.match['in_port']

		#initial
		out_port = None

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if not eth:
			return
		#Access ARP packet
		arp_pkt = pkt.get_protocol(arp.arp)
		if arp_pkt:
			self._handle_arp(datapath, in_port, eth, arp_pkt)
			return


		dst = eth.dst
		src = eth.src

		self.mac_to_port.setdefault(dpid, {})
		self.mac_to_dp.setdefault(src, datapath)
		self.stable.setdefault(dpid, datapath)
		if src in self.vtable:
			if src not in self.directed_Topo:

				#Add Host onto directed_Topo
				self.AddHost(dpid, src, in_port)

				#Add information to mac_to_port
				self.mac_to_port[dpid][src] = in_port

				self.host_enter += 1

				#All host has entered, compute all topo.
				if self.host_enter == self.host_num:
					self.default_path_install(ev)


			else:
				if in_port != self.mac_to_port.get(dpid).get(src):

					#Delete the wrong flow
					self.ShortestPathDeleteFlow(datapath, src)

					#Update mac_to_port table
					for key, value in self.mac_to_port.items():
						if value.has_key(src):
							for mac, port in value.items():
								if mac == src:
									del self.mac_to_port[key][mac]
							break
					self.mac_to_port[dpid][src] = in_port

					#Change Graph
					#Remove wrong
					self.directed_Topo.remove_node(src)
					#Add Correct
					self.AddHost(dpid, src, in_port)


		#Set the path between src and dst when the host is not all has entered.
		if dst in self.directed_Topo:
			if self.vtable[src] == self.vtable[dst]:
				#path = nx.shortest_path(self.directed_Topo, src, dst)
				self.ShortestPathInstall(ev, src, dst)
				return

			else:
				actions = []


		else:
			out_port = ofproto.OFPP_FLOOD
			actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(eth_src=src, eth_dst=dst)
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match, ctions, msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
													buffer_id=msg.buffer_id,
													in_port=in_port,
													actions=actions)
		datapath.send_msg(out)

