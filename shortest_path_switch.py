from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import arp, ipv4
from ryu.lib import dpid as dpid_lib
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.lib import hub
import networkx as nx
import copy
class ShortestPath(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(ShortestPath, self).__init__(*args, **kwargs)

		# constant data
		self.vtable = {'00:00:00:00:00:01':'3',
						'00:00:00:00:00:02':'3',
						'00:00:00:00:00:03':'2',}
						#	'00:00:00:00:00:04':'2',
						#'00:00:00:00:00:05':'1',
						#'00:00:00:00:00:06':'1'}

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

		self.hw_addr = None
		self.ip_addr = None
		self.mac_to_dp = {}
		self.mac_to_port = {}
		self.stable = {}
		self.topology_api_app = self
		self.directed_Topo = nx.DiGraph()
		self.switches = []
		
		self.switches_dp = []
		self.cnt = 0
		self.host_num = 3 #number of host
		self.path_db = []
		self.host_cnt = 0
		self.tmp = {}
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		dpid = datapath.id

		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
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
		print "****List of switches****"
		switch_list = get_switch(self.topology_api_app, None)
		self.switches = [switch.dp.id for switch in switch_list]
		self.switches_dp = [switch.dp for switch in switch_list]
		print(switch_list)
		self.directed_Topo.add_nodes_from(self.switches)
		links_list = get_link(self.topology_api_app, None)
		print(links_list)
		
		if self.cnt == len(self.switches) -1:
			links = [(link.src.dpid, link.dst.dpid, {'port':link.src.port_no}) for link in links_list ]
			links.sort()
			print links
			self.directed_Topo.add_edges_from(links)
			print "****List of links****"
			print(self.directed_Topo.edges(data = True))
	
		self.cnt += 1
		
	def _handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
		if arp_pkt.opcode != arp.ARP_REQUEST:
			return
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,dst=eth_pkt.src,src = self.hw_addr))
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


	def default_path_install(self, ev):
		for src in self.vtable:
			for dst in self.vtable:
				if src != dst:
					if self.vtable[src] == self.vtable[dst]:
						path = nx.shortest_path(self.directed_Topo, src, dst)
						str_path = str(path).replace(', ', ',')
						self.path_db.append(path)
						for k, sw in enumerate(self.switches):
							if sw in path:
								next = path[path.index(sw)+1]
								
								out_port = self.directed_Topo[sw][next]['port']

								actions = [self.switches_dp[k].ofproto_parser.OFPActionOutput(out_port)]
								match = self.switches_dp[k].ofproto_parser.OFPMatch(eth_src=src,eth_dst=dst)
								print('added flow')
								self.add_flow(self.switches_dp[k], 1, match, actions, ev.msg.buffer_id)
							

					else:
						actions = []
						match = self.mac_to_dp[src].ofproto_parser.OFPMatch(eth_src=src,eth_dst=dst)
						self.add_flow(self.mac_to_dp[src], 1, match, actions, ev.msg.buffer_id)
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):

		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		actions = None
		out_port = None
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


		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_dp.setdefault(src, datapath)
		self.mac_to_port.setdefault(dpid,{})
		self.stable.setdefault(dpid,datapath)		
			
		if src in self.vtable:
			if src not in self.directed_Topo:
				print("add node " + src)
				self.directed_Topo.add_node(src)
				self.directed_Topo.add_edge(dpid, src, {'port':in_port})
				self.directed_Topo.add_edge(src, dpid)
				self.mac_to_port[dpid][src]=in_port
				self.host_cnt += 1
				if self.host_cnt == self.host_num:
					self.default_path_install(ev)
				print self.directed_Topo.edges()
			else:
				if in_port != self.mac_to_port.get(dpid).get(src):
					self.host_cnt-=1

					#update mac_to_port table
					self.tmp = copy.deepcopy(self.mac_to_port)
					for key,value in self.mac_to_port[dpid].items():
						if value == in_port:
							del self.tmp[dpid][key]
							
					self.mac_to_port = copy.deepcopy(self.tmp)
					self.mac_to_port[dpid][src] = in_port
				
					print("The table has changed")
					print("\n")

					#change graph
					self.directed_Topo.remove_node(src)
					if dst in self.vtable:
						if self.vtable[src] == self.vtable[dst]:
							path = nx.shortest_path(self.directed_Topo, src, dst)

					#delete flows
					for key,value in self.stable.items():
						print("Delete flow on dpid: %d\n"%(key))

						match=parser.OFPMatch(eth_dst=src)
						self.del_flow(value,match,msg.buffer_id)
						match=parser.OFPMatch(eth_src=src)
						self.del_flow(value,match,msg.buffer_id)
						print("Match eth_dst=eth_src=%s\n"%(src))
						print("Fix the table")
					print "directed_Topo data:\n"
					print(self.directed_Topo.edges())
		 
		
		if dst in self.directed_Topo:
			print("dst in Topo "+dst)
		
			if self.vtable[src] == self.vtable[dst]:
				
				path = nx.shortest_path(self.directed_Topo, src, dst)
			
				if dpid not in path:
					return
				next = path[path.index(dpid)+1]
		
				out_port = self.directed_Topo[dpid][next]['port']

				actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		
			else:
				actions = []
				#drop
		else:
			out_port = ofproto.OFPP_FLOOD
			actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
		
		
		
		if out_port != ofproto.OFPP_FLOOD:

			match = parser.OFPMatch(eth_src=src,eth_dst=dst)

			if msg.buffer_id != ofproto.OFP_NO_BUFFER:

				self.add_flow(datapath, 1, match, actions, msg.buffer_id)
				return 
			else:
				self.add_flow(datapath,1,match,actions)
		if actions != None:
			data = None
			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				data = msg.data
			out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
								in_port=in_port,actions=actions)
			datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchLeave,[MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
	def handler_switch_leave(self,ev):
		self.logger.info("Not tracking Switches, switch leaved.")
	


