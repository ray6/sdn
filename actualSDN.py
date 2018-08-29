from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, ipv4

from ryu.topology.api import get_switch, get_link, get_host
from ryu.topology import event, switches
import networkx as nx
from ryu.lib import hub

class actualSDN_switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(actualSDN_switch, self).__init__(*args, **kwargs)

        self.vtable = {}
        # default vlan table
        self.vtable = {'00:00:00:00:00:01':'1',
                        '00:00:00:00:00:02':'1',
                        '00:00:00:00:00:03':'1'}
        self.mac_to_ip = {} # mac <-> ip
        self.ip_to_mac = {} # ip <-> mac
        self.mac_to_port = {}   # host in which port
        self.stable = {} #dpid<->datapath
        self.default_datapath = None
        self.default_ev = None
        self.host_enter = 0 # host enter number
        self.switch_enter = 0   # switch enter number
        self.mac_to_dp = {} # mac <-> datapath
        self.switches = [] #all switches' dpid
        self.switches_dp = [] #all switches' datapath
        # self.path_db = []   # store shortest path
        
        # monitor init
        self.datapaths={}   # all datapaths
        self.monitor_thread = hub.spawn(self._monitor)
        self.bandwidth = {}

        #networkx init
        self.topology_api_app = self 
        self.directed_Topo = nx.DiGraph()
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        self.datapaths[datapath.id] = datapath

        self.default_datapath = datapath
        

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # read the mac_table(valid user) and put the information into the mac_to_ip and ip_to_mac
        with open('./mac_table.txt') as f:
            line = f.readlines()
        line = [x.strip('\n') for x in line]
        for content in line:
            tmp = content.split(',')
            mac = tmp[0]
            ip = tmp[1]
            self.mac_to_ip[mac] = ip
            self.ip_to_mac[ip] = mac
        #self.host_num = len(self.ip_to_mac)
        self.host_num = 3

    # _monitor, _request_stats adn _port_stats_reply_handler, the three functions are used when monitor the traffic
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3)
    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0 , ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        parser = ev.msg.datapath.ofproto_parser
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes '
                         'tx-pkts  tx-bytes bandwidth')
        self.logger.info('---------------- -------- '
                         '-------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body):
            if stat.port_no < 7:
                index = str(ev.msg.datapath.id) + '-' + str(stat.port_no)
                if index not in self.bandwidth:
                    self.bandwidth[index] = 0
                transfer_bytes = stat.rx_bytes + stat.tx_bytes
                speed = (transfer_bytes - self.bandwidth[index]) / 3
                self.logger.info('%016x %8x %8d %8d %8d %8d %8d\n',
                ev.msg.datapath.id, stat.port_no,
                stat.rx_packets, stat.rx_bytes,
                stat.tx_packets, stat.tx_bytes, speed)

                self.bandwidth[index] = transfer_bytes
           
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        print('add flow!!')

    # delete flow
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        mod = ofproto_parser.OFPFlowMod(datapath=datapath,
        command= ofproto.OFPFC_DELETE,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,match=match)
        datapath.send_msg(mod)
        print('del flow')

    # when src in topo and change port, this situation will run this function to delete flows which are relative the src.
    def ShortestPathDeleteFlow(self, datapath, *args):
        if datapath==None:
            return
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        #print('stable',self.stable)
        for key, value in self.stable.items():
            for arg in args:
                match = ofproto_parser.OFPMatch(eth_dst=arg)
                self.del_flow(value, match)
                match = ofproto_parser.OFPMatch(eth_src=arg)
                self.del_flow(value, match)
        print('SP del flow end')

    # handle arp package    
    def _handle_arp(self, datapath, in_port, pkt_ethernet, arp_pkt):
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return
        if self.ip_to_mac.get(arp_pkt.dst_ip) == None:
            return
        #Browse Target hardware adress from ip_to_mac table.
        get_mac = self.ip_to_mac[arp_pkt.dst_ip]
        #target_ip_addr = arp_pkt.dst_ip
        pkt = packet.Packet()
        #Create ethernet packet
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,dst=pkt_ethernet.src,src=get_mac))
        #Create ARP Reply packet
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=get_mac,
                                src_ip=arp_pkt.dst_ip,
                                dst_mac=arp_pkt.src_mac,
                                dst_ip=arp_pkt.src_ip))

        self._send_packet(datapath, in_port, pkt)
        print('arp', get_mac, pkt_ethernet.src,)

    # add host in the direct topo
    def AddHost(self, dpid, host, in_port):
        #Add host into directed_topo
        self.directed_Topo.add_node(host)
        #Add edge switch's port to src host
        self.directed_Topo.add_edge(dpid, host, {'port':in_port})
        #Add edge host to switch
        self.directed_Topo.add_edge(host, dpid)
        return
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
    #Topo information of switch
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
    # install direct topo. 
    # if the hosts in the same vlan, the function will install paths between them.
    def default_path_install(self, ev):
        for src in self.vtable:
            for dst in self.vtable:
                if src != dst:
                    if self.vtable[src] == self.vtable[dst]:
                        print('****Shortest path****')
                        print('vtable', self.vtable)
                        print(self.directed_Topo.edges(data = True))

                        self.ShortestPathInstall(ev, src, dst)

    # Using networkx, the paths between the hosts in the same vlan are the shortest.
    def ShortestPathInstall(self, ev, src, dst):
        #Compute shortest path
        path = nx.shortest_path(self.directed_Topo, src, dst)
  
        #Add Flow along with the path
        for k, sw in enumerate(self.switches):
            if sw in path:
                next = path[path.index(sw)+1]
                out_port = self.directed_Topo[sw][next]['port']

                actions = [self.switches_dp[k].ofproto_parser.OFPActionOutput(out_port)]
                match = self.switches_dp[k].ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [actions]
                self.add_flow(self.switches_dp[k], 1, match, actions, inst)
                
        return

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

    # the main function
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

        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocols(ethernet.ethernet)[0]
        if not pkt_ethernet:
            return
        if pkt_ethernet.ethertype == 35020:
            # ignore lldp packet
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if pkt_ethernet.ethertype== 2054:
            self._handle_arp(datapath, in_port, pkt_ethernet, arp_pkt)
            return

        dst = pkt_ethernet.dst
        src = pkt_ethernet.src
        out_port = None

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_dp.setdefault(src, datapath)
        self.stable.setdefault(dpid, datapath)
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # when the src is valid
        if src in self.vtable:
            # if the valid src not in the direct topo
            if not self.directed_Topo.has_node(src):
                                
                print('add', src)
                self.AddHost(dpid,src,in_port)
                #Add information to mac_to_port     
                self.mac_to_port[dpid][src] = in_port
                self.host_enter += 1

                # if entered host > 3, it will install shortest path
                if self.host_enter == self.host_num:
                    self.default_path_install(ev)

            #change port function
            else:
                #change port: del relative flow and reinstall
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
                    #Add Correct host
                    self.AddHost(dpid, src, in_port)
                    #Add new flows and path
                    self.default_path_install(ev)
        
        # when the dst is in the direct topo
        if dst in self.mac_to_port[dpid]:
            if self.vtable[src] != None and self.vtable[src] == self.vtable[dst]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
                print('out_port',out_port)
            else:
                out_port = ofproto.OFPP_FLOOD
                actions=[parser.OFPActionOutput(out_port)]
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
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
