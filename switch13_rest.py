import jason
import logging

from ryu.app import simple_switch_13

class SimpleSwitchRest13(simple_switch_13.SimpleSwitch13):
	#install SimpleSwitchRest13 class
	_CONTEXTs = { 'wsgi' : WSGIApplication }

	def __init__(self, *args, **kwargs):
		super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
		self.switches = {}
		self.mac_to_port = {}
		wsgi = kwargs['wsgi']
		wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		super(SimpleSwitchRest13, self).switch_features_handler(ev)
		datapath = ev.msg.datapath
		dpid = datapath.id
		self.switches[dpid] = datapath
		self.mac_to_port.setdefault(dpid, {})

		...

	def set_mac_to_port(self, dpid, entry):
		mac_table = self.mac_to_port.setdefault(dpid, {})
		datapath = self.switches.get(dpid)

		entry_port = entry['port']
		entry_mac = entry['mac']

		if datapath is not None:
			parser = datapath.ofproto_parser
			if entry_port not in mac_table.values():

				for mac, port in mac_table.items():

					#from known device to new device
					actions = [parser.OFPActionOutput(entry_port)]
					match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
					self.add_flow(datapath, 1, match, actions)

					#from new device to known device
					actions = [parser.OFPActionOutput(port)]
					match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
					self.add_flow(datapath, 1, match, actions)

				mac_table.update({entry_mac : entry_port})
		return mac_table


