import shortest_path_switch
import simple_switch
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.controller import ofp_event
import os
import socket
import json
from ryu.lib import hub

SOCKFILE = '/tmp/hello_sock'

class ShortestRestSwitch(simple_switch.SimpleSwitch13):


	def __init__(self, *args, **kwargs):
		super(ShortestRestSwitch, self).__init__(*args, **kwargs)
		self.sock = None
		self.config = {}
		self.start_sock_server()

	def set_vtable(self, host, vlan):
		if self.vtable[host] != vlan:
			self.vtable.update({host:vlan})
			self.SimpleSwitchDeleteFlow(self.default_datapath, host)

	def recv_loop(self):
		print('start loop')
		while True:
			print('wait for recev')
			data = self.sock.recv(1024)
			print('Receive new vtable from web')
			print(data)
			msg = json.loads(data)
			if msg:
				print('get msg')

			for host, vlan in msg.items():
				self.set_vtable(host, vlan)

	def start_sock_server(self):
		if os.path.exists(SOCKFILE):
			os.unlink(SOCKFILE)

		self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
		self.sock.bind(SOCKFILE)
		hub.spawn(self.recv_loop)
