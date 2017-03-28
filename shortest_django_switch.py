import shortest_path_switch
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
import os
import socket
import json
from ryu.lib import hub

SOCKFILE = '/tmp/hello_sock'

class ShortestRestSwitch(shortest_path_switch.ShortestPath):

	def __init__(self, *args, **kwargs):
		super(ShortestRestSwitch, self).__init__(*args, **kwargs)
		self.sock = None
		self.config = {}
		self.start_sock_server()

	def set_vtable(self, host, vlan):
		if self.vtable.get(host) != vlan:
			self.vtable.update({host:vlan})
			print("Change")
			print(self.vtable)
			self.ShortestPathDeleteFlow(self.default_datapath, host)

	def recv_loop(self):

		while True:
			data = self.sock.recv(1024)
			msg = json.loads(data)
			print("print msg")
			print(msg)
			for host, vlan in msg.items():
				self.set_vtable(str(host), str(vlan))


	def start_sock_server(self):
		if os.path.exists(SOCKFILE):
			os.unlink(SOCKFILE)
		self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
		self.sock.bind(SOCKFILE)
		hub.spawn(self.recv_loop)

