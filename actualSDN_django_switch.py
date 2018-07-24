import actualSDN
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
import os
import socket
import json
from ryu.lib import hub


SOCKFILE = '/tmp/hello_sock'


class actualSDN_Django_Switch(actualSDN.actualSDN_switch):

	def __init__(self, *args, **kwargs):
		super(actualSDN_Django_Switch, self).__init__(*args, **kwargs)
	
		self.sock = None
		self.config = {}
		self.start_sock_server()

	def set_vtable(self, host, vlan):
		if self.vtable[host] != vlan:
			del self.vtable[host]
			self.vtable.update({host:vlan})
			print("Change")
			print(self.vtable)
			self.ShortestPathDeleteFlow(self.default_datapath, host)

	def recv_loop(self):
		while True:
			print('wait rcv')
			data = self.sock.recv(1024)
			msg = json.loads(data)
			print("print msg")
			print(msg)
			if self.host_enter >= self.host_num:
				self.default_path_install(self.default_ev)
			for host, vlan in msg.items():
				self.set_vtable(str(host).rstrip(' '), str(vlan))
			print(self.vtable)			


	def start_sock_server(self):
		#print('test\n')
		if os.path.exists(SOCKFILE):
			os.unlink(SOCKFILE)
		self.sock = hub.socket.socket(hub.socket.AF_UNIX, hub.socket.SOCK_DGRAM)
		self.sock.bind(SOCKFILE)
		hub.spawn(self.recv_loop)
		print('success start sock')
