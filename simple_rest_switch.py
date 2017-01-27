import json
from webob import Response
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
import simple_switch

simple_switch_instance_name = 'simple_switch_api_app'
url = '/vlan/'
print('***Start***')

class SimpleRestSwitch(simple_switch.SimpleSwitch13):
	print('***install SimpleRestSwitch***')

	_CONTEXTS = { 'wsgi' : WSGIApplication }

	def __init__(self, *args, **kwargs):
		super(SimpleRestSwitch, self).__init__(*args, **kwargs)
		print('***SRS_init***')
		wsgi = kwargs['wsgi']
		wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})

	def set_vtable(self, new_entry):
		host = new_entry['host']
		vlan = new_entry['vlan']
		if self.vtable[host] != vlan:
			self.vtable.update({host:vlan})
			self.SimpleSwitchDeleteFlow(self.default_datapath, host)

		return self.vtable

	def change_vlan(self,*args):
		self.SimpleSwitchDeleteFlow(self.default_datapath, args)


class SimpleSwitchController(ControllerBase):
	print('***SimpleSwitchController***')
	def __init__(self, req, link, data, **config):
		super(SimpleSwitchController, self).__init__(req, link, data, **config)
		self.simple_switch_spp = data[simple_switch_instance_name]
		print("***SSC_init***")

	@route('vlan', url, methods=['GET'])
	def get_vtable(self, req, **kwargs):
		print('***SSC_GET***')
		simple_switch = self.simple_switch_spp

		vtable = simple_switch.vtable
		body = json.dumps(vtable)
		return Response(content_type='application/json', body=body)

	@route('vlan', url, methods=['PUT'])
	def put_vtable(self, req, **kwargs):
		print('***SSC_PUT***')
		simple_switch = self.simple_switch_spp
		print('**req.body before eval' + str(req.body) + '**')
		new_entry = eval(req.body)
		print('**new_entry_type' + str(type(new_entry)) + '**')
		print(new_entry)

		#new_entry is in format {'00:00:00:00:00:01':'1'}
		vtable = simple_switch.set_vtable(new_entry)
		body = json.dumps(vtable)
		return Response(content_type='application/json', body=body)
