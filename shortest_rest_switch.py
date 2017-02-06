from cgi import parse_qs, escape
from webob import Response, Request
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
import shortest_path_switch

shortest_path_switch_instance_name = 'shortest_path__switch_api_app'
url = '/vlan/'

class ShortestRestSwitch(shortest_path_switch.ShortestPath):

	_CONTEXTS = { 'wsgi' : WSGIApplication }

	def __init__(self, *args, **kwargs):
		super(ShortestRestSwitch, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		wsgi.register(ShortestPathSwitchController, {shortest_path_switch_instance_name : self})

	def set_vtable(self, host, vlan):
		if self.vtable[host] != vlan:
			self.vtable.update({host:vlan})
			self.ShortestPathDeleteFlow(self.default_datapath, host)

class ShortestPathSwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(ShortestPathSwitchController, self).__init__(req, link, data, **config)
		self.shortest_switch_spp = data[shortest_path_switch_instance_name]

	@route('vlan', url, methods=['GET'])
	def get_vtable(self, req, **kwargs):

		body =self.html()
		return Response(content_type='text/html', body=body)

	@route('vlan', url, methods=['POST'])
	def put_vtable(self, req, **kwargs):
		shortest_switch = self.shortest_switch_spp

		#Check request isn't blank.
		try:
			request_body_size = int(req.environ.get('CONTENT_LENGTH', 0))

		except(ValueError):
			request_body_size = 0

		d = parse_qs(req.body)

		#Interpret vlan input
		for key, value in d.items():
			host = ('00:00:00:00:00:0'+key[4])
			vlan = value[0][4]
			shortest_switch.set_vtable(host, vlan)

		body = self.html()

		return Response(content_type='text/html', body=body)

	def html(self):
		shortest_switch = self.shortest_switch_spp
		vtable = shortest_switch.vtable
		html = """
			<html>
			<body>
				<form method="post" action="">
					<p>
						00:00:00:00:00:01 :
						<input name="host1" type="checkbox" value="vlan1" %(h1_v1)s>vlan1
						<input name="host1" type="checkbox" value="vlan2" %(h1_v2)s>vlan2
						<input name="host1" type="checkbox" value="vlan3" %(h1_v3)s>vlan3
					</p>
					<p>
						00:00:00:00:00:02 :
						<input name="host2" type="checkbox" value="vlan1" %(h2_v1)s>vlan1
						<input name="host2" type="checkbox" value="vlan2" %(h2_v2)s>vlan2
						<input name="host2" type="checkbox" value="vlan3" %(h2_v3)s>vlan3
					</p>
					<p>
						00:00:00:00:00:03 :
						<input name="host3" type="checkbox" value="vlan1" %(h3_v1)s>vlan1
						<input name="host3" type="checkbox" value="vlan2" %(h3_v2)s>vlan2
						<input name="host3" type="checkbox" value="vlan3" %(h3_v3)s>vlan3
					</p>
					<p>
						00:00:00:00:00:04 :
						<input name="host4" type="checkbox" value="vlan1" %(h4_v1)s>vlan1
						<input name="host4" type="checkbox" value="vlan2" %(h4_v2)s>vlan2
						<input name="host4" type="checkbox" value="vlan3" %(h4_v3)s>vlan3
					</p>
					<p>
						00:00:00:00:00:05 :
						<input name="host5" type="checkbox" value="vlan1" %(h5_v1)s>vlan1
						<input name="host5" type="checkbox" value="vlan2" %(h5_v2)s>vlan2
						<input name="host5" type="checkbox" value="vlan3" %(h5_v3)s>vlan3
					</p>
					<p>
						00:00:00:00:00:06 :
						<input name="host6" type="checkbox" value="vlan1" %(h6_v1)s>vlan1
						<input name="host6" type="checkbox" value="vlan2" %(h6_v2)s>vlan2
						<input name="host6" type="checkbox" value="vlan3" %(h6_v3)s>vlan3
					</p>

					<p>
						<input type="submit" value="submit">
					</p>
				</form>
				<p>
					00:00:00:00:00:01 %(host1)s
				</p>
				<p>
					00:00:00:00:00:02 %(host2)s
				</p>
				<p>
					00:00:00:00:00:03 %(host3)s
				</p>
				<p>
					00:00:00:00:00:04 %(host4)s
				</p>
				<p>
					00:00:00:00:00:05 %(host5)s
				</p>
				<p>
					00:00:00:00:00:06 %(host6)s
				</p>

			</body>
			</html>
			"""
		#DeBug
		print(vtable)
		#DeBug

		body = html %{
			'h1_v1':('', 'checked')[vtable['00:00:00:00:00:01'] is '1'],
			'h1_v2':('', 'checked')[vtable['00:00:00:00:00:01'] is '2'],
			'h1_v3':('', 'checked')[vtable['00:00:00:00:00:01'] is '3'],
			'h2_v1':('', 'checked')[vtable['00:00:00:00:00:02'] is '1'],
			'h2_v2':('', 'checked')[vtable['00:00:00:00:00:02'] is '2'],
			'h2_v3':('', 'checked')[vtable['00:00:00:00:00:02'] is '3'],
			'h3_v1':('', 'checked')[vtable['00:00:00:00:00:03'] is '1'],
			'h3_v2':('', 'checked')[vtable['00:00:00:00:00:03'] is '2'],
			'h3_v3':('', 'checked')[vtable['00:00:00:00:00:03'] is '3'],
			'h4_v1':('', 'checked')[vtable['00:00:00:00:00:04'] is '1'],
			'h4_v2':('', 'checked')[vtable['00:00:00:00:00:04'] is '2'],
			'h4_v3':('', 'checked')[vtable['00:00:00:00:00:04'] is '3'],
			'h5_v1':('', 'checked')[vtable['00:00:00:00:00:05'] is '1'],
			'h5_v2':('', 'checked')[vtable['00:00:00:00:00:05'] is '2'],
			'h5_v3':('', 'checked')[vtable['00:00:00:00:00:05'] is '3'],
			'h6_v1':('', 'checked')[vtable['00:00:00:00:00:06'] is '1'],
			'h6_v2':('', 'checked')[vtable['00:00:00:00:00:06'] is '2'],
			'h6_v3':('', 'checked')[vtable['00:00:00:00:00:06'] is '3'],
			'host1':('vlan'+vtable['00:00:00:00:00:01']),
			'host2':('vlan'+vtable['00:00:00:00:00:02']),
			'host3':('vlan'+vtable['00:00:00:00:00:03']),
			'host4':('vlan'+vtable['00:00:00:00:00:04']),
			'host5':('vlan'+vtable['00:00:00:00:00:05']),
			'host6':('vlan'+vtable['00:00:00:00:00:06'])
			}
		return body

