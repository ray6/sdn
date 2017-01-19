#!/usr/bin/env python

from wsgiref.simple_server import make_server
from cgi import parse_qs, escape

html = """
<html>
<body>
	<form method="post" action="">
		<p>
			00:00:00:00:00:01 :
			<input name="host1" type="checkbox" value="vlan1" %(h1_v1)s>vlan1
			<input name="host1" type="checkbox" value="vlan2" %(h1_v2)s>vlan2
		</p>
		<p>
			00:00:00:00:00:02 :
			<input name="host2" type="checkbox" value="vlan1" %(h2_v1)s>vlan1
			<input name="host2" type="checkbox" value="vlan2" %(h2_v2)s>vlan2
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
</body>
</html>
"""

def application(environ, start_response):
	#start_response: A callback function supplied by server

	try:
		request_body_size = int(environ.get('CONTENT_LENGTH', 0))
	except(ValueError):
		request_body_size = 0

	request_body = environ['wsgi.input'].read(request_body_size)
	d = parse_qs(request_body)

	host1 = d.get("host1", ["vlan1"])[0]
	#set host1 default belong to vlan1
	print("type of host1 : " + str(type(host1)))
	print("host1 : " + str(host1))
	host2 = d.get("host2", ["vlan2"])[0]
	#set host2 default belong to vlan2

	host1 = escape(host1)
	host2 = escape(host2)

	response_body = html %{
			'h1_v1':('', 'checked')['vlan1' in host1],
			'h1_v2':('', 'checked')['vlan2' in host1],
			'h2_v1':('', 'checked')['vlan1' in host2],
			'h2_v2':('','checked')['vlan2' in host2],
			'host1':host1,
			'host2':host2}

	status = '200 OK'
	response_headers = [('Content Type','text/plain'),
						('Content-length','str(len(response_body))')]
	#must wrapped as a list of Tuple(Header name, Header value)

	#send them to the server through function
	start_response(status, response_headers)
	return [response_body]
httpd = make_server('localhost', 8051, application)
httpd.serve_forever()
