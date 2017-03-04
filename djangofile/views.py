from django.http import HttpResponse
from django import template
from django.shortcuts import render
import os
import socket

SOCKFILE = '/tmp/hello_sock'

def vlan(request):
	users = {"Ray":"00:00:00:00:00:01",
				"Han":"00:00:00:00:00:02"}
	user_v = {"Ray":"1", "Han":"2"}

	vtable = {"00:00:00:00:00:01":"1",
				"00:00:00:00:00:02":"1",
				"00:00:00:00:00:03":"1",
				"00:00:00:00:00:04":"2",
				"00:00:00:00:00:05":"2",
				"00:00:00:00:00:06":"2"}

	if request.method == 'GET':
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		data = vtable_trans(vtable)
		try:
			sock.connect(SOCKFILE)
			sock.sendall(data)
		except Exception, ex:
			print ex
			print 'connect error'

		return render(request, 'controller/vlan.html', locals())
	if request.method == 'POST':
		print("POST")
		print(request.POST)
		print(request.POST['vlan'])
		print(request.POST['user'])
		new_vlan = request.POST['vlan']
		vtable["00:00:00:00:00:01"] = new_vlan[4]
		print(vtable["00:00:00:00:00:01"])
		return render(request, 'controller/vlan.html', locals())

def vtable_trans(vtable):
	#translate vtable into data which can used by json.loads()
	i = 1
	data = '{'
	for key, value in vtable.items():
		if i != len(vtable):
			data = data+'\"'+key+'\":\"'+value+'\",'
		else:
			data = data+'\"'+key+'\":\"'+value+'\"'
		i+=1

	data = data+'}'

	return data


