from django.http import HttpResponse
from django import template
from django.shortcuts import render
import os
import socket

SOCKFILE = '/tmp/hello_sock'

def vlan(request):
	users = {"Ray":"00:00:00:00:00:01",
				"Han":"00:00:00:00:00:02",
				"Mira":"00:00:00:00:00:03",
				"Rou":"00:00:00:00:00:04",
				"Firi":"00:00:00:00:00:05",
				"Haha":"00:00:00:00:00:06"}

	user_v = {"Ray":"1", "Han":"2", "Mira":"3",
				"Rou":"3", "Firi":"4", "Haha":"4"}
	vlan_list = ["1", "2", "3", "4", "5", "6", "7", "8"]


	if request.method == 'GET':
		vtable = {}
		for name, mac in users.items():
			vtable.update({ mac : user_v[name] })

		data = vtable_trans(vtable)

		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

		try:
			sock.connect(SOCKFILE)
			sock.sendall(data)
		except Exception, ex:
			print ex
			print("connet error")

		return render(request, 'controller/vlan.html', locals())

	if request.method == 'POST':
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		#get data from the POST request
		post_user = request.POST['user']
		post_vlan = request.POST['vlan'][4]
		user_v[post_user] = post_vlan
		new={users[post_user] : user_v[post_user]}
		data = vtable_trans(new)

		try:
			sock.connect(SOCKFILE)
			sock.sendall(data)
		except Exception, ex:
			print ex
			print("connet error")

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


