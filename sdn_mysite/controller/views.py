from django.http import HttpResponse
from django import template
from django.shortcuts import render_to_response
from sdn_mysite.views import login, index
from django.contrib import auth
from django.template import RequestContext
from controller.models import Usertable
import os
import socket

SOCKFILE = '/tmp/hello_sock'

def vlan_admin(request):
	users = Usertable.objects.all()	
	vlan_list = ["1", "2", "3", "4", "5", "6", "7", "8"]

	if request.method == 'GET':
		print('GET')
		vtable = {}
		for u in users:
			vtable.update({ u.address : u.vlan })

		print(vtable)

		data = vtable_trans(vtable)

		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

		try:
			sock.connect(SOCKFILE)
			sock.sendall(bytes(data, 'UTF-8'))
		except Exception as ex:
			print(ex)
			print("connet error")

		return render_to_response('vlan_admin.html', RequestContext(request,locals()))

	if request.method == 'POST':
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		#get data from the POST request
		post_user = request.POST['user']
		post_vlan = request.POST['vlan'][4]
		obj, created = Usertable.objects.update_or_create(name=post_user, defaults={'vlan': post_vlan})

		new={obj.address : obj.vlan}
		data = vtable_trans(new)

		try:
			sock.connect(SOCKFILE)
			sock.sendall(bytes(data, 'UTF-8'))
		except Exception as ex:
			print(ex)
			print("connet error")

		return render_to_response('vlan_admin.html', RequestContext(request,locals()))

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
