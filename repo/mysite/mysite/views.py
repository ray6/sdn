from django.http import HttpResponse
from django import template
from django.shortcuts import render
import os
import socket

SOCKFILE = '/tmp/hello_sock'

def menu(request):
	i = 1
	vlan = '{'
	vtable = {"00:00:00:00:00:01":"1",
				"00:00:00:00:00:02":"1",
				"00:00:00:00:00:03":"1",
				"00:00:00:00:00:04":"2",
				"00:00:00:00:00:05":"2",
				"00:00:00:00:00:06":"2"}
	for key, value in vtable.items():
		if i != len(vtable):
			vlan = vlan+'\"'+key+'\":\"'+value+'\",'
		else:
			vlan = vlan+'\"'+key+'\":\"'+value+'\"'
		i+=1
	vlan = vlan+'}'
	print(vlan)
	if request.method == 'GET':
		print('GET')
		food1 = {'name':'tomat egg', 'price':'60', 'comment':'Nice', 'is_spice':False}
		food2 = {'name':'tenbura', 'price':'80', 'comment':'Great', 'is_spice':True}
		foods = [food1, food2]
		print(str(request.GET))
		print(str(type(request)))
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		try:
			print('try')
			sock.connect(SOCKFILE)
			sock.sendall(vlan)
		except Exception, ex:
			print ex
			print 'connect error'

		return render(request, 'menu.html', locals())

