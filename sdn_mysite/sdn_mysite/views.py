from django.shortcuts import render_to_response
from django.http import HttpResponse,HttpResponseRedirect
from django.template import RequestContext
from django.contrib import auth
from django.contrib.auth.forms import UserCreationForm
from controller.models import Usertable
import uuid
import os
def login(request):
	if request.user.is_authenticated():
		return HttpResponseRedirect('/index/')
	username = request.POST.get('username','')
	password = request.POST.get('password','')
	user = auth.authenticate(username=username, password=password)
	
	if user is not None and user.is_active:
		auth.login(request, user)
		if username == 'admin' and password == 'admin':
			return HttpResponseRedirect('/vlan_admin/')
		
		return HttpResponseRedirect('/index/')
	else:
		return render_to_response('login.html',RequestContext(request, locals()))
def index(request):
	s = "%12x" % uuid.getnode()
	mac = ":".join(x+y for x, y in zip(s[::2], s[1::2]))

	return render_to_response('index.html',RequestContext(request,locals()))
def logout(request):
	auth.logout(request)
	return HttpResponseRedirect('/accounts/logout/')
def register(request):
	if request.method == 'POST':
		form = UserCreationForm(request.POST)
		
		if form.is_valid():
			user = form.save()
			mac = form.save()
			return HttpResponseRedirect('/accounts/login/')
		p=Usertable(name=user,address=mac)
		p.save()
	else:
		form = UserCreationForm()
	return render_to_response('register.html',RequestContext(request,locals()))
