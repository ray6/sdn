from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.auth.views import login, logout
from django.contrib.auth.decorators import login_required
from controller.views import vlan_admin
from views import index, register, login 
admin.autodiscover()
urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'sdn_mysite.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/login/$', login,),
    url(r'^index/$', index),
    url(r'^accounts/logout/$', logout,{'template_name':'logout.html'}),
    url(r'^accounts/register/$', register),
    url(r'^vlan_admin/$',login_required(vlan_admin)),
    url(r'^vlan_admin/accounts/logout/$',logout,{'template_name':'logout.html'}),
)
