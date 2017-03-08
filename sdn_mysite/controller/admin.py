from django.contrib import admin
from controller.models import Usertable
class UsertableAdmin(admin.ModelAdmin):
	list_display = ('name', 'address')

admin.site.register(Usertable,UsertableAdmin)

