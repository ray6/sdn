from django.db import models
class Usertable(models.Model):
	name = models.CharField(max_length=255)
	address = models.CharField(max_length=20)
	#vlan = models.IntegerField()
	def __unicode__(self):
		return self.name
	
