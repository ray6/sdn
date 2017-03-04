from django import template

register = template.Library()

@register.filter(name='dict')
def dict(value, arg):
	return value[arg]

