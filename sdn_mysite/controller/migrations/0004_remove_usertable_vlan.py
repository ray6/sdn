# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('controller', '0003_auto_20170307_1724'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usertable',
            name='vlan',
        ),
    ]
