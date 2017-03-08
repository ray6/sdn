# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('controller', '0002_auto_20170307_1632'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usertable',
            name='name',
            field=models.CharField(max_length=255),
            preserve_default=True,
        ),
    ]
