# Generated by Django 5.1.2 on 2024-10-30 18:03

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('zssapi', '0002_alter_network_balance'),
    ]

    operations = [
        migrations.AlterField(
            model_name='deposit',
            name='transaction_id',
            field=models.UUIDField(blank=True, default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
