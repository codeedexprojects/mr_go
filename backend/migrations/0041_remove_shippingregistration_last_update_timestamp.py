# Generated by Django 3.2.10 on 2024-04-08 05:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0040_shippingregistration_last_update_timestamp'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='shippingregistration',
            name='last_update_timestamp',
        ),
    ]