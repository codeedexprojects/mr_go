# Generated by Django 3.2.10 on 2024-04-04 07:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0038_auto_20240404_1140'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shippingregistration',
            name='City',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
