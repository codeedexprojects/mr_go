# Generated by Django 3.2.10 on 2024-04-01 06:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0032_auto_20240401_1212'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingregistrationnotification',
            name='username',
            field=models.CharField(blank=True, max_length=150, null=True),
        ),
    ]
