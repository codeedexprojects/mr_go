# Generated by Django 3.2.10 on 2024-04-19 07:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0055_delete_adminuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shippingregistration',
            name='invoice_number',
            field=models.CharField(default='0', editable=False, max_length=20, null=True),
        ),
    ]
