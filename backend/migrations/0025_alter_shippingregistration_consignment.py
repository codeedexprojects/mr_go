# Generated by Django 3.2.10 on 2024-03-19 09:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0024_alter_shippingregistration_consignment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shippingregistration',
            name='Consignment',
            field=models.CharField(blank=True, choices=[('Document', 'Document'), ('Non-Document', 'Non-Document')], max_length=20, null=True),
        ),
    ]
