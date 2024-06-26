# Generated by Django 3.2.10 on 2024-04-24 04:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0056_alter_shippingregistration_invoice_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingregistration',
            name='payment_status',
            field=models.CharField(blank=True, choices=[('Collected', 'Collected'), ('Not Collected', 'Not Collected')], max_length=20, null=True),
        ),
    ]
