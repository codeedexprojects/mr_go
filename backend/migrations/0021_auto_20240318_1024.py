# Generated by Django 3.2.10 on 2024-03-18 04:54

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0020_alter_shippingregistration_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingregistration',
            name='Booking_date',
            field=models.DateField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='shippingregistration',
            name='Delivery_date',
            field=models.DateField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
