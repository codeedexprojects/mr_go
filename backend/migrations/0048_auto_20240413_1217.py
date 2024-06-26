# Generated by Django 3.2.10 on 2024-04-13 06:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0047_auto_20240413_1046'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingregistration',
            name='final_amount',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Price_per_kg',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Total_price',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Total_weight',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='invoice_number',
            field=models.CharField(default='0', editable=False, max_length=20, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='packing',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='packing_cover',
            field=models.FloatField(blank=True, default='0', null=True),
        ),
    ]
