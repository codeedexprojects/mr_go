# Generated by Django 3.2.10 on 2024-03-19 07:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0021_auto_20240318_1024'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shippingregistration',
            name='Consignment',
            field=models.CharField(choices=[('Document', 'Document'), ('Non-Document', 'Non-Document')], max_length=20),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Content_Type',
            field=models.CharField(choices=[('ARTIFICIAL JWELLERY', 'ARTIFICIAL JWELLERY'), ('BAGS', 'BAGS'), ('BOOKS', 'BOOKS'), ('CLOTHING', 'CLOTHING'), ('CORPORATE GIFTS', 'CORPORATE GIFTS'), ('LUGGAGE', 'LUGGAGE'), ('PERFUMES', 'PERFUMES'), ('PHOTO FRAME', 'PHOTO FRAME'), ('RAKHI', 'RAKHI'), ('SHOES', 'SHOES'), ('SLIPPERS', 'SLIPPERS')], max_length=20),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Delivery_date',
            field=models.DateField(null=True),
        ),
    ]
