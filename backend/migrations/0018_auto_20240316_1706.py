# Generated by Django 3.2.10 on 2024-03-16 11:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0017_auto_20240316_1703'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shippingregistration',
            name='Address',
            field=models.CharField(max_length=250),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='City',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Consignment',
            field=models.CharField(choices=[('Document', 'Document'), ('Non Document', 'Non Document')], max_length=20),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Content_Type',
            field=models.CharField(choices=[('ARTIFICIAL JWELLARY', 'ARTIFICIAL JWELLARY'), ('BAGS', 'BAGS'), ('BOOKS', 'BOOKS'), ('CLOTHING', 'CLOTHING'), ('CORPORATE GIFTS', 'CORPORATE GIFTS'), ('LUGGAGE', 'LUGGAGE'), ('PERFUMES', 'PERFUMES'), ('PHOTO FRAME', 'PHOTO FRAME'), ('RAKHI', 'RAKHI'), ('SHOES', 'SHOES'), ('SLIPPERS', 'SLIPPERS')], max_length=20),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Declared_value',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Name',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Number_of_box',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='shippingregistration',
            name='Pin_Code',
            field=models.IntegerField(),
        ),
    ]
