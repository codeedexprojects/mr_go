# Generated by Django 3.2.10 on 2024-04-04 05:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0036_rename_picked_updated_at_trackingstatus_collected_updated_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='shippingregistration',
            name='Registration_status',
            field=models.CharField(blank=True, choices=[('ACCEPTED', 'Accepted'), ('REJECTED', 'Rejected'), ('PENDING', 'Pending')], max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='trackingstatus',
            name='status',
            field=models.CharField(choices=[('Placed', 'Placed'), ('Collected', 'Collected'), ('Shipped', 'Shipped'), ('Delivered', 'Delivered')], max_length=20),
        ),
    ]