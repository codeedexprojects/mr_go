# Generated by Django 3.2.10 on 2024-04-15 11:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0053_delete_adminuser'),
    ]

    operations = [
        migrations.CreateModel(
            name='AdminUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('mobile', models.CharField(blank=True, max_length=15, null=True, unique=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_superuser', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'admin_user',
            },
        ),
    ]