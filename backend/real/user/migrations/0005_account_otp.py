# Generated by Django 5.0 on 2024-05-07 05:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_alter_account_phone'),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='otp',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
    ]
