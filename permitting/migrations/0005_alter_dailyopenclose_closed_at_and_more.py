# Generated by Django 5.1.5 on 2025-03-18 12:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "permitting",
            "0004_rename_declared_led_workers_in_dailyopenclose_confirmed_led_workers_in_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="dailyopenclose",
            name="closed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="dailyopenclose",
            name="opened_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
