# Generated by Django 5.1.2 on 2024-11-29 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='public_key',
            field=models.BinaryField(default=None, null=True),
        ),
    ]