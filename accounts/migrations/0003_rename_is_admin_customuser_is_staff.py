# Generated by Django 5.1.2 on 2024-11-29 13:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_customuser_public_key'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='is_admin',
            new_name='is_staff',
        ),
    ]