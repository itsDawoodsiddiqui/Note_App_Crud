# Generated by Django 5.0.6 on 2025-02-10 08:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('NoteApp', '0007_rename_customuser_signup'),
    ]

    operations = [
        migrations.RenameField(
            model_name='signup',
            old_name='uuid',
            new_name='user_id',
        ),
    ]
