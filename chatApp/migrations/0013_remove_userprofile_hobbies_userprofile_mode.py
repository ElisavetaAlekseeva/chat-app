# Generated by Django 4.1 on 2023-02-06 10:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chatApp', '0012_alter_userprofile_friends'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='hobbies',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='mode',
            field=models.BooleanField(default=True),
        ),
    ]
