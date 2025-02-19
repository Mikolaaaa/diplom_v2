# Generated by Django 5.0.1 on 2024-02-01 16:46

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('task_tracker', '0015_alter_status_description'),
    ]

    operations = [
        migrations.AlterField(
            model_name='status',
            name='description',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(255, message='Длина поля не должна превышать 255 символов.')]),
        ),
        migrations.AlterField(
            model_name='status',
            name='name',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_username', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
    ]
