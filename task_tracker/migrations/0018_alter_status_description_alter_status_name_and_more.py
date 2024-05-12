# Generated by Django 5.0.1 on 2024-02-01 17:27

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('task_tracker', '0017_alter_task_description_alter_task_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='status',
            name='description',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_description', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(255, message='Длина поля не должна превышать 255 символов.')]),
        ),
        migrations.AlterField(
            model_name='status',
            name='name',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_name', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='date_end',
            field=models.DateField(validators=[django.core.validators.RegexValidator(code='invalid_date', message='Недопустимый формат. Введите дату в формате dd-mm-yyy', regex='^\\d{2}-\\d{2}-\\d{4}$')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='date_start',
            field=models.DateField(validators=[django.core.validators.RegexValidator(code='invalid_date', message='Недопустимый формат. Введите дату в формате dd-mm-yyy', regex='^\\d{2}-\\d{2}-\\d{4}$')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='description',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_description', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(255, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='name',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_name', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_email', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='user',
            name='name',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_name', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='user',
            name='patronymic',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_patronymic', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
        migrations.AlterField(
            model_name='user',
            name='surname',
            field=models.CharField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_surname', message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$'), django.core.validators.MaxLengthValidator(50, message='Длина поля не должна превышать 50 символов.')]),
        ),
    ]
