# Generated by Django 5.0.1 on 2024-02-01 16:01

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('task_tracker', '0007_alter_task_priority_alter_task_readiness'),
    ]

    operations = [
        migrations.AlterField(
            model_name='status',
            name='description',
            field=models.CharField(max_length=255, validators=[django.core.validators.RegexValidator(message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$')]),
        ),
        migrations.AlterField(
            model_name='status',
            name='name',
            field=models.CharField(max_length=50, validators=[django.core.validators.RegexValidator(message='Недопустимые символы. Используйте только кириллицу, латиницу, цифры и некоторые спец символы.', regex='^[а-яА-Яa-zA-Z0-9\\s_.,!@#%&*()-+=;:]*$')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='name',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='task',
            name='priority',
            field=models.CharField(choices=[('Высокий', 'Высокий'), ('Средний', 'Средний'), ('Низкий', 'Низкий')], default='Высокий', max_length=50),
        ),
        migrations.AlterField(
            model_name='task',
            name='readiness',
            field=models.CharField(choices=[('100%', '100%'), ('75%', '75%'), ('50%', '50%'), ('25%', '25%'), ('0%', '0%')], default='0%', max_length=50),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='user',
            name='name',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='user',
            name='patronymic',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='user',
            name='surname',
            field=models.CharField(max_length=50),
        ),
    ]
