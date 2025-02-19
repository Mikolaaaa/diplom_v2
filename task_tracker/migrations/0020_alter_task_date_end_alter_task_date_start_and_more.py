# Generated by Django 5.0.1 on 2024-02-07 13:32

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('task_tracker', '0019_alter_task_date_end_alter_task_date_start'),
    ]

    operations = [
        migrations.AlterField(
            model_name='task',
            name='date_end',
            field=models.DateField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_date', message='Недопустимый формат. Введите дату в формате dd-mm-yyy', regex='^\\d{4}-\\d{2}-\\d{2}$')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='date_start',
            field=models.DateField(blank=True, null=True, validators=[django.core.validators.RegexValidator(code='invalid_date', message='Недопустимый формат. Введите дату в формате dd-mm-yyy', regex='^\\d{4}-\\d{2}-\\d{2}$')]),
        ),
        migrations.AlterField(
            model_name='task',
            name='priority',
            field=models.CharField(blank=True, choices=[('Высокий', 'Высокий'), ('Средний', 'Средний'), ('Низкий', 'Низкий')], default='Высокий', max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='task',
            name='readiness',
            field=models.CharField(blank=True, choices=[('100%', '100%'), ('75%', '75%'), ('50%', '50%'), ('25%', '25%'), ('0%', '0%')], default='0%', max_length=50, null=True),
        ),
    ]
