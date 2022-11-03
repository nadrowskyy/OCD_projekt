# Generated by Django 3.2.5 on 2022-11-01 22:48

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='MFAUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.IntegerField(max_length=6)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('slug', models.SlugField(default=None, max_length=250, unique_for_date='planning_date')),
                ('description', models.TextField(blank=True, max_length=1000, verbose_name='opis wydarzenia')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('planning_date', models.DateTimeField(blank=True, null=True)),
                ('publish', models.DateTimeField(default=django.utils.timezone.now)),
                ('status', models.CharField(choices=[('draft', 'Szkic'), ('publish', 'Opublikowano')], default='publish', max_length=15)),
                ('duration', models.IntegerField(blank=True, null=True)),
                ('icon', models.FileField(default='icons/default.png', null=True, upload_to='icons/')),
                ('attachment', models.FileField(blank=True, null=True, upload_to='attachments/')),
                ('link', models.CharField(blank=True, max_length=1000, null=True)),
                ('organizer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('want_to_listen', models.ManyToManyField(blank=True, default=None, null=True, related_name='want_to_listen', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('planning_date',),
            },
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('content', models.TextField(max_length=1000)),
                ('if_edited', models.BooleanField(default=False)),
                ('if_deleted', models.BooleanField(default=False)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('event', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='schedule.event')),
            ],
            options={
                'ordering': ('-created',),
            },
        ),
    ]
