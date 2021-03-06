# Generated by Django 2.0.1 on 2018-02-27 02:25

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('expires_at', models.DateTimeField()),
                ('access_token', models.CharField(max_length=40, unique=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='AuthorizationCode',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('expires_at', models.DateTimeField()),
                ('code', models.CharField(max_length=40, unique=True)),
                ('redirect_uri', models.CharField(max_length=200, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_id', models.CharField(max_length=254, unique=True, validators=[django.core.validators.EmailValidator()])),
                ('redirect_uri', models.CharField(max_length=200, null=True)),
                ('password', models.CharField(max_length=160)),
            ],
        ),
        migrations.CreateModel(
            name='RefreshToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('expires_at', models.DateTimeField()),
                ('refresh_token', models.CharField(max_length=40, unique=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scope', models.CharField(max_length=200, unique=True)),
                ('description', models.TextField()),
                ('is_default', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(max_length=254, unique=True, validators=[django.core.validators.EmailValidator()])),
                ('password', models.CharField(max_length=160)),
            ],
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='client',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oauth.Client'),
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='scopes',
            field=models.ManyToManyField(to='oauth.Scope'),
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='oauth.User'),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='client',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oauth.Client'),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='refresh_token',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_token', to='oauth.RefreshToken'),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='scopes',
            field=models.ManyToManyField(to='oauth.Scope'),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='oauth.User'),
        ),
    ]
