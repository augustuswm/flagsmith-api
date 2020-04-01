# -*- coding: utf-8 -*-
# Generated by Django 1.11.25 on 2019-12-13 09:05
from __future__ import unicode_literals

import django.db.models.deletion
from django.db import migrations, models


def create_webhooks(apps, schema_editor):
    Webhook = apps.get_model('environments', 'Webhook')
    Environment = apps.get_model('environments', 'Environment')

    webhooks_to_create = []
    for environment in Environment.objects.exclude(webhook_url=None):
        webhooks_to_create.append(
            Webhook(environment=environment, url=environment.webhook_url, enabled=environment.webhooks_enabled))

    Webhook.objects.bulk_create(webhooks_to_create)
    Environment.objects.exclude(webhook_url=None).update(webhook_url=None)


def update_environment_webhooks(apps, schema_editor):
    Webhook = apps.get_model('environments', 'Webhook')

    for webhook in Webhook.objects.all().order_by('created_at'):
        # Note this will only set the webhook url for the environment to be the earliest created one
        if webhook.environment.webhook_url is None:
            webhook.environment.webhook_url = webhook.url
            webhook.environment.webhooks_enabled = webhook.enabled
            webhook.environment.save()


class Migration(migrations.Migration):
    dependencies = [
        ('environments', '0007_auto_20190827_1528'),
    ]

    operations = [
        migrations.CreateModel(
            name='Webhook',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField()),
                ('environment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='environments.Environment', related_name='webhooks')),
                ('enabled', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True))
            ],
        ),
        migrations.RunPython(create_webhooks),
    ]
