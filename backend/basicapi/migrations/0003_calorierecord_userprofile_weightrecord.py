# Generated by Django 5.1.4 on 2025-01-13 16:12

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('basicapi', '0002_customuser_created_at_customuser_updated_at_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CalorieRecord',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('recorded_at', models.DateField()),
                ('calorie', models.FloatField()),
                ('total_calorie', models.FloatField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.TextField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='calorie_records', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('height', models.FloatField()),
                ('weight', models.FloatField()),
                ('nickname', models.CharField(max_length=255)),
                ('goal', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='WeightRecord',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('recorded_at', models.DateField()),
                ('weight', models.FloatField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('month', models.IntegerField()),
                ('week', models.IntegerField()),
                ('year', models.IntegerField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='weight_records', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
