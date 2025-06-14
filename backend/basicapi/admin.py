from django.contrib import admin
from .models import CustomUser  # models.py から User をインポート

# Register your models here.
admin.site.register(CustomUser)