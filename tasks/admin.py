from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

# Register your models here.

from tasks.models import Task, History, User

admin.sites.site.register(Task)
admin.sites.site.register(History)
admin.site.register(User, UserAdmin)
