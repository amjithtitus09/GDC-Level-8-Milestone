import os
from datetime import timedelta

from django.conf import settings


from celery import Celery
from celery.decorators import periodic_task


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "task_manager.settings")
app = Celery("task_manager")
app.config_from_object("django.conf:settings")
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

# Periodic Task
@periodic_task(run_every=timedelta(seconds=30))
def every_30_seconds():
    from tasks.views import send_reports
    print("Running Every 30 Seconds!")
    send_reports()

