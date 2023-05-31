from django.contrib import admin
from django.urls import path

from django.contrib.auth.views import LogoutView

from tasks.views import TaskListView, TaskCreateView, TaskUpdateView, TaskDeleteView,  \
    session_storage_view, UserSignupView, UserLoginView, CompletedTaskListView, TaskDetailView, TaskCompleteView, \
    UserUpdateView

from tasks.apiviews import TaskViewSet, HistoryViewSet, UserViewSet

from rest_framework.routers import SimpleRouter
from rest_framework_nested.routers import NestedSimpleRouter

router = SimpleRouter()

router.register("api/task", TaskViewSet)
router.register("api/users", UserViewSet)

tasks_router = NestedSimpleRouter(router, "api/task", lookup='task')
tasks_router.register(r"history", HistoryViewSet, basename="task-history")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('sessionviews/', session_storage_view),
    path('user/signup', UserSignupView.as_view()),
    path('user/login', UserLoginView.as_view()),
    path('user/logout', LogoutView.as_view()),
    path('tasks/', TaskListView.as_view()),
    path('create-task/', TaskCreateView.as_view()),
    path('update-task/<pk>', TaskUpdateView.as_view()),
    path('update-user/<pk>', UserUpdateView.as_view()),
    path('delete-task/<pk>/', TaskDeleteView.as_view()),
    path('view-task/<pk>/', TaskDetailView.as_view()),
    path('complete_task/<pk>/', TaskCompleteView.as_view()),
    path('completed_tasks/', CompletedTaskListView.as_view())
] + router.urls + tasks_router.urls
