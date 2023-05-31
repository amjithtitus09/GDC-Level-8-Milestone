# Add all your views here
from typing import Any
from django.db.models.query import QuerySet
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.core.exceptions import ValidationError
from django.db.models import Q

from django.views.generic.list import ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.detail import DetailView
from django.views import View
from django.forms import ModelForm

from django.contrib.auth.forms import UsernameField
from django.contrib.auth.views import LoginView

from django.contrib.auth.mixins import LoginRequiredMixin

import datetime

from django import forms
from django.contrib.auth import (
    authenticate, get_user_model, password_validation,
)
from django.contrib.auth.hashers import (
    UNUSABLE_PASSWORD_PREFIX, identify_hasher,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.text import capfirst
from django.utils.translation import gettext, gettext_lazy as _
from django.core.mail import send_mail

User = get_user_model()

tasks = []


def send_reports():
    print(datetime.datetime.now().time())
    users = User.objects.filter(send_report_at__isnull=False, send_report_at__lte=datetime.datetime.now().time()).filter(Q(last_sent_on__isnull=True) | Q(last_sent_on__lt=datetime.datetime.today()))
    for user in users:
        print(f'Yet to run for user {user.pk} at {user.send_report_at}')
        send_mail(
            "Tasks Report",
            f"PENDING: {user.tasks.filter(status=STATUS_CHOICES[0][0]).count()} \
            COMPLETED: {user.tasks.filter(status=STATUS_CHOICES[2][0]).count()}",
            "super@super.com",
            [user.email],
            fail_silently=False,
        )
        user.last_sent_on = datetime.datetime.today()
        user.save()

from tasks.models import Task, STATUS_CHOICES
class AbstractTaskQuerySet(LoginRequiredMixin):
    
    def get_queryset(self):
        return Task.objects.filter(deleted=False, user = self.request.user).order_by("priority")
    

class UserCreationForm(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """
    error_messages = {
        'password_mismatch': _('The two password fields didn’t match.'),
    }
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text=_("Enter the same password as before, for verification."),
    )

    class Meta:
        model = User
        fields = ("username",)
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs['autofocus'] = True

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def _post_clean(self):
        super()._post_clean()
        # Validate the password after self.instance is updated with form data
        # by super().
        password = self.cleaned_data.get('password2')
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except ValidationError as error:
                self.add_error('password2', error)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
    
class UserSignupView(CreateView):
    form_class = UserCreationForm
    template_name = "user_signup.html"
    success_url= "/user/login"

class UpdateUserForm(forms.ModelForm):
    send_report_at = forms.TimeField()
    class Meta:
        model = User
        fields = ['email', 'send_report_at']


class UserUpdateView(UpdateView):
    model = User
    form_class = UpdateUserForm
    template_name = "update_user.html"
    success_url = "/tasks"

class UserLoginView(LoginView):
    template_name = "user_login.html"


def session_storage_view(request):
    total_views = request.session.get("total_views", 0)
    request.session["total_views"] = total_views + 1
    return HttpResponse(f"Total Views {total_views}")

class TaskListView(LoginRequiredMixin, ListView):
    model = Task
    template_name = "tasks.html"
    context_object_name = "tasks"
    paginate_by = 5

    def get_queryset(self):
        tasks = Task.objects.filter(deleted=False, user = self.request.user).order_by("priority")
        search_term = self.request.GET.get("search")
        if search_term:
            tasks = tasks.filter(title__icontains=search_term)
        print(tasks)
        return tasks
    
    

class TaskCreateForm(ModelForm):
    status = forms.ChoiceField(choices = STATUS_CHOICES, label="Status",widget=forms.Select(), required=True)

    class Meta:
        model = Task
        fields = ("title", "description", "priority", "status")

    def clean_title(self):
        title = self.cleaned_data["title"]
        if len(title) < 10:
            raise ValidationError("Title is too short")
        return title.upper()

class TaskCreateView(AbstractTaskQuerySet, CreateView):
    form_class = TaskCreateForm
    template_name = "add_task.html"
    success_url = "/tasks"

    def check_and_move_down_task(self, priority):
        task_to_modify = self.get_queryset().filter(priority=priority)
        if not task_to_modify:
            return False
        else:
            if self.check_and_move_down_task(priority+1):
                return True
            else:
                task_to_modify = task_to_modify.get()
                task_to_modify.priority = priority+1
                task_to_modify.save()


    def form_valid(self, form):
        
        self.check_and_move_down_task(form.cleaned_data["priority"])
        self.object = form.save()
        
        self.object.user = self.request.user
        self.object.save()
        return HttpResponseRedirect(self.get_success_url())
    

class TaskUpdateView(AbstractTaskQuerySet, UpdateView):
    model = Task
    form_class = TaskCreateForm
    template_name = "update_task.html"
    success_url = "/tasks"

class TaskDeleteView(AbstractTaskQuerySet, DeleteView):
    model = Task
    template_name = "delete_task.html"
    success_url = "/tasks"

class TaskCompleteView(AbstractTaskQuerySet, UpdateView):
    model = Task
    template_name = "complete_task.html"
    success_url = "/tasks"

class TaskDetailView(AbstractTaskQuerySet, DetailView):
    model = Task

class AddTaskView(View):
    def get(self, request):
        return render(request, "add_task.html")
    
    def post(self, request):
        Task(title = request.POST.get("task")).save()
        return HttpResponseRedirect("/tasks")

class CompletedTaskListView(LoginRequiredMixin, ListView):
    model = Task
    template_name = "completed_tasks.html"
    context_object_name = "tasks"
    paginate_by = 5

    def get_queryset(self):
        return Task.objects.filter(status = STATUS_CHOICES.COMPLETED, deleted=False, user = self.request.user)


def complete_task_view(request, index):
    Task.objects.filter(id=index).update(completed=True)
    return HttpResponseRedirect("/tasks")