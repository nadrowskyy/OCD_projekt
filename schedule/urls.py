from django.contrib import admin
from django.urls import path
from . import views
from django.views.static import serve
from django.conf import settings
from django.conf.urls import url
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetConfirmView, \
    PasswordResetCompleteView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home_page, name='home'),
    path('events_list/', views.events_list, name='events_list'),
    path('register/', views.register_page, name='register'),
    path('activate/<uidb64>/<token>', views.verification, name='activate'),
    path('login/', views.login_page, name='login'),
    path('mfa/', views.mfa_login, name='mfa'),
    path('logout/', views.logout_user, name='logout'),
    path('create_event/', views.create_event, name='create_event'),
    path('about/', views.about, name='about'),
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(template_name=
        'schedule/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(template_name=
        'schedule/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', PasswordResetCompleteView.as_view(template_name=
        'schedule/password_reset_complete.html'), name='password_reset_complete'),
    path('users_list/', views.users_list, name='users_list'),
    path('user_details/<int:index>', views.user_details, name='user_details'),
    path('user_edit/<int:index>', views.user_edit, name='user_edit'),
    path('delete_user/<int:index>', views.delete_user, name='delete_user'),
    path('event_edit/<int:index>', views.event_edit, name='event_edit'),
    path('delete_event/<int:index>', views.delete_event, name='delete_event'),
    path('my_profile/', views.my_profile, name='my_profile'),
    # path('change_password/', views.change_password, name='change_password'),
    path('event_details/<int:index>', views.event_details, name='event_details'),
    path('403/', views.handler_403, name='403'),
    url(r'^media/(?P<path>.*)$', serve,{'document_root': settings.MEDIA_ROOT}),
    url(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT})
]
