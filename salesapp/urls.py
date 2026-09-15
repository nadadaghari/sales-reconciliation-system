from django.urls import path
from . import views

urlpatterns = [
    path('', views.entry_view, name='entry'),
    path('my-history/', views.waiter_history_view, name='waiter_history'),
    path('collector/', views.collector_view, name='collector'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard/<int:entry_id>/edit/', views.edit_entry_view, name='edit_entry'),
    path('entries/<int:entry_id>/archive/', views.archive_entry_view, name='archive_entry'),
    path('history/', views.archive_history_view, name='archive_history'),
    path('audit-log/', views.audit_log_view, name='audit_log'),
    # Waiters log in with Branch Code + Password (see branch_login_view).
    path('login/', views.branch_login_view, name='login'),
    # Collector / Audit / Admin / IT use username + password.
    path('staff-login/', views.login_view, name='staff_login'),
    path('logout/', views.logout_view, name='logout'),
    path('users/', views.create_user_view, name='create_user'),
    path('users/<int:user_id>/unlock/', views.unlock_user_view, name='unlock_user'),
    path('users/<int:user_id>/edit/', views.edit_user_view, name='edit_user'),
    path('users/<int:user_id>/toggle-active/', views.toggle_user_active_view, name='toggle_user_active'),
    path('users/<int:user_id>/delete/', views.delete_user_view, name='delete_user'),
    path('branches/', views.add_branch_view, name='add_branch'),
    path('branches/<int:branch_id>/edit/', views.edit_branch_view, name='edit_branch'),
    path('branches/<int:branch_id>/toggle-active/', views.toggle_branch_active_view, name='toggle_branch_active'),
    path('branches/<int:branch_id>/delete/', views.delete_branch_view, name='delete_branch'),
    path('branches/import/', views.import_branches_view, name='import_branches'),
]
