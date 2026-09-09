from django.contrib import admin
from .models import Branch, ShiftEntry, CollectorHandover, UserProfile, VisaMachineFile


@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ['name', 'code']
    search_fields = ['name', 'code']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'branch']
    list_filter = ['role', 'branch']


@admin.register(ShiftEntry)
class ShiftEntryAdmin(admin.ModelAdmin):
    list_display = ['reference_id', 'branch', 'date', 'shift', 'accountant', 'actual_total', 'expected_foodics', 'variance', 'created_at']
    list_filter = ['branch', 'shift', 'date']
    search_fields = ['reference_id', 'accountant', 'branch__name']


@admin.register(VisaMachineFile)
class VisaMachineFileAdmin(admin.ModelAdmin):
    list_display = ['entry', 'serial', 'created_at']


@admin.register(CollectorHandover)
class CollectorHandoverAdmin(admin.ModelAdmin):
    list_display = ['shift_entry', 'collector_name', 'actual_total', 'diff_from_waiter', 'diff_from_expected', 'recounted_at']
