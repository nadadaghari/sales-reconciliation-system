from decimal import Decimal
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from .constants import DENOMS, AED_DENOMS, DELIVERY_SOURCES, SHIFT_CHOICES


class Branch(models.Model):
    name = models.CharField(max_length=120, unique=True)
    code = models.CharField(max_length=20, unique=True, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('waiter', 'Waiter / Branch Accountant'),
        ('collector', 'Collector'),
        ('audit', 'Audit'),
        ('admin', 'Admin'),
        ('it', 'IT (Full Access)'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    # Only meaningful for the 'waiter' role — locks their entry form to one branch.
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True, related_name='staff')
    # Only meaningful for the 'waiter' role — the head cashier's name at that branch.
    head_cashier_name = models.CharField(max_length=200, blank=True)
    # Only meaningful for the 'waiter' role — their fingerprint/attendance (punch) ID.
    punch_id = models.CharField(max_length=50, blank=True)

    @property
    def is_full_access(self):
        """Admin and IT both get unrestricted access to every page."""
        return self.role in ('admin', 'it')

    def __str__(self):
        return f'{self.user.username} ({self.get_role_display()})'


def _cash_total_from_counts(cash_counts: dict) -> Decimal:
    total = Decimal('0')
    for denom in DENOMS:
        count = Decimal(str(cash_counts.get(denom, 0) or 0))
        total += count * Decimal(denom)
    return total


def _aed_cash_total_from_counts(cash_counts_aed: dict) -> Decimal:
    total = Decimal('0')
    for denom in AED_DENOMS:
        count = Decimal(str(cash_counts_aed.get(denom, 0) or 0))
        total += count * Decimal(denom)
    return total


def _delivery_total_from_data(delivery_data: dict) -> Decimal:
    total = Decimal('0')
    for key, _label in DELIVERY_SOURCES:
        source = delivery_data.get(key, {}) or {}
        total += Decimal(str(source.get('amount', 0) or 0))
    return total


def _visa_total_from_entries(visa_entries: list) -> Decimal:
    total = Decimal('0')
    for row in visa_entries or []:
        total += Decimal(str(row.get('amount', 0) or 0))
    return total


class ShiftEntry(models.Model):
    """One waiter/branch-accountant submission for a single shift."""

    branch = models.ForeignKey(Branch, on_delete=models.PROTECT, related_name='shift_entries')
    date = models.DateField()
    shift = models.CharField(max_length=1, choices=SHIFT_CHOICES)
    accountant = models.CharField(max_length=200, blank=True)

    # e.g. "AKL-0001" — sequential per branch, so numbering differs branch to branch.
    reference_id = models.CharField(max_length=40, unique=True, blank=True)

    staff_discount = models.DecimalField(max_digits=10, decimal_places=3, default=0)
    petty_cash = models.DecimalField(max_digits=10, decimal_places=3, default=0)

    # {"0.05": 4, "0.1": 5, ...} — OMR cash counted.
    cash_counts = models.JSONField(default=dict, blank=True)
    # {"5": 2, "10": 1, ...} — AED cash counted (converted into cash_total using aed_exchange_rate).
    cash_counts_aed = models.JSONField(default=dict, blank=True)
    aed_exchange_rate = models.DecimalField(max_digits=6, decimal_places=4, default=Decimal('0.1000'))
    # Combined OMR total — OMR cash counted + (AED cash counted × aed_exchange_rate).
    cash_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # [{"serial": "10026512", "amount": 66.4}, ...] — per-machine receipt files live in VisaMachineFile.
    visa_entries = models.JSONField(default=list, blank=True)
    visa_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # {"talabat": {"orders": 60, "amount": 239.52, "cancel_orders": 0, "cancel_amount": 0}, ...}
    delivery_data = models.JSONField(default=dict, blank=True)
    delivery_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # One attachment per delivery source (fixed set, so plain fields rather than a related model).
    delivery_attachment_talabat = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)
    delivery_attachment_tmdone = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)
    delivery_attachment_khedmah = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)
    delivery_attachment_callcenter = models.FileField(upload_to='delivery_attachments/%Y/%m/', blank=True, null=True)

    actual_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    expected_foodics = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    variance = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    notes = models.TextField(blank=True)
    audit_notes = models.TextField(blank=True)
    is_audited = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def delivery_attachment_field(self, key):
        return getattr(self, f'delivery_attachment_{key}', None)

    def recalculate(self):
        """Server-side auto-calculation — never trust client-side totals."""
        omr_cash = _cash_total_from_counts(self.cash_counts)
        aed_cash = _aed_cash_total_from_counts(self.cash_counts_aed)
        rate = Decimal(str(self.aed_exchange_rate or 0))
        self.cash_total = omr_cash + (aed_cash * rate)
        self.visa_total = _visa_total_from_entries(self.visa_entries)
        self.delivery_total = _delivery_total_from_data(self.delivery_data)
        self.actual_total = self.cash_total + self.visa_total + self.delivery_total
        self.variance = self.actual_total - Decimal(str(self.expected_foodics or 0))

    def save(self, *args, **kwargs):
        self.recalculate()
        if not self.reference_id:
            prefix = self.branch.code or f'BR{self.branch.id}'
            existing_count = ShiftEntry.objects.filter(branch=self.branch).count()
            self.reference_id = f'{prefix}-{existing_count + 1:04d}'
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.branch} / {self.date} / Shift {self.shift}'


class VisaMachineFile(models.Model):
    """A receipt/photo attached to one specific visa machine row on an entry."""
    entry = models.ForeignKey(ShiftEntry, on_delete=models.CASCADE, related_name='visa_files')
    serial = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to='visa_attachments/%Y/%m/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Visa file for {self.serial or "unknown machine"} ({self.entry})'


class CollectorHandover(models.Model):
    """The collector's independent recount for a given shift entry."""

    shift_entry = models.OneToOneField(ShiftEntry, on_delete=models.CASCADE, related_name='collector')
    collector_name = models.CharField(max_length=200, blank=True)

    cash_counts = models.JSONField(default=dict, blank=True)
    cash_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    visa_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    delivery_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    actual_total = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    # actual_total - shift_entry.actual_total  → flags a handover-stage problem
    diff_from_waiter = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # actual_total - shift_entry.expected_foodics → the real final variance
    diff_from_expected = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    notes = models.TextField(blank=True)
    recounted_at = models.DateTimeField(auto_now=True)

    def recalculate(self):
        self.cash_total = _cash_total_from_counts(self.cash_counts)
        self.actual_total = (
            self.cash_total
            + Decimal(str(self.visa_total or 0))
            + Decimal(str(self.delivery_total or 0))
        )
        self.diff_from_waiter = self.actual_total - self.shift_entry.actual_total
        self.diff_from_expected = self.actual_total - self.shift_entry.expected_foodics

    def save(self, *args, **kwargs):
        self.recalculate()
        super().save(*args, **kwargs)

    def status(self, threshold):
        if abs(self.diff_from_waiter) > threshold:
            return 'handover_discrepancy'
        if abs(self.diff_from_expected) > threshold:
            return 'final_variance'
        return 'matched'

    def __str__(self):
        return f'Handover for {self.shift_entry}'


class ActivityLog(models.Model):
    """A simple audit trail of who did what, for accountability. Deliberately
    keeps a text snapshot of the username, so the log entry still makes
    sense even after that account is deleted."""

    ACTION_CHOICES = [
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('user_created', 'User Created'),
        ('user_edited', 'User Edited'),
        ('user_deleted', 'User Deleted'),
        ('user_activated', 'User Activated'),
        ('user_deactivated', 'User Deactivated'),
        ('account_unlocked', 'Account Unlocked'),
        ('branch_created', 'Branch Created'),
        ('branch_edited', 'Branch Edited'),
        ('branch_deleted', 'Branch Deleted'),
        ('branch_activated', 'Branch Activated'),
        ('branch_deactivated', 'Branch Deactivated'),
        ('entry_edited', 'Shift Entry Edited'),
        ('entry_archived', 'Shift Entry Archived'),
        ('entry_unarchived', 'Shift Entry Unarchived'),
        ('handover_saved', 'Collector Handover Saved'),
        ('entry_audited', 'Shift Entry Audited'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='activity_logs')
    username_snapshot = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    description = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.username_snapshot or "unknown"} - {self.get_action_display()} - {self.created_at}'
