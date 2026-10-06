import csv
import io
from urllib.parse import urlencode
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db.models import Sum
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme

from django.views.decorators.http import require_POST
from .constants import DENOMS, AED_DENOMS, DELIVERY_SOURCES, SHIFT_CHOICES
from .decorators import role_required
from .models import Branch, ShiftEntry, CollectorHandover, UserProfile, VisaMachineFile, ActivityLog


def login_view(request):
    if request.user.is_authenticated:
        return _redirect_for_role(request.user)
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        cache_key = f'login_attempts:{username.lower()}'

        if _is_locked_out(cache_key):
            messages.error(request, 'Too many failed attempts. Please wait a few minutes and try again.')
            return redirect('staff_login')

        user = authenticate(request, username=username, password=password)
        if user is None:
            _register_failed_attempt(cache_key)
            log_activity(request, 'login_failed', username_override=username)
            messages.error(request, 'Invalid username or password.')
            return redirect('staff_login')
        _clear_attempts(cache_key)
        login(request, user)
        log_activity(request, 'login_success', user=user)
        return _redirect_for_role(user)
    return render(request, 'salesapp/login.html')


def branch_login_view(request):
    """Login for branch waiters: branch code + Punch ID (identifies *which*
    waiter at that branch — a branch can now have several, one per shift) +
    a real password (hashed, not a raw 2-digit guess). Repeated failures are
    rate-limited below."""
    if request.user.is_authenticated:
        return _redirect_for_role(request.user)
    if request.method == 'POST':
        branch_code = request.POST.get('branch_code', '').strip()
        punch_id = request.POST.get('punch_id', '').strip()
        password = request.POST.get('password', '')
        cache_key = f'login_attempts:branch:{branch_code.lower()}:{punch_id.lower()}'

        if _is_locked_out(cache_key):
            messages.error(request, 'Too many failed attempts. Please wait a few minutes and try again.')
            return redirect('login')

        branch = Branch.objects.filter(code__iexact=branch_code).first() if branch_code else None
        if not branch:
            _register_failed_attempt(cache_key)
            log_activity(request, 'login_failed', description=f'branch code: {branch_code}')
            messages.error(request, 'Invalid branch code, Punch ID, or password.')
            return redirect('login')
        if not branch.is_active:
            messages.error(request, 'This branch is deactivated. Contact your admin.')
            return redirect('login')

        profile = UserProfile.objects.filter(role='waiter', branch=branch, punch_id__iexact=punch_id).select_related('user').first()
        if not profile:
            _register_failed_attempt(cache_key)
            log_activity(request, 'login_failed', description=f'branch code: {branch_code}, punch id: {punch_id}')
            messages.error(request, 'Invalid branch code, Punch ID, or password.')
            return redirect('login')
        if not profile.user.check_password(password):
            _register_failed_attempt(cache_key)
            log_activity(request, 'login_failed', description=f'branch code: {branch_code}, punch id: {punch_id}', username_override=profile.user.username)
            messages.error(request, 'Invalid branch code, Punch ID, or password.')
            return redirect('login')
        if not profile.user.is_active:
            if profile.pending_approval:
                messages.error(request, 'Your registration is waiting for admin approval. You can log in once it is approved.')
            else:
                messages.error(request, 'This account is deactivated. Contact your admin.')
            return redirect('login')

        _clear_attempts(cache_key)
        login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
        log_activity(request, 'login_success', user=profile.user, description=f'branch: {branch.name}')
        return redirect('entry')
    return render(request, 'salesapp/branch_login.html', {
        'prefill_branch_code': request.GET.get('branch_code', '').strip()[:50],
        'prefill_punch_id': request.GET.get('punch_id', '').strip()[:50],
    })


# A waiter who registers through the public link is active immediately — the
# only gate is the branch code, checked against the code stored on that branch.
# (Set to True to make new registrations wait for an admin to approve them.)
SELF_REGISTRATION_NEEDS_APPROVAL = False
REGISTER_MAX_ATTEMPTS = 10


def register_view(request):
    """Public page where a waiter registers themselves: name, Punch ID, branch,
    the branch's code (proves they belong there) and a password. The branch
    code is checked on the server, and failed tries are rate-limited per IP."""
    if request.user.is_authenticated:
        return _redirect_for_role(request.user)

    branches = Branch.objects.filter(is_active=True).order_by('name')
    form = {'name': '', 'punch_id': '', 'branch': '', 'branch_code': ''}
    done = None
    error = None

    if request.method == 'POST':
        form = {
            'name': request.POST.get('name', '').strip(),
            'punch_id': request.POST.get('punch_id', '').strip(),
            'branch': request.POST.get('branch', '').strip(),
            'branch_code': request.POST.get('branch_code', '').strip(),
        }
        password = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')
        cache_key = f'register_attempts:{_client_ip(request)}'
        branch = branches.filter(id=form['branch']).first() if form['branch'].isdigit() else None

        if cache.get(cache_key, 0) >= REGISTER_MAX_ATTEMPTS:
            error = 'Too many attempts. Please wait a few minutes and try again.'
        elif not (form['name'] and form['punch_id'] and branch and password):
            error = 'Please fill in every field.'
        elif not branch.code:
            error = f'{branch.name} has no branch code saved yet. Please ask your admin.'
        elif form['branch_code'] and form['branch_code'].lower() != branch.code.lower():
            cache.set(cache_key, cache.get(cache_key, 0) + 1, LOGIN_LOCKOUT_SECONDS)
            error = 'That branch code does not match the selected branch.'
        elif UserProfile.objects.filter(role='waiter', branch=branch, punch_id__iexact=form['punch_id']).exists():
            error = f'{branch.name} already has someone registered with Punch ID "{form["punch_id"]}". Check your Punch ID, or ask your admin.'
        elif len(password) < 8:
            error = 'Please choose a password of at least 8 characters.'
        elif password != password2:
            error = 'The two passwords do not match.'
        else:
            base_username = f'waiter_{branch.code or branch.id}'.lower().replace(' ', '')
            username, suffix = base_username, 1
            while User.objects.filter(username=username).exists():
                suffix += 1
                username = f'{base_username}_{suffix}'
            needs_approval = SELF_REGISTRATION_NEEDS_APPROVAL
            user = User.objects.create_user(username=username)
            user.set_password(password)  # hashed, never stored in plain text
            user.is_active = not needs_approval
            user.save()
            UserProfile.objects.create(
                user=user, role='waiter', branch=branch,
                head_cashier_name=form['name'], punch_id=form['punch_id'],
                pending_approval=needs_approval,
            )
            log_activity(request, 'user_created', username_override=username,
                         description=f'self-registered waiter "{form["name"]}" at {branch.name} ({username})')
            if needs_approval:
                done = 'pending'
            else:
                messages.success(request, f'Welcome {form["name"]}! You are registered — log in below.')
                return redirect(reverse('login') + '?' + urlencode({'branch_code': branch.code, 'punch_id': form['punch_id']}))

    return render(request, 'salesapp/register.html', {
        'branches': branches, 'form': form, 'error': error, 'done': done,
    })


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        log_activity(request, 'logout')
    logout(request)
    return redirect('login')


# Cash is counted to the baisa, so the Cash Reconciliation tolerates no real
# difference. (Deliberately NOT settings.VARIANCE_THRESHOLD, which is far too
# loose for cash and would let a shortage of a few rials pass as "matched".)
CASH_TOLERANCE = Decimal('0.001')


def _dec(value, default='0'):
    try:
        if value in (None, ''):
            return Decimal(default)
        return Decimal(str(value))
    except InvalidOperation:
        return Decimal(default)


def _redirect_for_role(user):
    """Send an already-logged-in user to the page that matches their role,
    instead of always sending them to Waiter Entry (which would 403 for non-waiters)."""
    profile = getattr(user, 'profile', None)
    if profile is None:
        return redirect('login')
    if profile.is_full_access:
        return redirect('create_user')
    if profile.role == 'collector':
        return redirect('collector')
    if profile.role in ('audit', 'manager'):
        return redirect('dashboard')
    return redirect('entry')


LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes


def _is_locked_out(cache_key):
    return cache.get(cache_key, 0) >= LOGIN_MAX_ATTEMPTS


def _register_failed_attempt(cache_key):
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, LOGIN_LOCKOUT_SECONDS)


def _clear_attempts(cache_key):
    cache.delete(cache_key)


def _parse_visa_rows(request):
    """One dict per submitted visa row, carrying that row's own receipt.
    Receipts are matched by row number (visa_attachment_<n>), never by their
    position among the uploaded files — otherwise a machine without a receipt
    would shift every later receipt onto the wrong machine."""
    serials = request.POST.getlist('visa_serial[]')
    amounts = request.POST.getlist('visa_amount[]')
    row_ids = request.POST.getlist('visa_row[]')
    rows = []
    for serial, amount, row_id in zip(serials, amounts, row_ids):
        serial = serial.strip()
        if not serial and not amount.strip():
            continue
        rows.append({
            'serial': serial,
            'amount': _dec(amount),
            'file': request.FILES.get(f'visa_attachment_{row_id}'),
        })
    return rows


def _save_visa_files(entry, rows):
    for row in rows:
        if row['file']:
            VisaMachineFile.objects.create(entry=entry, serial=row['serial'], file=row['file'])


def _safe_next(request):
    """A "take me back to where I was" address, sent by the page that linked
    here. Only paths on this site are honoured — anything else is ignored, so
    the link can't be abused to bounce people to another website."""
    nxt = request.POST.get('next') or request.GET.get('next') or ''
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return nxt
    return ''


def _reopen_url(request, base_path, entry_id):
    """The same report again after a save, keeping whatever filters were active
    (branch, dates, shifts) so Back lands on the list the user was working in."""
    params = request.GET.copy()
    params['entry_id'] = entry_id
    return f"{base_path}?{params.urlencode()}"


def _cash_subtotals(denom_rows, aed_rows):
    """OMR subtotal, and the AED subtotal converted to OMR — for the cash cards
    that show OMR beside AED."""
    omr = sum((Decimal(str(r['amount'])) for r in denom_rows or []), Decimal('0'))
    aed = sum((Decimal(str(r['omr_equivalent'])) for r in aed_rows or []), Decimal('0'))
    return {'cash_omr_total': omr, 'cash_aed_in_omr': aed}


def _entry_cash_context(entry):
    """The waiter's cash report, broken down by denomination for display."""
    aed_rate = float(entry.aed_exchange_rate or 0)
    entry_denoms = [
        {'denom': d, 'count': entry.cash_counts.get(d, 0), 'amount': float(d) * int(entry.cash_counts.get(d, 0) or 0)}
        for d in DENOMS
    ]
    entry_aed_denoms = [
        {
            'denom': d,
            'count': entry.cash_counts_aed.get(d, 0),
            'amount': float(d) * int(entry.cash_counts_aed.get(d, 0) or 0),
            'omr_equivalent': float(d) * int(entry.cash_counts_aed.get(d, 0) or 0) * aed_rate,
        }
        for d in AED_DENOMS if entry.cash_counts_aed.get(d, 0)
    ]
    return {'entry_denoms': entry_denoms, 'entry_aed_denoms': entry_aed_denoms,
            **_cash_subtotals(entry_denoms, entry_aed_denoms)}


def _handover_cash_context(handover):
    """The collector's count, broken down the same way (only denominations actually counted)."""
    aed_rate = float(handover.shift_entry.aed_exchange_rate or 0)
    denoms = [
        {'denom': d, 'count': handover.cash_counts.get(d, 0), 'amount': float(d) * int(handover.cash_counts.get(d, 0) or 0)}
        for d in DENOMS if handover.cash_counts.get(d, 0)
    ]
    aed = [
        {
            'denom': d,
            'count': handover.cash_counts_aed.get(d, 0),
            'amount': float(d) * int(handover.cash_counts_aed.get(d, 0) or 0),
            'omr_equivalent': float(d) * int(handover.cash_counts_aed.get(d, 0) or 0) * aed_rate,
        }
        for d in AED_DENOMS if handover.cash_counts_aed.get(d, 0)
    ]
    subtotals = _cash_subtotals(denoms, aed)
    return {'handover_denoms': denoms, 'handover_aed_denoms': aed,
            'handover_omr_total': subtotals['cash_omr_total'], 'handover_aed_in_omr': subtotals['cash_aed_in_omr']}


def _shift_snapshot(entry):
    """The same shape as ShiftEntry.original_snapshot, built from an entry's
    CURRENT state — used to capture 'before' just ahead of applying an edit,
    so that edit's own diff can be computed (regardless of what the very
    first waiter submission looked like)."""
    return {
        'cash_counts': dict(entry.cash_counts),
        'cash_counts_aed': dict(entry.cash_counts_aed),
        'visa_entries': list(entry.visa_entries),
        'delivery_data': dict(entry.delivery_data),
        'staff_discount': str(entry.staff_discount),
        'cash_cancel_amount': str(entry.cash_cancel_amount),
        'petty_cash': str(entry.petty_cash),
    }


def _handover_snapshot(handover):
    return {
        'cash_counts': dict(handover.cash_counts),
        'cash_counts_aed': dict(handover.cash_counts_aed),
    }


def _decimals_differ(old_str, new_value):
    try:
        return Decimal(str(old_str or '0')) != Decimal(str(new_value))
    except Exception:
        return str(old_str) != str(new_value)


def _shift_field_diffs(snap, entry):
    """Per-field 'changed from X to Y' notes, comparing entry's current
    numbers against an arbitrary earlier snapshot (same shape as
    ShiftEntry.original_snapshot). Empty if snap is empty or nothing differs."""
    changes = {}
    if not snap:
        return changes
    for d in DENOMS:
        old = int(snap.get('cash_counts', {}).get(d, 0) or 0)
        new = int(entry.cash_counts.get(d, 0) or 0)
        if old != new:
            changes[f'denom_{d}'] = f'Changed from {old} to {new}'
    for d in AED_DENOMS:
        old = int(snap.get('cash_counts_aed', {}).get(d, 0) or 0)
        new = int(entry.cash_counts_aed.get(d, 0) or 0)
        if old != new:
            changes[f'denom_aed_{d}'] = f'Changed from {old} to {new}'
    if _decimals_differ(snap.get('staff_discount', '0'), entry.staff_discount):
        changes['staff_discount'] = f"Changed from {snap.get('staff_discount', '0')} to {entry.staff_discount}"
    if _decimals_differ(snap.get('cash_cancel_amount', '0'), entry.cash_cancel_amount):
        changes['cash_cancel_amount'] = f"Changed from {snap.get('cash_cancel_amount', '0')} to {entry.cash_cancel_amount}"
    if _decimals_differ(snap.get('petty_cash', '0'), entry.petty_cash):
        changes['petty_cash'] = f"Changed from {snap.get('petty_cash', '0')} to {entry.petty_cash}"
    for key, _label in DELIVERY_SOURCES:
        old_row = snap.get('delivery_data', {}).get(key, {})
        new_row = entry.delivery_data.get(key, {})
        for field in ['orders', 'amount', 'cancel_orders', 'cancel_amount']:
            old_v = old_row.get(field, 0)
            new_v = new_row.get(field, 0)
            if old_v != new_v:
                changes[f'{field}_{key}'] = f'Changed from {old_v} to {new_v}'
    old_visa_total = sum(float(v.get('amount', 0)) for v in snap.get('visa_entries', []))
    new_visa_total = sum(float(v.get('amount', 0)) for v in entry.visa_entries)
    if abs(old_visa_total - new_visa_total) > 0.0001 or len(snap.get('visa_entries', [])) != len(entry.visa_entries):
        changes['visa_total'] = f'Changed from {old_visa_total:.3f} to {new_visa_total:.3f}'
    return changes


def _shift_field_diff_lines_sales(snap, entry):
    """Daily Sales section only: Discount, Visa, Delivery. Named per the card
    the field lives in, so the history line reads like the page does."""
    diffs = _shift_field_diffs(snap, entry)
    lines = []
    if 'staff_discount' in diffs:
        lines.append('Discount: ' + diffs['staff_discount'].replace('Changed from ', '').replace(' to ', ' → '))
    if 'visa_total' in diffs:
        lines.append('Visa: ' + diffs['visa_total'].replace('Changed from ', '').replace(' to ', ' → '))
    for key, source_label in DELIVERY_SOURCES:
        for field, field_label in [('orders', 'orders'), ('amount', 'amount'), ('cancel_orders', 'cancelled orders'), ('cancel_amount', 'cancelled amount')]:
            k = f'{field}_{key}'
            if k in diffs:
                lines.append(f'Delivery — {source_label} {field_label}: ' + diffs[k].replace('Changed from ', '').replace(' to ', ' → '))
    return lines


def _shift_field_diff_lines_cash(snap, entry):
    """Cash section only: OMR/AED counts, cash cancellation, petty cash."""
    diffs = _shift_field_diffs(snap, entry)
    lines = []
    for d in DENOMS:
        if f'denom_{d}' in diffs:
            lines.append('Cash ' + d + ': ' + diffs[f'denom_{d}'].replace('Changed from ', '').replace(' to ', ' → '))
    for d in AED_DENOMS:
        if f'denom_aed_{d}' in diffs:
            lines.append('AED ' + d + ': ' + diffs[f'denom_aed_{d}'].replace('Changed from ', '').replace(' to ', ' → '))
    for field_key, label in [('cash_cancel_amount', 'Cash cancelled'), ('petty_cash', 'Petty cash')]:
        if field_key in diffs:
            lines.append(f'{label}: ' + diffs[field_key].replace('Changed from ', '').replace(' to ', ' → '))
    return lines


def _handover_field_diff_lines(snap, handover):
    lines = []
    if not snap:
        return lines
    for d in DENOMS:
        old = int(snap.get('cash_counts', {}).get(d, 0) or 0)
        new = int(handover.cash_counts.get(d, 0) or 0)
        if old != new:
            lines.append(f'Cash {d}: {old} → {new}')
    for d in AED_DENOMS:
        old = int(snap.get('cash_counts_aed', {}).get(d, 0) or 0)
        new = int(handover.cash_counts_aed.get(d, 0) or 0)
        if old != new:
            lines.append(f'AED {d}: {old} → {new}')
    return lines


def _compute_shift_changes(entry):
    """Per-field 'changed from X to Y' notes, comparing the entry's current
    numbers to the waiter's original submission. Empty if nothing was ever
    corrected, or if the entry predates this feature (no snapshot saved)."""
    return _shift_field_diffs(entry.original_snapshot or {}, entry)


def _compute_handover_changes(handover):
    """Which of the collector's fields are marked 'Audited': any count that
    differs from what the WAITER reported, plus any count edited after his
    first save."""
    changes = {}
    entry = handover.shift_entry
    snap = handover.original_snapshot or {}
    for d in DENOMS:
        new = int(handover.cash_counts.get(d, 0) or 0)
        waiter = int(entry.cash_counts.get(d, 0) or 0)
        first = int(snap.get('cash_counts', {}).get(d, new) or 0) if snap else new
        if new != waiter:
            changes[f'cdenom_{d}'] = f'Waiter {waiter} → collector {new}'
        elif new != first:
            changes[f'cdenom_{d}'] = f'Changed from {first} to {new}'
    for d in AED_DENOMS:
        new = int(handover.cash_counts_aed.get(d, 0) or 0)
        waiter = int(entry.cash_counts_aed.get(d, 0) or 0)
        first = int(snap.get('cash_counts_aed', {}).get(d, new) or 0) if snap else new
        if new != waiter:
            changes[f'cdenom_aed_{d}'] = f'Waiter {waiter} → collector {new}'
        elif new != first:
            changes[f'cdenom_aed_{d}'] = f'Changed from {first} to {new}'
    return changes


def _build_stepper(entry, handover, review_log):
    """The four stages a shift moves through. 'current' marks the first one
    not yet done — that's the stage Audit still needs to act on. Each step
    carries the id of the card it should jump to when clicked."""
    steps = [
        {'key': 'submitted', 'label': 'Waiter Submitted', 'anchor': 'stepWaiterSubmitted',
         'done': True, 'timestamp': entry.created_at},
        {'key': 'sales_reviewed', 'label': 'Sales Reviewed', 'anchor': 'stepSalesReviewed',
         'done': entry.is_audited, 'timestamp': review_log.created_at if review_log else None},
        {'key': 'cash_collected', 'label': 'Cash Collected', 'anchor': 'stepCashCollected',
         'done': handover is not None, 'timestamp': handover.recounted_at if handover else None},
        {'key': 'cash_reconciled', 'label': 'Cash Reconciled', 'anchor': 'stepCashCollected',
         'done': bool(handover and handover.reconciled),
         'timestamp': handover.reconciled_at if (handover and handover.reconciled) else None},
    ]
    current_index = next((i for i, s in enumerate(steps) if not s['done']), None)
    for i, s in enumerate(steps):
        s['current'] = (i == current_index)
    return {'steps': steps, 'complete': current_index is None}


def _apply_waiter_financials(request, entry):
    """Applies the cash/visa/delivery/discount fields from a POST to an entry.
    Shared by the waiter's own edit page and by Audit's inline correction on
    the Sales Review card, so a fix made in either place saves the same way."""
    entry.staff_discount = _dec(request.POST.get('staff_discount'))
    entry.petty_cash = _dec(request.POST.get('petty_cash'))
    entry.cash_counts = {d: int(request.POST.get(f'denom_{d}', 0) or 0) for d in DENOMS}
    entry.cash_counts_aed = {d: int(request.POST.get(f'denom_aed_{d}', 0) or 0) for d in AED_DENOMS}
    entry.aed_exchange_rate = _dec(request.POST.get('aed_exchange_rate'), default='0.1000')
    entry.cash_cancel_amount = _dec(request.POST.get('cash_cancel_amount'))

    visa_rows = _parse_visa_rows(request)
    entry.visa_entries = [{'serial': r['serial'], 'amount': float(r['amount'])} for r in visa_rows]

    delivery_data = {}
    for key, _label in DELIVERY_SOURCES:
        delivery_data[key] = {
            'orders': int(request.POST.get(f'orders_{key}', 0) or 0),
            'amount': float(_dec(request.POST.get(f'amount_{key}', 0))),
            'cancel_orders': int(request.POST.get(f'cancel_orders_{key}', 0) or 0),
            'cancel_amount': float(_dec(request.POST.get(f'cancel_amount_{key}', 0))),
        }
    entry.delivery_data = delivery_data

    if request.FILES.get('discount_attachment'):
        entry.staff_discount_attachment = request.FILES['discount_attachment']
    if request.FILES.get('cash_cancel_attachment'):
        entry.cash_cancel_attachment = request.FILES['cash_cancel_attachment']
    for key, _label in DELIVERY_SOURCES:
        uploaded = request.FILES.get(f'delivery_attachment_{key}')
        if uploaded:
            setattr(entry, f'delivery_attachment_{key}', uploaded)

    return visa_rows


def _build_visa_rows(entry):
    """Pairs each visa_entries[] row with its matching VisaMachineFile (by
    serial) so the template can show serial + amount + receipt in one table
    row instead of two separate, hard-to-match lists."""
    files_by_serial = {}
    for vf in entry.visa_files.all():
        files_by_serial.setdefault(vf.serial, vf)
    rows = []
    for v in entry.visa_entries or []:
        serial = v.get('serial', '')
        rows.append({
            'serial': serial,
            'amount': v.get('amount', 0),
            'file': files_by_serial.get(serial),
        })
    return rows


def _client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def log_activity(request, action, description='', user=None, username_override=None, details=''):
    """Record one line in the audit trail. Pass `user` explicitly right
    after a successful login (before/without relying on request.user), or
    `username_override` for failed-login attempts where there's no user
    object at all — just the username someone typed in. `details` is a short
    human-readable summary of what actually changed, shown in Audit History."""
    actor = user or (request.user if request.user.is_authenticated else None)
    snapshot = username_override or (actor.username if actor else '')
    ActivityLog.objects.create(
        user=actor,
        username_snapshot=snapshot,
        action=action,
        description=description[:255],
        details=details,
        ip_address=_client_ip(request),
    )


@role_required('waiter', 'admin')
def entry_view(request):
    profile = request.user.profile
    locked_branch = profile.branch if profile.role == 'waiter' else None

    if request.method == 'POST':
        if locked_branch:
            branch = locked_branch
        else:
            branch_name = request.POST.get('branch', '').strip()
            if not branch_name:
                messages.error(request, 'Please fill in branch and date.')
                return redirect('entry')
            branch, _ = Branch.objects.get_or_create(name=branch_name)

        if profile.role == 'waiter':
            date = timezone.localdate()  # server-side truth — never trust a client-submitted date for waiters
        else:
            date = request.POST.get('date')

        shift = request.POST.get('shift')
        accountant = profile.head_cashier_name if profile.role == 'waiter' else request.POST.get('accountant', '').strip()

        if not date:
            messages.error(request, 'Please fill in branch and date.')
            return redirect('entry')

        cash_counts = {d: int(request.POST.get(f'denom_{d}', 0) or 0) for d in DENOMS}
        cash_counts_aed = {d: int(request.POST.get(f'denom_aed_{d}', 0) or 0) for d in AED_DENOMS}
        aed_exchange_rate = _dec(request.POST.get('aed_exchange_rate'), default='0.1000')

        visa_rows = _parse_visa_rows(request)
        visa_entries = [{'serial': r['serial'], 'amount': float(r['amount'])} for r in visa_rows]

        delivery_data = {}
        for key, _label in DELIVERY_SOURCES:
            delivery_data[key] = {
                'orders': int(request.POST.get(f'orders_{key}', 0) or 0),
                'amount': float(_dec(request.POST.get(f'amount_{key}', 0))),
                'cancel_orders': int(request.POST.get(f'cancel_orders_{key}', 0) or 0),
                'cancel_amount': float(_dec(request.POST.get(f'cancel_amount_{key}', 0))),
            }

        entry = ShiftEntry(
            branch=branch,
            date=date,
            shift=shift,
            accountant=accountant,
            petty_cash=_dec(request.POST.get('petty_cash')),
            staff_discount=_dec(request.POST.get('discount_amount')),
            cash_counts=cash_counts,
            cash_counts_aed=cash_counts_aed,
            aed_exchange_rate=aed_exchange_rate,
            visa_entries=visa_entries,
            cash_cancel_amount=_dec(request.POST.get('cash_cancel_amount')),
            delivery_data=delivery_data,
            notes=request.POST.get('notes', ''),
            # expected_foodics is set later by Audit, not by the waiter.
        )
        if request.FILES.get('discount_attachment'):
            entry.staff_discount_attachment = request.FILES['discount_attachment']
        if request.FILES.get('notes_attachment'):
            entry.notes_attachment = request.FILES['notes_attachment']
        if request.FILES.get('cash_cancel_attachment'):
            entry.cash_cancel_attachment = request.FILES['cash_cancel_attachment']
        for key, _label in DELIVERY_SOURCES:
            uploaded = request.FILES.get(f'delivery_attachment_{key}')
            if uploaded:
                setattr(entry, f'delivery_attachment_{key}', uploaded)
        entry.save()
        _save_visa_files(entry, visa_rows)

        return redirect(f"/?submitted={entry.reference_id}")

    context = {
        'denoms': DENOMS,
        'aed_denoms': AED_DENOMS,
        'denom_pairs': list(zip(DENOMS, AED_DENOMS)),
        'delivery_sources': DELIVERY_SOURCES,
        'shift_choices': SHIFT_CHOICES,
        'active_tab': 'entry',
        'locked_branch': locked_branch,
        'head_cashier_name': profile.head_cashier_name if profile.role == 'waiter' else None,
        'today': timezone.localdate() if profile.role == 'waiter' else None,
        'submitted_ref': request.GET.get('submitted'),
        'submitted_branch': locked_branch.name if locked_branch else None,
    }
    return render(request, 'salesapp/entry.html', context)


@role_required('collector', 'audit', 'admin')
def collector_view(request):
    if request.method == 'POST':
        entry_id = request.POST.get('shift_entry_id')
        shift_entry = get_object_or_404(ShiftEntry, id=entry_id)

        cash_counts = {d: int(request.POST.get(f'cdenom_{d}', 0) or 0) for d in DENOMS}
        cash_counts_aed = {d: int(request.POST.get(f'cdenom_aed_{d}', 0) or 0) for d in AED_DENOMS}

        handover = CollectorHandover.objects.filter(shift_entry=shift_entry).first()
        is_new = handover is None
        if is_new:
            handover = CollectorHandover(shift_entry=shift_entry)
        before_snap = _handover_snapshot(handover)
        if is_new:
            # nothing saved before: what he changes is measured against the waiter's own count
            before_snap = {'cash_counts': dict(shift_entry.cash_counts), 'cash_counts_aed': dict(shift_entry.cash_counts_aed)}
        if not is_new and not handover.original_snapshot:
            # Older record saved before baselines existed: treat the count as it
            # stood just before this edit as the baseline, so this edit is flagged.
            handover.original_snapshot = before_snap
        handover.collector_name = request.POST.get('collector_name', '').strip()
        handover.cash_counts = cash_counts
        handover.cash_counts_aed = cash_counts_aed
        handover.notes = request.POST.get('notes', '')
        # A new count invalidates any earlier Cash Reconciliation sign-off.
        handover.reconciled = False
        handover.reconciled_at = None
        handover.save()

        diff_lines = _handover_field_diff_lines(before_snap, handover)
        by_audit = request.user.profile.role in ('audit', 'admin')
        total = f'{Decimal(str(handover.cash_total)):.3f}'
        # The Who column already names the person, so the details carry only what changed.
        if is_new:
            head = f'Recorded: {total} RO' if by_audit else f'Collector count: {total} RO'
            details = (head + "\nDifferent from the waiter's count (waiter → collector):\n" + '\n'.join(diff_lines)) if diff_lines \
                else head + " — matches the waiter's count"
        elif diff_lines:
            details = '\n'.join(diff_lines)
        else:
            details = f'Saved again, counts unchanged: {total} RO'
        log_activity(request, 'handover_saved', description=shift_entry.reference_id, details=details)
        messages.success(request, 'Collector handover saved.')
        return redirect(_safe_next(request) or _reopen_url(request, '/collector/', entry_id))

    selected_entry = None
    selected_handover = None

    search_ref = request.GET.get('search_ref', '').strip()
    entry_id = request.GET.get('entry_id')

    if search_ref and not entry_id:
        matched = ShiftEntry.objects.filter(reference_id__iexact=search_ref).first()
        if matched:
            return redirect(f"/collector/?entry_id={matched.id}")
        messages.error(request, f'No entry found with reference ID "{search_ref}".')

    handover_changes = {}
    shift_changes = {}
    cash_history = None
    if entry_id:
        selected_entry = get_object_or_404(ShiftEntry, id=entry_id)
        selected_handover = getattr(selected_entry, 'collector', None)
        if selected_handover is not None:
            handover_changes = _compute_handover_changes(selected_handover)
        shift_changes = _compute_shift_changes(selected_entry)
        cash_history = list(
            ActivityLog.objects.filter(
                description=selected_entry.reference_id,
                action__in=['handover_saved', 'cash_reconciled', 'entry_edited'],
            ).order_by('-created_at')
        )

    entry_denoms = None
    entry_aed_denoms = None
    entry_visa_rows = None
    if selected_entry:
        entry_denoms = [
            {'denom': d, 'count': selected_entry.cash_counts.get(d, 0), 'amount': float(d) * int(selected_entry.cash_counts.get(d, 0) or 0)}
            for d in DENOMS
        ]
        aed_rate = float(selected_entry.aed_exchange_rate or 0)
        entry_aed_denoms = [
            {
                'denom': d,
                'count': selected_entry.cash_counts_aed.get(d, 0),
                'amount': float(d) * int(selected_entry.cash_counts_aed.get(d, 0) or 0),
                'omr_equivalent': float(d) * int(selected_entry.cash_counts_aed.get(d, 0) or 0) * aed_rate,
            }
            for d in AED_DENOMS if selected_entry.cash_counts_aed.get(d, 0)
        ]
        entry_visa_rows = _build_visa_rows(selected_entry)

    shift_filter = request.GET.getlist('shift_filter')
    branch_filter = request.GET.get('branch_filter', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    all_entries_qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False).order_by('-created_at')
    if shift_filter:
        all_entries_qs = all_entries_qs.filter(shift__in=shift_filter)
    if branch_filter:
        all_entries_qs = all_entries_qs.filter(branch__name__icontains=branch_filter)
    if date_from:
        all_entries_qs = all_entries_qs.filter(date__gte=date_from)
    if date_to:
        all_entries_qs = all_entries_qs.filter(date__lte=date_to)
    if search_ref:
        all_entries_qs = all_entries_qs.filter(reference_id__icontains=search_ref)

    group_summary = None
    if branch_filter and (date_from or date_to) and all_entries_qs.exists():
        agg = all_entries_qs.aggregate(total_cash=Sum('cash_total'))
        group_summary = {
            'count': all_entries_qs.count(),
            'shifts': sorted(set(all_entries_qs.values_list('shift', flat=True))),
            **agg,
        }

    # Group the (filtered) entries by branch, with a running total per branch,
    # so the collector can see each branch's cash/visa/delivery totals at a glance.
    branch_groups_map = {}
    for e in all_entries_qs:
        group = branch_groups_map.setdefault(e.branch_id, {
            'branch': e.branch,
            'entries': [],
            'total_cash': Decimal('0'),
        })
        group['entries'].append(e)
        handover = getattr(e, 'collector', None)
        if handover is None:
            e.simple_status = 'not_collected'
        elif handover.reconciled:
            e.simple_status = 'reconciled'
        else:
            e.simple_status = 'collected'
        group['total_cash'] += e.cash_total
    branch_groups = sorted(branch_groups_map.values(), key=lambda g: g['branch'].name)

    # Sort each branch's entries by date (newest first) and flag the first
    # row of each date so the template can draw a divider line before it.
    # date_group is a 0-indexed counter per branch, used for the "show more
    # dates" pagination in the template (client-side, no reload needed).
    for group in branch_groups:
        group['entries'].sort(key=lambda e: (e.date, e.created_at), reverse=True)
        previous_date = None
        date_group = -1
        for e in group['entries']:
            e.show_date_divider = (e.date != previous_date)
            if e.show_date_divider:
                date_group += 1
            e.date_group = date_group
            previous_date = e.date
        group['date_group_count'] = date_group + 1

    cash_subtotals = _cash_subtotals(entry_denoms, entry_aed_denoms)

    context = {
        **cash_subtotals,
        'all_entries': all_entries_qs,
        'branch_groups': branch_groups,
        'shift_filter': shift_filter,
        'branch_filter': branch_filter,
        'date_from': date_from,
        'date_to': date_to,
        'group_summary': group_summary,
        'shift_choices': SHIFT_CHOICES,
        'denoms': DENOMS,
        'selected_entry': selected_entry,
        'selected_handover': selected_handover,
        'entry_denoms': entry_denoms,
        'entry_aed_denoms': entry_aed_denoms,
        'entry_visa_rows': entry_visa_rows,
        'aed_denoms': AED_DENOMS,
        'delivery_sources': DELIVERY_SOURCES,
        'cash_tolerance': CASH_TOLERANCE,
        'handover_changes': handover_changes,
        'shift_changes': shift_changes,
        'waiter_cash_changes': sum(1 for k in shift_changes if k.startswith('denom_') or k in ('cash_cancel_amount', 'petty_cash')),
        'cash_history': cash_history,
        'next_url': _safe_next(request),
        'search_ref': search_ref,
        'active_tab': 'collector',
    }
    return render(request, 'salesapp/collector.html', context)


@role_required('audit', 'manager', 'admin')
def dashboard_view(request):
    """The single Audit workspace. Every shift moves through four stages —
    Waiter Submitted, Sales Reviewed, Cash Collected, Cash Reconciled — shown
    as a stepper when the shift is opened. There are no separate tabs: the
    sales review (Foodics) and the cash reconciliation both live on this one
    page, one after the other in the same report."""
    threshold = Decimal(str(settings.VARIANCE_THRESHOLD))
    is_viewer = request.user.profile.role == 'manager'

    if request.method == 'POST':
        if is_viewer:
            raise PermissionDenied('Managers have view-only access.')
        entry_id = request.POST.get('entry_id')
        entry = get_object_or_404(ShiftEntry, id=entry_id)
        before_snap = _shift_snapshot(entry)
        if not entry.original_snapshot:
            entry.original_snapshot = before_snap   # legacy shift: baseline = how it stood before this edit
        old_foodics = entry.expected_foodics
        old_notes = entry.audit_notes
        old_date, old_shift, old_accountant = entry.date, entry.shift, entry.accountant
        if request.POST.get('date'):
            entry.date = request.POST.get('date')
        if request.POST.get('shift'):
            entry.shift = request.POST.get('shift')
        entry.accountant = request.POST.get('accountant', '').strip()
        visa_rows = _apply_waiter_financials(request, entry)
        entry.audit_notes = request.POST.get('audit_notes', '').strip()
        if 'expected_foodics' in request.POST:
            entry.expected_foodics = _dec(request.POST.get('expected_foodics'))
        entry.is_audited = True
        entry.save()  # full save so recalculate() persists the updated variance too
        _save_visa_files(entry, visa_rows)
        handover = getattr(entry, 'collector', None)
        if handover is not None:
            handover.save()  # re-derive the cash difference from any corrected figures

        # Daily Sales and Cash never share a history line — even though Audit can
        # correct both from this one page, each gets logged under its own action.
        sales_lines = _shift_field_diff_lines_sales(before_snap, entry)
        if str(old_date) != str(entry.date):
            sales_lines.append(f'Date: {old_date} → {entry.date}')
        if old_shift != entry.shift:
            sales_lines.append(f'Shift: {old_shift} → {entry.shift}')
        if old_accountant != entry.accountant:
            sales_lines.append(f'Accountant: "{old_accountant}" → "{entry.accountant}"')
        if _decimals_differ(str(old_foodics), entry.expected_foodics):
            sales_lines.append(f'Foodics: {Decimal(str(old_foodics)):.3f} → {Decimal(str(entry.expected_foodics)):.3f}')
        if entry.audit_notes and entry.audit_notes != old_notes:
            sales_lines.append(f'Note: "{entry.audit_notes}"')
        sales_details = '\n'.join(sales_lines) if sales_lines else 'No numbers changed.'
        log_activity(request, 'entry_audited', description=entry.reference_id, details=sales_details)

        cash_lines = _shift_field_diff_lines_cash(before_snap, entry)
        if cash_lines:
            log_activity(request, 'entry_edited', description=entry.reference_id, details='\n'.join(cash_lines))

        messages.success(request, f'{entry.reference_id} sales review approved.')
        return redirect(_reopen_url(request, '/dashboard/', entry_id))

    selected_entry = None
    selected_handover = None
    review_log = None
    entry_id = request.GET.get('entry_id')
    if entry_id:
        selected_entry = get_object_or_404(ShiftEntry, id=entry_id)
        selected_handover = getattr(selected_entry, 'collector', None)
        if selected_entry.is_audited:
            review_log = ActivityLog.objects.filter(
                action='entry_audited', description=selected_entry.reference_id
            ).order_by('-created_at').first()

    entry_denoms = entry_aed_denoms = entry_visa_rows = None
    handover_denoms = handover_aed_denoms = None
    handover_omr_total = handover_aed_in_omr = None
    selected_has_difference = False
    stepper = None
    shift_changes = {}
    handover_changes = {}
    if selected_entry:
        cash_ctx = _entry_cash_context(selected_entry)
        entry_denoms = cash_ctx['entry_denoms']
        entry_aed_denoms = cash_ctx['entry_aed_denoms']
        entry_visa_rows = _build_visa_rows(selected_entry)
        shift_changes = _compute_shift_changes(selected_entry)
        if selected_handover is not None:
            h_ctx = _handover_cash_context(selected_handover)
            handover_denoms = h_ctx['handover_denoms']
            handover_aed_denoms = h_ctx['handover_aed_denoms']
            handover_omr_total = h_ctx['handover_omr_total']
            handover_aed_in_omr = h_ctx['handover_aed_in_omr']
            selected_has_difference = selected_handover.has_difference(CASH_TOLERANCE)
            handover_changes = _compute_handover_changes(selected_handover)
        stepper = _build_stepper(selected_entry, selected_handover, review_log)

    sales_history = None
    cash_history = None
    if selected_entry:
        sales_history = list(
            ActivityLog.objects.filter(
                description=selected_entry.reference_id, action='entry_audited',
            ).order_by('-created_at')
        )
        cash_history = list(
            ActivityLog.objects.filter(
                description=selected_entry.reference_id,
                action__in=['handover_saved', 'cash_reconciled', 'entry_edited'],
            ).order_by('-created_at')
        )

    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False)

    shift_filter = request.GET.getlist('shift_filter')
    branch_filter = request.GET.get('branch_filter', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    search_ref = request.GET.get('search_ref', '').strip()
    if shift_filter:
        qs = qs.filter(shift__in=shift_filter)
    if branch_filter:
        qs = qs.filter(branch__name__icontains=branch_filter)
    if date_from:
        qs = qs.filter(date__gte=date_from)
    if date_to:
        qs = qs.filter(date__lte=date_to)
    if search_ref:
        qs = qs.filter(reference_id__icontains=search_ref)
    qs = qs.order_by('-created_at')

    branch_groups_map = {}
    for e in qs:
        foodics_entered = e.expected_foodics != 0
        has_issue = foodics_entered and abs(e.variance) > threshold
        handover = getattr(e, 'collector', None)
        if not e.is_audited:
            stage = 'awaiting_sales'
        elif handover is None:
            stage = 'awaiting_collection'
        elif not handover.reconciled:
            stage = 'awaiting_cash_approval'
        else:
            stage = 'complete'

        group = branch_groups_map.setdefault(e.branch_id, {
            'branch': e.branch,
            'rows': [],
            'total_variance': Decimal('0'),
            'total_actual': Decimal('0'),
        })
        group['rows'].append({'entry': e, 'stage': stage, 'has_issue': has_issue})
        group['total_variance'] += e.variance
        group['total_actual'] += e.sales_actual

    branch_groups = sorted(branch_groups_map.values(), key=lambda g: g['branch'].name)

    # Sort each branch's rows by date (newest first) and flag the first row
    # of each date so the template can draw a divider line before it.
    for group in branch_groups:
        group['rows'].sort(key=lambda r: (r['entry'].date, r['entry'].created_at), reverse=True)
        previous_date = None
        date_group = -1
        for row in group['rows']:
            row['show_date_divider'] = (row['entry'].date != previous_date)
            if row['show_date_divider']:
                date_group += 1
            row['date_group'] = date_group
            previous_date = row['entry'].date
        group['date_group_count'] = date_group + 1

    context = {
        'review_log': review_log,
        'variance_threshold': threshold,
        'foodics_flagged': bool(selected_entry and selected_entry.expected_foodics != 0 and abs(selected_entry.variance) > threshold),
        'branch_groups': branch_groups,
        'shift_filter': shift_filter,
        'shift_choices': SHIFT_CHOICES,
        'branch_filter': branch_filter,
        'date_from': date_from,
        'date_to': date_to,
        'search_ref': search_ref,
        'denoms': DENOMS,
        'aed_denoms': AED_DENOMS,
        'delivery_sources': DELIVERY_SOURCES,
        'selected_entry': selected_entry,
        'is_viewer': is_viewer,
        'selected_handover': selected_handover,
        'selected_has_difference': selected_has_difference,
        'entry_denoms': entry_denoms,
        'entry_aed_denoms': entry_aed_denoms,
        'entry_visa_rows': entry_visa_rows,
        'handover_denoms': handover_denoms,
        'handover_aed_denoms': handover_aed_denoms,
        'handover_omr_total': handover_omr_total,
        'handover_aed_in_omr': handover_aed_in_omr,
        'stepper': stepper,
        'sales_history': sales_history,
        'cash_history': cash_history,
        'shift_changes': shift_changes,
        'handover_changes': handover_changes,
        'cash_change_count': sum(1 for k in shift_changes if k.startswith('denom_') or k in ('cash_cancel_amount', 'petty_cash')) + len(handover_changes),
        'sales_change_count': sum(1 for k in shift_changes if not (k.startswith('denom_') or k in ('cash_cancel_amount', 'petty_cash'))),
        'active_tab': 'dashboard',
    }
    return render(request, 'salesapp/dashboard.html', context)


@role_required('admin')
def create_user_view(request):
    if request.method == 'POST':
        role = request.POST.get('role')

        if role == 'waiter':
            head_cashier_name = request.POST.get('head_cashier_name', '').strip()
            punch_id = request.POST.get('punch_id', '').strip()
            password = request.POST.get('waiter_password', '')
            branch_id = request.POST.get('branch')
            branch = Branch.objects.filter(id=branch_id).first() if branch_id else None

            if not head_cashier_name or not branch:
                messages.error(request, 'Please fill in the head cashier name and select a branch.')
                return redirect('create_user')
            if not punch_id:
                messages.error(request, 'Please set a Punch ID — it identifies this waiter when several share the same branch.')
                return redirect('create_user')
            if UserProfile.objects.filter(role='waiter', branch=branch, punch_id__iexact=punch_id).exists():
                messages.error(request, f'{branch.name} already has a waiter with Punch ID "{punch_id}". Use a different one.')
                return redirect('create_user')
            if len(password) < 8:
                messages.error(request, 'Please set a password of at least 8 characters for this waiter account.')
                return redirect('create_user')

            base_username = f'waiter_{branch.code or branch.id}'.lower().replace(' ', '')
            username = base_username
            suffix = 1
            while User.objects.filter(username=username).exists():
                suffix += 1
                username = f'{base_username}_{suffix}'

            user = User.objects.create_user(username=username)
            user.set_password(password)  # hashed (PBKDF2) — never stored or compared as plain text
            user.save()
            UserProfile.objects.create(
                user=user, role='waiter', branch=branch,
                head_cashier_name=head_cashier_name, punch_id=punch_id,
            )
            log_activity(request, 'user_created', description=f'waiter "{head_cashier_name}" at {branch.name} ({username})')
            messages.success(
                request,
                f'Waiter account created for "{head_cashier_name}" at {branch.name}. '
                f'Username: {username}. Share the username and password with them securely — the password is not shown again.'
            )
            return redirect('create_user')

        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password or not role:
            messages.error(request, 'Please fill in username, password, and role.')
            return redirect('create_user')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'That username already exists.')
            return redirect('create_user')

        user = User.objects.create_user(username=username, password=password)
        UserProfile.objects.create(user=user, role=role)
        log_activity(request, 'user_created', description=f'{role} account: {username}')
        messages.success(request, f'User "{username}" created as {role}.')
        return redirect('create_user')

    branches_info = [
        {'id': b.id, 'name': b.name, 'code': b.code or '', 'id_suffix': str(b.id).zfill(2)[-2:]}
        for b in Branch.objects.all()
    ]

    users_list = list(User.objects.select_related('profile').order_by('username'))
    for u in users_list:
        profile = getattr(u, 'profile', None)
        if profile and profile.role == 'waiter' and profile.branch and profile.branch.code:
            key = f'login_attempts:branch:{profile.branch.code.lower()}'
        else:
            key = f'login_attempts:{u.username.lower()}'
        u.is_locked = _is_locked_out(key)

    context = {
        'branches': branches_info,
        'users': users_list,
        'pending_users': [u for u in users_list if getattr(getattr(u, 'profile', None), 'pending_approval', False)],
        'active_tab': 'users',
    }
    return render(request, 'salesapp/create_user.html', context)


@role_required('admin')
def add_branch_view(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        code = request.POST.get('code', '').strip()
        if not name:
            messages.error(request, 'Please enter a branch name.')
        elif Branch.objects.filter(name__iexact=name).exists():
            messages.error(request, 'That branch already exists.')
        elif code and Branch.objects.filter(code__iexact=code).exists():
            messages.error(request, 'That branch code is already used.')
        else:
            Branch.objects.create(name=name, code=code or None)
            log_activity(request, 'branch_created', description=f'{name} ({code or "-"})')
            messages.success(request, f'Branch "{name}" added.')
        return redirect('add_branch')

    context = {
        'branches': Branch.objects.all(),
        'active_tab': 'branches',
    }
    return render(request, 'salesapp/add_branch.html', context)


def _find_column(fieldnames, candidates):
    """Match a CSV header to one of several accepted spellings, so files
    exported with different column names (e.g. "Branch / Flat Name" instead
    of "name") still import correctly."""
    normalized = {(f or '').strip().lower(): f for f in fieldnames}
    for cand in candidates:
        if cand in normalized:
            return normalized[cand]
    for norm, original in normalized.items():
        for cand in candidates:
            if cand in norm:
                return original
    return None


NAME_COLUMN_CANDIDATES = ['name', 'branch', 'branch name', 'branch / flat name', 'flat name', 'branch/flat name']
CODE_COLUMN_CANDIDATES = ['code', 'branch code']


@role_required('admin')
def import_branches_view(request):
    if request.method != 'POST':
        return redirect('add_branch')

    upload = request.FILES.get('csv_file')
    if not upload:
        messages.error(request, 'Please choose a file.')
        return redirect('add_branch')

    filename = (upload.name or '').lower()
    rows = []

    if filename.endswith('.xlsx'):
        try:
            import openpyxl
        except ImportError:
            messages.error(
                request,
                'Reading .xlsx files needs the "openpyxl" package. '
                'Run: pip install openpyxl — or export the file as CSV instead.'
            )
            return redirect('add_branch')

        try:
            workbook = openpyxl.load_workbook(upload, read_only=True, data_only=True)
            worksheet = workbook.active
            rows_iter = worksheet.iter_rows(values_only=True)
            header = next(rows_iter)
        except StopIteration:
            messages.error(request, 'That Excel file appears to be empty.')
            return redirect('add_branch')
        except Exception:
            messages.error(request, 'Could not read that Excel file. Make sure it is a valid .xlsx workbook.')
            return redirect('add_branch')

        fieldnames = [str(h).strip() if h is not None else '' for h in header]
        for values in rows_iter:
            row = {fieldnames[i]: (values[i] if i < len(values) else None) for i in range(len(fieldnames))}
            rows.append(row)
    else:
        raw_bytes = upload.read()
        decoded = None
        for encoding in ('utf-8-sig', 'utf-16', 'cp1256', 'cp1252', 'latin-1'):
            try:
                decoded = raw_bytes.decode(encoding)
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
        if decoded is None:
            messages.error(request, 'Could not read the file — unrecognized text encoding. Try re-saving it as "CSV UTF-8" from Excel.')
            return redirect('add_branch')

        try:
            dialect = csv.Sniffer().sniff(decoded[:2048], delimiters=',\t;')
        except csv.Error:
            dialect = csv.excel  # comma-separated fallback

        reader = csv.DictReader(io.StringIO(decoded), dialect=dialect)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    name_col = _find_column(fieldnames, NAME_COLUMN_CANDIDATES)
    code_col = _find_column(fieldnames, CODE_COLUMN_CANDIDATES)

    if not name_col:
        messages.error(
            request,
            f'Could not find a branch-name column. Found columns: {", ".join(str(f) for f in fieldnames)}. '
            f'Expected something like "name" or "Branch / Flat Name".'
        )
        return redirect('add_branch')

    created, skipped = 0, 0
    for row in rows:
        name = str(row.get(name_col) or '').strip()
        code = str(row.get(code_col) or '').strip() if code_col else ''
        if not name:
            continue
        # Case-insensitive check (matches the manual "Add Branch" form's logic) —
        # avoids near-duplicate rows like "Kucu Ibri" vs "kucu ibri" from a
        # spreadsheet with inconsistent capitalization.
        if Branch.objects.filter(name__iexact=name).exists():
            skipped += 1
            continue
        Branch.objects.create(name=name, code=code or None)
        created += 1

    log_activity(request, 'branch_created', description=f'Bulk import: {created} added, {skipped} skipped')
    messages.success(request, f'Import finished: {created} branch(es) added, {skipped} already existed.')
    return redirect('add_branch')


@role_required('audit', 'manager', 'admin')
def daily_sales_report_view(request):
    """Daily Sales report: a card with the amount for every item, and under it
    one full table with every shift and every field.
    The cards (and the table's total row) count only COMPLETE shifts — Daily
    Sales items use shifts whose sales review is approved; Cash items use
    shifts whose cash reconciliation is approved. Shifts still waiting are
    listed in the table (greyed out) and join the totals the moment they complete."""
    from .models import _aed_cash_total_from_counts

    first_load = not request.GET
    today = timezone.localdate()
    date_from = request.GET.get('date_from', '').strip() if not first_load else today.replace(day=1).isoformat()
    date_to = request.GET.get('date_to', '').strip() if not first_load else today.isoformat()
    branch_id = request.GET.get('branch', '').strip()
    shift_filter = request.GET.getlist('shift')

    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False)
    if date_from:
        qs = qs.filter(date__gte=date_from)
    if date_to:
        qs = qs.filter(date__lte=date_to)
    if branch_id:
        qs = qs.filter(branch_id=branch_id)
    if shift_filter:
        qs = qs.filter(shift__in=shift_filter)
    entries = list(qs.order_by('-date', 'branch__name', 'shift'))

    zero = Decimal('0')

    def dec(v):
        return Decimal(str(v or 0))

    # (key, label, side) — the table columns, Daily Sales first, then Cash
    sales_cols = [('discount', 'Discount'), ('visa', 'Visa')]
    sales_cols += [(f'del_{k}', label) for k, label in DELIVERY_SOURCES]
    sales_cols += [('del_cancel', 'Delivery Cancelled'), ('del_net', 'Delivery (net)'),
                   ('orders', 'Delivery Orders'), ('sales_actual', 'Sales Actual'),
                   ('foodics', 'Foodics'), ('variance', 'Variance')]
    cash_cols = [('waiter_cash', 'Cash (waiter)'), ('cash_cancel', 'Cash Cancelled'), ('petty', 'Petty Cash'),
                 ('col_cash', 'Cash (collected)'), ('col_aed', 'AED Cash'), ('cash_diff', 'Cash Difference')]
    columns = [{'key': k, 'label': l, 'side': 'sales'} for k, l in sales_cols] + \
              [{'key': k, 'label': l, 'side': 'cash'} for k, l in cash_cols]

    totals = {c['key']: zero for c in columns}
    n_sales = n_cash = 0
    rows = []
    for e in entries:
        h = getattr(e, 'collector', None)
        sales_ok = e.is_audited
        cash_ok = h is not None and h.reconciled
        n_sales += 1 if sales_ok else 0
        n_cash += 1 if cash_ok else 0

        dl = e.delivery_data or {}
        vals = {
            'discount': e.staff_discount, 'visa': e.visa_total,
            'del_cancel': e.delivery_cancel_amount, 'del_net': e.delivery_total,
            'orders': sum(int((dl.get(k, {}) or {}).get('orders') or 0) for k, _ in DELIVERY_SOURCES),
            'sales_actual': e.sales_actual,
            'foodics': e.expected_foodics if sales_ok else None,
            'variance': e.variance if sales_ok else None,
            'waiter_cash': e.cash_total, 'cash_cancel': e.cash_cancel_amount, 'petty': e.petty_cash,
            'col_cash': h.cash_total if h is not None else None,
            'col_aed': (_aed_cash_total_from_counts(h.cash_counts_aed or {}) * dec(e.aed_exchange_rate)) if h is not None else None,
            'cash_diff': h.diff_from_waiter if h is not None else None,
        }
        for k, _ in DELIVERY_SOURCES:
            row = dl.get(k, {}) or {}
            vals[f'del_{k}'] = dec(row.get('amount')) - dec(row.get('cancel_amount'))

        cells = []
        for c in columns:
            counted = sales_ok if c['side'] == 'sales' else cash_ok
            v = vals[c['key']]
            if v is not None and counted:
                totals[c['key']] += dec(v)
            cells.append({'value': v, 'counted': counted, 'int': c['key'] == 'orders'})
        rows.append({
            'entry': e, 'sales_ok': sales_ok, 'cash_ok': cash_ok,
            'cash_state': 'reconciled' if cash_ok else ('collected' if h is not None else 'not collected'),
            'cells': cells,
        })

    cards = [
        {'title': 'Sales Actual', 'amount': totals['sales_actual'], 'shifts': n_sales,
         'hint': 'cash + visa − discount', 'pending': len(entries) - n_sales,
         'pending_text': 'waiting for sales review'},
        {'title': 'Cash', 'amount': totals['col_cash'], 'shifts': n_cash,
         'hint': 'as counted by the collector', 'pending': len(entries) - n_cash,
         'pending_text': 'waiting for cash reconciliation'},
    ]

    return render(request, 'salesapp/daily_sales_report.html', {
        'active_tab': 'daily_report',
        'cards': cards,
        'columns': columns,
        'sales_col_count': len(sales_cols),
        'cash_col_count': len(cash_cols),
        'rows': rows,
        'total_cells': [{'value': totals[c['key']], 'int': c['key'] == 'orders'} for c in columns],
        'entry_count': len(entries),
        'branches': Branch.objects.filter(is_active=True).order_by('name'),
        'shift_choices': SHIFT_CHOICES,
        'date_from': date_from,
        'date_to': date_to,
        'branch_id': branch_id,
        'shift_filter': shift_filter,
    })


@role_required('audit', 'admin')
def edit_entry_view(request, entry_id):
    entry = get_object_or_404(ShiftEntry, id=entry_id)

    if request.method == 'POST':
        entry.date = request.POST.get('date')
        entry.shift = request.POST.get('shift')
        entry.accountant = request.POST.get('accountant', '').strip()
        visa_rows = _apply_waiter_financials(request, entry)
        entry.expected_foodics = _dec(request.POST.get('expected_foodics'))
        entry.notes = request.POST.get('notes', '')
        if request.FILES.get('notes_attachment'):
            entry.notes_attachment = request.FILES['notes_attachment']

        entry.save()  # reference_id is untouched since it's already set
        _save_visa_files(entry, visa_rows)

        handover = getattr(entry, 'collector', None)
        if handover is not None:
            handover.save()  # re-derive the cash difference from the corrected waiter figures

        messages.success(request, f'Entry {entry.reference_id} updated.')
        log_activity(request, 'entry_edited', description=entry.reference_id)
        return redirect(_safe_next(request) or 'dashboard')

    context = {
        'entry': entry,
        'denoms': DENOMS,
        'aed_denoms': AED_DENOMS,
        'denom_pairs': list(zip(DENOMS, AED_DENOMS)),
        'delivery_sources': DELIVERY_SOURCES,
        'shift_choices': SHIFT_CHOICES,
        'active_tab': 'dashboard',
        'next_url': _safe_next(request),
        'selected_entry': entry,
    }
    return render(request, 'salesapp/edit_entry.html', context)


@role_required('admin')
def edit_branch_view(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        code = request.POST.get('code', '').strip()

        if not name:
            messages.error(request, 'Please enter a branch name.')
            return redirect('edit_branch', branch_id=branch.id)
        if Branch.objects.exclude(id=branch.id).filter(name__iexact=name).exists():
            messages.error(request, 'Another branch already uses that name.')
            return redirect('edit_branch', branch_id=branch.id)
        if code and Branch.objects.exclude(id=branch.id).filter(code__iexact=code).exists():
            messages.error(request, 'Another branch already uses that code.')
            return redirect('edit_branch', branch_id=branch.id)

        branch.name = name
        branch.code = code or None
        branch.save()
        log_activity(request, 'branch_edited', description=branch.name)
        messages.success(request, f'Branch "{branch.name}" updated.')
        return redirect('add_branch')

    context = {
        'branch': branch,
        'active_tab': 'branches',
    }
    return render(request, 'salesapp/edit_branch.html', context)


@role_required('admin')
@require_POST
def toggle_user_active_view(request, user_id):
    target = get_object_or_404(User, id=user_id)
    if target == request.user:
        messages.error(request, "You can't deactivate your own account.")
        return redirect('create_user')
    target.is_active = not target.is_active
    target.save()
    if target.is_active and getattr(target, 'profile', None) and target.profile.pending_approval:
        target.profile.pending_approval = False
        target.profile.save(update_fields=['pending_approval'])
    state = 'activated' if target.is_active else 'deactivated'
    log_activity(request, f'user_{state}', description=target.username)
    messages.success(request, f'{target.username} {state}.')
    return redirect('create_user')


@role_required('admin')
@require_POST
def delete_user_view(request, user_id):
    target = get_object_or_404(User, id=user_id)
    if target == request.user:
        messages.error(request, "You can't delete your own account.")
        return redirect('create_user')
    name = target.username
    target.delete()
    log_activity(request, 'user_deleted', description=name)
    messages.success(request, f'User "{name}" deleted.')
    return redirect('create_user')


@role_required('admin')
@require_POST
def toggle_branch_active_view(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)
    branch.is_active = not branch.is_active
    branch.save()
    state = 'activated' if branch.is_active else 'deactivated'
    log_activity(request, f'branch_{state}', description=branch.name)
    messages.success(request, f'{branch.name} {state}.')
    return redirect('add_branch')


@role_required('admin')
@require_POST
def delete_branch_view(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)
    if branch.shift_entries.exists():
        messages.error(
            request,
            f'Can\'t delete "{branch.name}" — it already has submitted shift entries. Deactivate it instead.'
        )
        return redirect('add_branch')
    name = branch.name
    branch.delete()
    log_activity(request, 'branch_deleted', description=name)
    messages.success(request, f'Branch "{name}" deleted.')
    return redirect('add_branch')


@role_required('admin')
def edit_user_view(request, user_id):
    target = get_object_or_404(User.objects.select_related('profile'), id=user_id)
    profile = target.profile

    if request.method == 'POST':
        if profile.role == 'waiter':
            head_cashier_name = request.POST.get('head_cashier_name', '').strip()
            punch_id = request.POST.get('punch_id', '').strip()
            branch_id = request.POST.get('branch')
            branch = Branch.objects.filter(id=branch_id).first() if branch_id else None
            new_password = request.POST.get('new_password', '')

            if not head_cashier_name or not branch:
                messages.error(request, 'Please fill in the head cashier name and select a branch.')
                return redirect('edit_user', user_id=target.id)
            if not punch_id:
                messages.error(request, 'Please set a Punch ID — it identifies this waiter when several share the same branch.')
                return redirect('edit_user', user_id=target.id)
            if UserProfile.objects.filter(role='waiter', branch=branch, punch_id__iexact=punch_id).exclude(id=profile.id).exists():
                messages.error(request, f'{branch.name} already has a different waiter with Punch ID "{punch_id}".')
                return redirect('edit_user', user_id=target.id)
            if new_password and len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters.')
                return redirect('edit_user', user_id=target.id)

            profile.head_cashier_name = head_cashier_name
            profile.punch_id = punch_id
            profile.branch = branch
            profile.save()
            if new_password:
                target.set_password(new_password)
                target.save()
        else:
            username = request.POST.get('username', '').strip()
            if not username:
                messages.error(request, 'Please enter a username.')
                return redirect('edit_user', user_id=target.id)
            if User.objects.exclude(id=target.id).filter(username=username).exists():
                messages.error(request, 'That username is already taken.')
                return redirect('edit_user', user_id=target.id)
            target.username = username

            new_password = request.POST.get('new_password', '')
            if new_password:
                target.set_password(new_password)
            target.save()

        messages.success(request, f'{profile.head_cashier_name or target.username} updated.')
        log_activity(request, 'user_edited', description=f'{profile.head_cashier_name or target.username}')
        return redirect('create_user')

    context = {
        'target': target,
        'profile': profile,
        'branches': Branch.objects.filter(is_active=True),
        'active_tab': 'users',
    }
    return render(request, 'salesapp/edit_user.html', context)


@role_required('admin')
@require_POST
def unlock_user_view(request, user_id):
    """Unlock one specific account directly from the Users page — figures
    out the right cache key itself (branch code for waiters, username for
    everyone else) instead of asking the admin to type an identifier."""
    target = get_object_or_404(User.objects.select_related('profile'), id=user_id)
    profile = getattr(target, 'profile', None)
    if profile and profile.role == 'waiter' and profile.branch and profile.branch.code:
        key = f'login_attempts:branch:{profile.branch.code.lower()}'
    else:
        key = f'login_attempts:{target.username.lower()}'
    cache.delete(key)
    log_activity(request, 'account_unlocked', description=target.username)
    messages.success(request, f'{target.username} has been unlocked.')
    return redirect('create_user')


@role_required('collector', 'audit', 'admin')
@require_POST
def archive_entry_view(request, entry_id):
    entry = get_object_or_404(ShiftEntry, id=entry_id)
    entry.is_archived = not entry.is_archived
    entry.save(update_fields=['is_archived'])
    state = 'archived' if entry.is_archived else 'unarchived'
    log_activity(request, f'entry_{state}', description=entry.reference_id)
    messages.success(request, f'{entry.reference_id} {state}.')
    referer = request.META.get('HTTP_REFERER')
    return redirect(referer or 'collector')


@role_required('collector', 'audit', 'admin')
def archive_history_view(request):
    """Shows archived (removed-from-view) entries, grouped by branch, with an Unarchive action."""
    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=True).order_by('-created_at')

    branch_filter = request.GET.get('branch_filter', '').strip()
    date_filter = request.GET.get('date_filter', '').strip()
    search_ref = request.GET.get('search_ref', '').strip()
    if branch_filter:
        qs = qs.filter(branch__name__icontains=branch_filter)
    if date_filter:
        qs = qs.filter(date=date_filter)
    if search_ref:
        qs = qs.filter(reference_id__icontains=search_ref)

    branch_groups_map = {}
    for e in qs:
        group = branch_groups_map.setdefault(e.branch_id, {'branch': e.branch, 'entries': []})
        group['entries'].append(e)
    branch_groups = sorted(branch_groups_map.values(), key=lambda g: g['branch'].name)

    context = {
        'branch_groups': branch_groups,
        'branch_filter': branch_filter,
        'date_filter': date_filter,
        'search_ref': search_ref,
        'active_tab': 'history',
    }
    return render(request, 'salesapp/archive_history.html', context)


@role_required('waiter')
def waiter_history_view(request):
    """Read-only history of a waiter's own branch shifts — no editing, no
    archive, no other branches. Just a reference list so they can check
    what they submitted before."""
    profile = request.user.profile
    branch = profile.branch

    qs = ShiftEntry.objects.select_related('collector').filter(branch=branch, is_archived=False).order_by('-date', '-created_at')

    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    if date_from:
        qs = qs.filter(date__gte=date_from)
    if date_to:
        qs = qs.filter(date__lte=date_to)

    rows = []
    previous_date = None
    date_group = -1
    tracked_actions = ['handover_saved', 'entry_audited', 'cash_reconciled', 'entry_edited']
    for e in qs:
        show_date_divider = (e.date != previous_date)
        if show_date_divider:
            date_group += 1
        history = list(
            ActivityLog.objects
            .filter(description=e.reference_id, action__in=tracked_actions)
            .order_by('created_at')
        )
        rows.append({
            'entry': e,
            'show_date_divider': show_date_divider,
            'date_group': date_group,
            'sales_status': 'reviewed' if e.is_audited else 'pending',
            'cash_status': (
                'not_collected' if getattr(e, 'collector', None) is None
                else 'reconciled' if e.collector.reconciled
                else 'collected'
            ),
            'history': history,
        })
        previous_date = e.date

    context = {
        'branch': branch,
        'rows': rows,
        'date_group_count': date_group + 1,
        'date_from': date_from,
        'date_to': date_to,
        'active_tab': 'waiter_history',
    }
    return render(request, 'salesapp/waiter_history.html', context)


@role_required('admin')
def audit_log_view(request):
    """Read-only activity trail for Admin/IT — who did what, when. Not to be
    confused with the 'Audit' role's shift-review notes; this is a
    system-level accountability log."""
    qs = ActivityLog.objects.select_related('user').all()

    action_filter = request.GET.get('action', '').strip()
    username_filter = request.GET.get('username', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    if action_filter:
        qs = qs.filter(action=action_filter)
    if username_filter:
        qs = qs.filter(username_snapshot__icontains=username_filter)
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    logs = list(qs[:300])  # most recent 300 matching entries — plenty for a review session

    context = {
        'logs': logs,
        'action_choices': ActivityLog.ACTION_CHOICES,
        'action_filter': action_filter,
        'username_filter': username_filter,
        'date_from': date_from,
        'date_to': date_to,
        'active_tab': 'audit_log',
    }
    return render(request, 'salesapp/audit_log.html', context)


def _mark_reconciled(request, handover, note=''):
    handover.reconciled = True
    handover.reconciled_at = timezone.now()
    handover.reconciled_by = request.user
    handover.reconcile_note = note
    handover.save(update_fields=['reconciled', 'reconciled_at', 'reconciled_by', 'reconcile_note'])
    details = (f'Waiter cash: {Decimal(str(handover.shift_entry.cash_total)):.3f} RO | '
               f'Collector cash: {Decimal(str(handover.cash_total)):.3f} RO | '
               f'Difference: {Decimal(str(handover.diff_from_waiter)):.3f} RO')
    if note:
        details += f'\nNote: "{note}"'
    log_activity(request, 'cash_reconciled', description=handover.shift_entry.reference_id, details=details)


@role_required('audit', 'admin')
def cash_reconciliation_view(request):
    """Retired as a separate page — Cash Reconciliation is now part of the
    single Audit workspace. Kept only so an old bookmark still lands somewhere."""
    entry_id = request.GET.get('entry_id', '')
    return redirect(f'/dashboard/?entry_id={entry_id}' if entry_id else '/dashboard/')


@role_required('audit', 'admin')
@require_POST
def cash_reconcile_action_view(request):
    action = request.POST.get('action')
    handovers = list(
        CollectorHandover.objects.select_related('shift_entry')
        .filter(id__in=request.POST.getlist('handover_id'), reconciled=False)
    )

    if action == 'approve_matched':
        approved = 0
        for h in handovers:
            # Re-checked here: a shift with a difference is never bulk-approved.
            if not h.has_difference(CASH_TOLERANCE):
                _mark_reconciled(request, h)
                approved += 1
        skipped = len(handovers) - approved
        if approved:
            messages.success(request, f'{approved} shift(s) reconciled.')
        if skipped:
            messages.error(request, f'{skipped} shift(s) have a cash difference and need their own note.')
    elif action == 'approve_one':
        note = request.POST.get('note', '').strip()
        if not handovers:
            messages.error(request, 'That shift was already reconciled or no longer exists.')
        elif handovers[0].has_difference(CASH_TOLERANCE) and not note:
            messages.error(request, 'Please write a note explaining the difference before approving.')
        else:
            _mark_reconciled(request, handovers[0], note)
            messages.success(request, f'{handovers[0].shift_entry.reference_id} reconciled.')
    else:
        messages.error(request, 'Unknown action.')

    return redirect(request.META.get('HTTP_REFERER') or 'cash_reconciliation')
