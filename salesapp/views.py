import re
import unicodedata
import csv
import datetime
import io
from urllib.parse import urlencode, quote
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.core.cache import cache
from django.template.defaultfilters import date as date_filter
from django.views.decorators.cache import never_cache
from django.core.exceptions import PermissionDenied
from django.db.models import Sum, Q
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme

from django.views.decorators.http import require_POST
from .constants import DENOMS, AED_DENOMS, DELIVERY_SOURCES, SHIFT_CHOICES
from .decorators import role_required
from .models import Branch, ShiftEntry, CollectorHandover, UserProfile, VisaMachineFile, NotesFile, ActivityLog, DayClose, _fmt12


def login_view(request):
    if request.user.is_authenticated:
        return _redirect_after_login(request, request.user)
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
        return _redirect_after_login(request, user)
    return render(request, 'salesapp/login.html')


def branch_login_view(request):
    """Login for branch waiters: branch code + Punch ID (identifies *which*
    waiter at that branch — a branch can now have several, one per shift) +
    a real password (hashed, not a raw 2-digit guess). Repeated failures are
    rate-limited below."""
    if request.user.is_authenticated:
        return _redirect_after_login(request, request.user)
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

        profile = _find_waiter_by_punch(branch, punch_id)
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
        return _redirect_after_login(request, request.user)

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
        elif _find_waiter_by_punch(branch, form['punch_id']):
            error = f'{branch.name} already has someone registered with this Punch ID ("{_find_waiter_by_punch(branch, form["punch_id"]).punch_id}"). Check your Punch ID, or ask your admin.'
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


def _clean_number(value):
    """Typed amounts may carry commas, spaces, Arabic digits or Arabic separators."""
    t = str(value).strip()
    t = t.translate({ord(c): str(i) for i, c in enumerate('٠١٢٣٤٥٦٧٨٩')})
    t = t.translate({ord(c): str(i) for i, c in enumerate('۰۱۲۳۴۵۶۷۸۹')})
    t = re.sub(r"[\s\u00A0\u066C']", '', t).replace('\u066B', ',').replace('،', ',')
    if ',' in t:
        if re.fullmatch(r'[1-9]\d{0,2}(,\d{3})+(\.\d+)?', t):
            t = t.replace(',', '')            # 1,234 -> thousands separator
        elif t.count(',') == 1 and '.' not in t:
            t = t.replace(',', '.')           # 0,500 / 1,5 -> decimal comma
        else:
            t = t.replace(',', '')
    return t


def _dec(value, default='0'):
    try:
        if value in (None, ''):
            return Decimal(default)
        return Decimal(_clean_number(value))
    except InvalidOperation:
        return Decimal(default)


def _int(value, default=0):
    try:
        if value in (None, ''):
            return default
        return int(Decimal(_clean_number(value)))
    except (InvalidOperation, ValueError):
        return default


def _redirect_after_login(request, user):
    """Like _redirect_for_role, but an account with no role (profile) can never bounce
    between the login page and itself: a superuser goes to /admin/, anyone else is logged
    out with a message."""
    if getattr(user, 'profile', None) is None:
        if user.is_superuser:
            return redirect('/admin/')
        logout(request)
        messages.error(request, 'This account has no role assigned yet. Please ask an admin to set it up.')
        return redirect('staff_login')
    return _redirect_for_role(user)


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
    if profile.role == 'sales_manager':
        return redirect('collector')
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


_NOTE_FILE_EXT = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif', '.bmp')


def _save_notes_files(entry, request):
    for f in request.FILES.getlist('notes_files'):
        NotesFile.objects.create(entry=entry, file=f)


def _notes_files_ok(request):
    files = request.FILES.getlist('notes_files')
    return bool(files) and all(f.name.lower().endswith(_NOTE_FILE_EXT) for f in files)


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
        'discount_entries': list(entry.discount_entries or []),
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
        old_rows = [Decimal(str(r.get('amount') or 0)) for r in (snap.get('discount_entries') or [])]
        new_rows = [Decimal(str(r.get('amount') or 0)) for r in (entry.discount_entries or [])]
        for i in range(max(len(old_rows), len(new_rows))):
            o = old_rows[i] if i < len(old_rows) else None
            n = new_rows[i] if i < len(new_rows) else None
            if o is None:
                lines.append(f'Discount #{i + 1}: added {n:.3f}')
            elif n is None:
                lines.append(f'Discount #{i + 1}: removed (was {o:.3f})')
            elif o != n:
                lines.append(f'Discount #{i + 1}: {o:.3f} → {n:.3f}')
        lines.append('Discount total: ' + diffs['staff_discount'].replace('Changed from ', '').replace(' to ', ' → '))
    if 'visa_total' in diffs:
        old_v = {str(x.get('serial', '')): Decimal(str(x.get('amount') or 0)) for x in (snap.get('visa_entries') or [])}
        new_v = {str(x.get('serial', '')): Decimal(str(x.get('amount') or 0)) for x in (entry.visa_entries or [])}
        for s in list(old_v) + [k for k in new_v if k not in old_v]:
            if s not in old_v:
                lines.append(f'Visa machine {s}: added {new_v[s]:.3f}')
            elif s not in new_v:
                lines.append(f'Visa machine {s}: removed (was {old_v[s]:.3f})')
            elif old_v[s] != new_v[s]:
                lines.append(f'Visa machine {s}: {old_v[s]:.3f} → {new_v[s]:.3f}')
        lines.append('Visa total: ' + diffs['visa_total'].replace('Changed from ', '').replace(' to ', ' → '))
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


def _parse_discount_rows(request):
    """Discount rows (Order Number + Amount) from a POST. Empty rows are dropped.
    Returns None when the form sent no rows at all (an older form that only
    sends one total), so the caller can fall back to that total."""
    if 'discount_row_amount[]' not in request.POST and 'discount_order[]' not in request.POST:
        return None
    orders = request.POST.getlist('discount_order[]')
    amounts = request.POST.getlist('discount_row_amount[]')
    rows = []
    for i, raw in enumerate(amounts):
        amount = _dec(raw)
        order = (orders[i] if i < len(orders) else '').strip()
        if amount or order:
            rows.append({'order_no': order, 'amount': f'{amount:.3f}'})
    return rows


def _apply_waiter_financials(request, entry):
    """Applies the cash/visa/delivery/discount fields from a POST to an entry.
    Shared by the waiter's own edit page and by Audit's inline correction on
    the Sales Review card, so a fix made in either place saves the same way."""
    rows = _parse_discount_rows(request)
    if rows is None:
        entry.discount_entries = []
        entry.staff_discount = _dec(request.POST.get('staff_discount'))
    else:
        entry.discount_entries = rows
        entry.staff_discount = sum((Decimal(r['amount']) for r in rows), Decimal('0'))
    # The waiter's cash numbers are view-only for Audit: only the waiter
    # (or admin) can change them. Audit corrects the collector's section instead.
    _role = getattr(getattr(request.user, 'profile', None), 'role', None)
    if _role != 'audit':
        entry.petty_cash = _dec(request.POST.get('petty_cash'))
        entry.cash_counts = {d: _int(request.POST.get(f'denom_{d}', 0)) for d in DENOMS}
        entry.cash_counts_aed = {d: _int(request.POST.get(f'denom_aed_{d}', 0)) for d in AED_DENOMS}
        entry.aed_exchange_rate = _dec(request.POST.get('aed_exchange_rate'), default='0.1000')
        entry.cash_cancel_amount = _dec(request.POST.get('cash_cancel_amount'))
        entry.cash_cancel_order = request.POST.get('cash_cancel_order', '').strip()[:200]

    visa_rows = _parse_visa_rows(request)
    entry.visa_entries = [{'serial': r['serial'], 'amount': float(r['amount'])} for r in visa_rows]

    delivery_data = {}
    for key, _label in DELIVERY_SOURCES:
        delivery_data[key] = {
            'orders': _int(request.POST.get(f'orders_{key}', 0)),
            'amount': float(_dec(request.POST.get(f'amount_{key}', 0))),
            'cancel_orders': _int(request.POST.get(f'cancel_orders_{key}', 0)),
            'cancel_amount': float(_dec(request.POST.get(f'cancel_amount_{key}', 0))),
        }
    entry.delivery_data = delivery_data

    if request.FILES.get('discount_attachment'):
        entry.staff_discount_attachment = request.FILES['discount_attachment']
    if request.FILES.get('cash_cancel_attachment') and _role != 'audit':
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


def _visa_urls(entry):
    """{serial: receipt url} so the edit forms can link the receipt already on file."""
    return {vf.serial: vf.file.url for vf in entry.visa_files.all() if vf.file}


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

        submitted_late = False
        if profile.role == 'waiter':
            now = timezone.now()
            date = branch.business_date(now)  # server-side truth (the branch's business day) — never trust a client-submitted date for waiters
            if not branch.in_business_hours(now):
                # closed right now: no submissions at all (the form also blocks this, but the server decides)
                messages.error(request, f"Your branch is closed right now (opens {branch.open_label}, closes {branch.close_label}), so a report cannot be submitted. Please submit during opening hours.")
                return redirect('entry')
        else:
            date = request.POST.get('date')

        shift = request.POST.get('shift')
        accountant = profile.head_cashier_name if profile.role == 'waiter' else request.POST.get('accountant', '').strip()

        if not date:
            messages.error(request, 'Please fill in branch and date.')
            return redirect('entry')

        if shift not in dict(SHIFT_CHOICES):
            messages.error(request, 'Please choose the shift (1, 2 or 3).')
            return redirect('entry')
        _n_shifts = max(int(branch.shifts_per_day or 1), 1)
        if int(shift) > _n_shifts:
            messages.error(request, f'This branch works {_n_shifts} shift(s) per day (Settings), so shift {shift} cannot be submitted.')
            return redirect('entry')
        # A day that is already closed, or a shift that was already submitted: the waiter's
        # submission is not rejected — it is sent to Audit as a request (kept archived, so it
        # counts nowhere) and Audit approves or rejects it.
        request_reason = ''
        if DayClose.objects.filter(branch=branch, date=date).exists():
            request_reason = 'Day already closed'
        elif ShiftEntry.objects.filter(branch=branch, date=date, shift=shift, is_archived=False).exists():
            request_reason = 'Shift already submitted'
        if request_reason and ShiftEntry.objects.filter(branch=branch, date=date, shift=shift, request_status='pending').exists():
            messages.error(request, f'A request for shift {shift} on {date} is already waiting for Audit. Please wait for their decision.')
            return redirect('entry')

        cash_counts = {d: _int(request.POST.get(f'denom_{d}', 0)) for d in DENOMS}
        cash_counts_aed = {d: _int(request.POST.get(f'denom_aed_{d}', 0)) for d in AED_DENOMS}
        aed_exchange_rate = _dec(request.POST.get('aed_exchange_rate'), default='0.1000')

        visa_rows = _parse_visa_rows(request)
        visa_entries = [{'serial': r['serial'], 'amount': float(r['amount'])} for r in visa_rows]

        delivery_data = {}
        for key, _label in DELIVERY_SOURCES:
            delivery_data[key] = {
                'orders': _int(request.POST.get(f'orders_{key}', 0)),
                'amount': float(_dec(request.POST.get(f'amount_{key}', 0))),
                'cancel_orders': _int(request.POST.get(f'cancel_orders_{key}', 0)),
                'cancel_amount': float(_dec(request.POST.get(f'cancel_amount_{key}', 0))),
            }

        # A receipt photo/PDF is mandatory whenever a cash cancellation or a discount is entered.
        _disc_rows = _parse_discount_rows(request) or []
        _disc_total = sum((Decimal(str(r['amount'])) for r in _disc_rows), Decimal('0')) or _dec(request.POST.get('discount_amount'))
        _cancel_filled = _dec(request.POST.get('cash_cancel_amount')) > 0 or bool(request.POST.get('cash_cancel_order', '').strip())
        if _cancel_filled and not request.FILES.get('cash_cancel_attachment'):
            messages.error(request, 'Please attach the receipt photo for the cash cancellation.')
            return redirect('entry')
        if _disc_total > 0 and not request.FILES.get('discount_attachment'):
            messages.error(request, 'Please attach the receipt photo for the discount.')
            return redirect('entry')
        for _vr in visa_rows:
            if _vr['amount'] > 0 and not _vr['file']:
                messages.error(request, f'Please attach the receipt photo for visa machine {_vr["serial"] or "(no serial)"}: an amount was entered.')
                return redirect('entry')

        if not _notes_files_ok(request):
            messages.error(request, 'Please upload Close Till Foodics (photo, several photos, or a PDF).')
            return redirect('entry')

        entry = ShiftEntry(
            branch=branch,
            date=date,
            shift=shift,
            accountant=accountant,
            submitted_punch=(profile.punch_id or '') if profile.role == 'waiter' else '',
            submitted_late=submitted_late,
            petty_cash=_dec(request.POST.get('petty_cash')),
            staff_discount=_dec(request.POST.get('discount_amount')),
            discount_entries=_parse_discount_rows(request) or [],
            cash_counts=cash_counts,
            cash_counts_aed=cash_counts_aed,
            aed_exchange_rate=aed_exchange_rate,
            visa_entries=visa_entries,
            cash_cancel_amount=_dec(request.POST.get('cash_cancel_amount')),
            cash_cancel_order=request.POST.get('cash_cancel_order', '').strip()[:200],
            delivery_data=delivery_data,
            notes=request.POST.get('notes', ''),
            # expected_foodics is set later by Audit, not by the waiter.
            is_archived=bool(request_reason),
            request_status='pending' if request_reason else '',
            request_reason=request_reason,
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
        _save_notes_files(entry, request)

        if request_reason:
            messages.warning(request, f'Shift {shift} for {date} is not open for submission ({request_reason.lower()}), so your submission ({entry.reference_id}) was sent to Audit for review. You will see its status in History.')
            return redirect('entry')
        return redirect(f"/?submitted={entry.reference_id}")

    context = {
        'denoms': DENOMS,
        'aed_denoms': AED_DENOMS,
        'denom_pairs': list(zip(DENOMS, AED_DENOMS)),
        'delivery_sources': DELIVERY_SOURCES,
        'shift_choices': [c for c in SHIFT_CHOICES if not locked_branch or int(c[0]) <= max(int(locked_branch.shifts_per_day or 1), 1)],
        'active_tab': 'entry',
        'locked_branch': locked_branch,
        'done_shifts': (set(ShiftEntry.objects.filter(branch=locked_branch, date=profile.branch.business_date(), is_archived=False).values_list('shift', flat=True)) if (locked_branch and profile.role == 'waiter') else set()),
        'head_cashier_name': profile.head_cashier_name if profile.role == 'waiter' else None,
        'today': (profile.branch.business_date() if profile.branch else timezone.localdate()) if profile.role == 'waiter' else None,
        'punch_id': (profile.punch_id or '') if profile.role == 'waiter' else '',
        'branch_hours': ({'open': profile.branch.open_label, 'close': profile.branch.close_label, 'next_day': profile.branch.closes_next_day}
                         if (profile.role == 'waiter' and profile.branch and profile.branch.has_custom_hours) else None),
        'outside_hours': bool(profile.role == 'waiter' and profile.branch and not profile.branch.in_business_hours()),
        'submitted_ref': request.GET.get('submitted'),
        'submitted_branch': locked_branch.name if locked_branch else None,
    }
    return render(request, 'salesapp/entry.html', context)


def _collector_day_rows(entry):
    """The shifts of the opened shift's branch/day, as the collector's approval card shows them."""
    branch = entry.branch
    entries = list(ShiftEntry.objects.filter(branch=branch, date=entry.date, is_archived=False)
                   .select_related('collector').order_by('shift'))
    by_shift = {}
    for e in entries:
        by_shift.setdefault(str(e.shift), e)
    wanted = [str(n) for n in range(1, max(int(branch.shifts_per_day or 1), 1) + 1)]
    rows = []
    for sh in wanted + sorted(k for k in by_shift if k not in wanted):
        e = by_shift.get(sh)
        counted = bool(e is not None and getattr(e, 'collector', None) is not None)
        # Approved only once the handover is really saved (a bare flag from an older build does not count).
        rows.append({'shift': sh, 'entry': e,
                     'state': 'missing' if e is None else ('approved' if (e.collector_approved and counted) else 'waiting'),
                     'counted': counted})
    waiting = [r['entry'] for r in rows if r['state'] == 'waiting']
    return {'branch': branch, 'date': entry.date, 'rows': rows, 'waiting': waiting,
            'shifts_per_day': len(wanted),
            'needs_proof': any(r['state'] == 'waiting' and not r['counted'] for r in rows),
            'total_cash': sum((e.final_cash_total for e in entries), Decimal('0')),
            'approved_n': sum(1 for r in rows if r['state'] == 'approved')}


def _collector_approve(request):
    """'Approve all shifts' on the collector's day card = Save Handover for the whole day: every
    shift of the day that has no collector count yet is saved as collected, with the waiter's
    cash counts as they are (the collector confirms they are correct), the one cash-proof photo
    and the note. A shift he already counted himself keeps his own count and is just marked
    approved. Each shift then moves on to Audit's cash reconciliation."""
    if request.user.profile.role not in ('collector', 'admin'):
        raise PermissionDenied('Only the collector can approve shifts here.')
    entry = get_object_or_404(ShiftEntry, id=request.POST.get('shift_entry_id'), is_archived=False)
    back = redirect(_safe_next(request) or _reopen_url(request, '/collector/', entry.id))
    note = (request.POST.get('approve_note') or '').strip()
    targets = list(ShiftEntry.objects.filter(branch=entry.branch, date=entry.date, is_archived=False)
                   .filter(Q(collector_approved=False) | Q(collector__isnull=True))
                   .select_related('collector').order_by('shift'))
    if not targets:
        messages.info(request, 'Nothing to approve: every shift of this day is already approved.')
        return back
    needs_count = [e for e in targets if getattr(e, 'collector', None) is None]
    proof = request.FILES.get('proof_attachment')
    proof_bytes = None
    if proof:
        ext = proof.name.rsplit('.', 1)[-1].lower() if '.' in proof.name else ''
        if ext not in ('jpg', 'jpeg', 'png', 'webp', 'heic', 'pdf') or proof.size > 10 * 1024 * 1024:
            messages.error(request, 'Cash proof must be a photo (JPG/PNG/WEBP/HEIC) or PDF, up to 10 MB.')
            return back
        proof_bytes = proof.read()
    elif needs_count:
        messages.error(request, 'Please attach the photo of the cash invoice (Cash Proof) before approving.')
        return back
    from django.core.files.base import ContentFile
    name = (request.user.get_full_name() or request.user.username)
    now = timezone.now()
    done_new, done_old = [], []
    for e in targets:
        h = getattr(e, 'collector', None)
        if h is None:
            h = CollectorHandover(shift_entry=e, collector_name=name, cash_counts=dict(e.cash_counts),
                                  cash_counts_aed=dict(e.cash_counts_aed), notes=note)
            h.proof_attachment.save(proof.name, ContentFile(proof_bytes), save=False)
            h.save()
            e = h.shift_entry
            total = f'{Decimal(str(h.cash_total)):.3f}'
            details = f'Approved by the collector ("Approve Handover"): {total} RO, same as the waiter\'s count'
            if note:
                details += f'\nNote: "{note}"'
            log_activity(request, 'handover_saved', description=e.reference_id, details=details + '\nCash proof photo attached')
            done_new.append(e)
        else:
            details = 'Approved by the collector ("Approve Handover"); his own count kept'
            if note:
                details += f'\nNote: "{note}"'
            log_activity(request, 'collector_approved', description=e.reference_id, details=details)
            done_old.append(e)
        e.collector_approved = True
        e.collector_approved_at = now
        e.collector_approved_by = request.user
        if note:
            e.collector_note = note
        e.save(update_fields=['collector_approved', 'collector_approved_at', 'collector_approved_by', 'collector_note'])
    refs = ', '.join(e.reference_id for e in done_new + done_old)
    messages.success(request, f'Approved {len(targets)} shift(s) and saved as collected: {refs}.')
    return back


@role_required('collector', 'audit', 'sales_manager', 'admin')
def collector_view(request):
    is_viewer = request.user.profile.role == 'sales_manager'   # the Sales Department Manager only looks
    if request.method == 'POST':
        if is_viewer:
            raise PermissionDenied('This account can only view the collector page.')
        if request.POST.get('action') == 'collector_approve_all':
            return _collector_approve(request)
        entry_id = request.POST.get('shift_entry_id')
        shift_entry = get_object_or_404(ShiftEntry, id=entry_id)

        cash_counts = {d: _int(request.POST.get(f'cdenom_{d}', 0)) for d in DENOMS}
        cash_counts_aed = {d: _int(request.POST.get(f'cdenom_aed_{d}', 0)) for d in AED_DENOMS}

        handover = CollectorHandover.objects.filter(shift_entry=shift_entry).first()
        is_new = handover is None
        by_audit_role = request.user.profile.role == 'audit'
        if by_audit_role and is_new:
            # Audit can correct the collector's numbers only AFTER the collector has saved them.
            messages.error(request, "The collector has not saved this shift's cash yet — Audit can correct his numbers only after he does.")
            return redirect(_safe_next(request) or _reopen_url(request, '/collector/', entry_id))
        # Cash proof: photo of the invoice / receipt. The collector must attach it with the
        # first count; Audit corrections keep the existing photo unless a new one is sent.
        proof = request.FILES.get('proof_attachment')
        if proof:
            ext = proof.name.rsplit('.', 1)[-1].lower() if '.' in proof.name else ''
            if ext not in ('jpg', 'jpeg', 'png', 'webp', 'heic', 'pdf') or proof.size > 10 * 1024 * 1024:
                messages.error(request, 'Cash proof must be a photo (JPG/PNG/WEBP/HEIC) or PDF, up to 10 MB.')
                return redirect(_safe_next(request) or _reopen_url(request, '/collector/', entry_id))
        elif request.user.profile.role == 'collector' and not (handover and handover.proof_attachment):
            messages.error(request, 'Please attach the photo of the cash invoice (Cash Proof) before saving.')
            return redirect(_safe_next(request) or _reopen_url(request, '/collector/', entry_id))
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
        if not by_audit_role:   # the collector's note stays his — Audit writes its own Audit Note
            handover.notes = request.POST.get('notes', '')
        if proof:
            handover.proof_attachment = proof
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
        if proof:
            details += '\nCash proof photo attached'
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
    selected_branches = _read_branch_filter(request)
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    all_entries_qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False).order_by('-created_at')
    if shift_filter:
        all_entries_qs = all_entries_qs.filter(shift__in=shift_filter)
    all_entries_qs = _apply_branch_filter(all_entries_qs, selected_branches)
    if date_from:
        all_entries_qs = all_entries_qs.filter(date__gte=date_from)
    if date_to:
        all_entries_qs = all_entries_qs.filter(date__lte=date_to)
    if search_ref:
        all_entries_qs = all_entries_qs.filter(reference_id__icontains=search_ref)
    selected_collected = _read_collected(request)
    collected_ctx = _collected_context(all_entries_qs, selected_collected)
    all_entries_qs = _apply_collected(all_entries_qs, selected_collected)

    group_summary = None
    if selected_branches and (date_from or date_to) and all_entries_qs.exists():
        agg = {'total_cash': sum((e.final_cash_total for e in all_entries_qs.select_related('collector')), Decimal('0'))}
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
        group['total_cash'] += e.final_cash_total
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
    collector_day = _collector_day_rows(selected_entry) if selected_entry and not selected_entry.is_archived else None

    context = {
        **cash_subtotals,
        'collector_day': collector_day,
        'can_approve': request.user.profile.role in ('collector', 'admin'),
        'all_entries': all_entries_qs,
        'branch_groups': branch_groups,
        'shift_filter': shift_filter,
        **_branch_picker_context(selected_branches),
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
        **collected_ctx,
        'is_viewer': is_viewer,
        'active_tab': 'collector',
    }
    return render(request, 'salesapp/collector.html', context)


def _approve_all(request, entry):
    """Approve every shift of this branch/day that is still waiting for sales review, in one
    go. No numbers are changed (a figure that needs fixing is still corrected on its own
    shift). The optional note is saved as the Audit note of each shift it approves."""
    note = request.POST.get('all_note', '').strip()
    waiting = list(ShiftEntry.objects.filter(branch=entry.branch, date=entry.date, is_archived=False, is_audited=False).order_by('shift'))
    if not waiting:
        messages.info(request, 'Every shift of this day is already approved.')
        return redirect(_reopen_url(request, '/dashboard/', entry.id))
    for e in waiting:
        if not e.original_snapshot:
            e.original_snapshot = _shift_snapshot(e)   # legacy shift: baseline = how it stood before
        lines = ['Approved with "Approve all shifts". No numbers changed.']
        if note:
            if e.audit_notes and note not in e.audit_notes:
                e.audit_notes = f'{e.audit_notes}\n{note}'
            elif not e.audit_notes:
                e.audit_notes = note
            lines.append(f'Note: "{note}"')
        e.is_audited = True
        e.save()
        log_activity(request, 'entry_audited', description=e.reference_id, details='\n'.join(lines))
    refs = ', '.join(e.reference_id for e in waiting)
    messages.success(request, f'Approved {len(waiting)} shift(s): {refs}.')
    return redirect(_reopen_url(request, '/dashboard/', entry.id))


def _decide_request(request, entry):
    """Audit's decision on a waiter's request (a shift sent for a closed day or for a shift
    that was already submitted). Approve: the shift goes live (replacing any live shift with
    the same number, which is archived). Reject: it stays archived."""
    if entry.request_status != 'pending':
        messages.error(request, 'This request was already decided.')
        return redirect(f'/dashboard/?entry_id={entry.id}')
    decision = request.POST.get('decision')
    if decision == 'approve':
        replaced = list(ShiftEntry.objects.filter(branch=entry.branch, date=entry.date, shift=entry.shift, is_archived=False).exclude(pk=entry.pk))
        for old in replaced:
            old.is_archived = True
            old.save(update_fields=['is_archived'])
        entry.is_archived = False
        entry.request_status = 'approved'
        entry.is_audited = False   # it still needs the normal Audit review (and a re-close of the day)
        entry.save()
        note = f' replacing {", ".join(o.reference_id for o in replaced)}' if replaced else ''
        log_activity(request, 'entry_unarchived', description=entry.reference_id,
                     details=f'Waiter request approved ({entry.request_reason}){note}')
        messages.success(request, f'Request {entry.reference_id} approved{note}. Review the shift again and re-close the day.')
    elif decision == 'reject':
        entry.request_status = 'rejected'
        entry.save(update_fields=['request_status'])
        log_activity(request, 'entry_archived', description=entry.reference_id,
                     details=f'Waiter request rejected ({entry.request_reason})')
        messages.success(request, f'Request {entry.reference_id} rejected.')
    else:
        messages.error(request, 'Please choose approve or reject.')
    return redirect(f'/dashboard/?entry_id={entry.id}')


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
        if request.POST.get('action') == 'close_day':
            return _close_day(request, entry)
        if request.POST.get('action') == 'request_decision':
            return _decide_request(request, entry)
        if request.POST.get('action') == 'approve_all':
            return _approve_all(request, entry)
        if entry.request_status == 'pending':
            messages.error(request, 'This is a waiter request. Approve or reject it first.')
            return redirect(f'/dashboard/?entry_id={entry.id}')
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
        if (entry.date, entry.shift) != (old_date, old_shift) and ShiftEntry.objects.filter(branch=entry.branch, date=entry.date, shift=entry.shift, is_archived=False).exclude(pk=entry.pk).exists():
            messages.error(request, f'Shift {entry.shift} already exists for {entry.branch.name} on {entry.date}.')
            return redirect('edit_entry', entry_id=entry.id)
        entry.accountant = request.POST.get('accountant', '').strip()
        if entry.accountant != old_accountant:
            entry.submitted_punch = _punch_for(entry.branch, entry.accountant)   # a different name -> its own Punch ID (or none)
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

    day_status = day_history = None
    day_flagged = False
    if selected_entry:
        day_status = _day_status(selected_entry.branch, selected_entry.date)
        day_history = list(ActivityLog.objects.filter(
            action='day_closed', description=f'{selected_entry.branch.name} {selected_entry.date}'
        ).order_by('-created_at'))
        if day_status['day'] is not None:
            day_flagged = abs(day_status['day'].variance) > threshold

    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False)

    shift_filter = request.GET.getlist('shift_filter')
    selected_branches = _read_branch_filter(request)
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    search_ref = request.GET.get('search_ref', '').strip()
    if shift_filter:
        qs = qs.filter(shift__in=shift_filter)
    qs = _apply_branch_filter(qs, selected_branches)
    if date_from:
        qs = qs.filter(date__gte=date_from)
    if date_to:
        qs = qs.filter(date__lte=date_to)
    if search_ref:
        qs = qs.filter(reference_id__icontains=search_ref)
    qs = qs.order_by('-created_at')

    # where every shift is in its life; the Stage filter is applied after counting, so each
    # pill shows how many shifts sit in that stage under the OTHER filters
    staged = [(e, _entry_stage(e)) for e in qs]
    stage_counts = {value: 0 for value, _ in ENTRY_STAGES}
    for _, st in staged:
        stage_counts[st] += 1
    valid_stages = {value for value, _ in ENTRY_STAGES}
    selected_stages = [v for v in request.GET.getlist('stage') if v in valid_stages]
    if selected_stages:
        staged = [(e, st) for e, st in staged if st in selected_stages]

    day_closes = {(d.branch_id, d.date): d for d in DayClose.objects.filter(
        branch_id__in={e.branch_id for e, _ in staged}, date__in={e.date for e, _ in staged})}
    last_shift = {}
    for e, _ in staged:
        k = (e.branch_id, e.date)
        if k not in last_shift or int(e.shift) > int(last_shift[k]):
            last_shift[k] = e.shift

    branch_groups_map = {}
    for e, stage in staged:
        k = (e.branch_id, e.date)
        # the day's Foodics / variance sit on the day's last shift row (one figure per day)
        day = day_closes.get(k) if str(last_shift[k]) == str(e.shift) else None
        has_issue = bool(day) and abs(day.variance) > threshold

        group = branch_groups_map.setdefault(e.branch_id, {
            'branch': e.branch,
            'rows': [],
            'total_variance': Decimal('0'),
            'total_actual': Decimal('0'),
        })
        group['rows'].append({'entry': e, 'stage': stage, 'has_issue': has_issue, 'day': day,
                              'day_variance': day.variance if day else None})
        if day:
            group['total_variance'] += day.variance
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
        'day_status': day_status,
        'day_history': day_history,
        'day_flagged': day_flagged,
        'pending_requests': list(ShiftEntry.objects.select_related('branch').filter(request_status='pending').order_by('created_at')),
        'branch_groups': branch_groups,
        'shift_filter': shift_filter,
        'shift_choices': SHIFT_CHOICES,
        **_branch_picker_context(selected_branches),
        'stage_options': [(value, label, stage_counts[value]) for value, label in ENTRY_STAGES],
        'selected_stages': selected_stages,
        'stage_qs': ''.join(f'stage={v}&' for v in selected_stages),
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
        'visa_urls': _visa_urls(selected_entry) if selected_entry else {},
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
            _dup = _find_waiter_by_punch(branch, punch_id)
            if _dup:
                messages.error(request, f'{branch.name} already has a waiter with this Punch ID ("{_dup.punch_id}", {_dup.head_cashier_name}). Use a different one.')
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
        name = _clean_branch_name(request.POST.get('name', ''))
        code = request.POST.get('code', '').strip()
        _names = {_norm_branch_name(n) for n in Branch.objects.values_list('name', flat=True)}
        _codes = {_norm_branch_code(c) for c in Branch.objects.exclude(code__isnull=True).values_list('code', flat=True)}
        if not name:
            messages.error(request, 'Please enter a branch name.')
        elif _norm_branch_name(name) in _names:
            messages.error(request, 'That branch already exists.')
        elif code and _norm_branch_code(code) in _codes:
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

    names = {_norm_branch_name(b.name): b.name for b in Branch.objects.all()}
    codes = {_norm_branch_code(b.code): b.name for b in Branch.objects.exclude(code__isnull=True)}
    created, blank = 0, 0
    skipped = []   # (line number, name, why)
    for line_no, row in enumerate(rows, start=2):   # line 1 is the header
        name = _clean_branch_name(row.get(name_col))
        code = str(row.get(code_col) or '').strip() if code_col else ''
        if not name:
            if code:
                skipped.append((line_no, f'(code {code})', 'no branch name'))
            else:
                blank += 1
            continue
        nkey, ckey = _norm_branch_name(name), _norm_branch_code(code)
        if nkey in names:
            skipped.append((line_no, name, f'name already exists ("{names[nkey]}")'))
            continue
        if ckey and ckey in codes:
            skipped.append((line_no, name, f'code "{code}" already used by "{codes[ckey]}"'))
            continue
        Branch.objects.create(name=name, code=code or None)
        names[nkey] = name
        if ckey:
            codes[ckey] = name
        created += 1

    log_activity(request, 'branch_created', description=f'Bulk import: {created} added, {len(skipped)} skipped')
    if created:
        messages.success(request, f'Import finished: {created} branch(es) added, {len(skipped)} skipped (duplicates or missing name).')
    else:
        messages.warning(request, f'Nothing was added: {len(skipped)} row(s) skipped (duplicates or missing name).')
    for line_no, nm, why in skipped[:12]:
        messages.warning(request, f'Line {line_no}: {nm} skipped, {why}.')
    if len(skipped) > 12:
        messages.warning(request, f'… and {len(skipped) - 12} more skipped rows.')
    return redirect('add_branch')



# ── Duplicate rules ────────────────────────────────────────────────────────
_EASTERN_DIGITS = str.maketrans('٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹', '01234567890123456789')


def _norm_punch(value):
    """A Punch ID reduced to its identity: Arabic digits -> 0-9, spaces/dashes dropped,
    case ignored, and leading zeros ignored for numeric IDs — so 0123, 123 and ١٢٣
    all count as the same ID."""
    s = unicodedata.normalize('NFKC', str(value or '')).translate(_EASTERN_DIGITS)
    s = re.sub(r'[\s\-_./]+', '', s).casefold()
    return (s.lstrip('0') or '0') if s.isdigit() else s


def _find_waiter_by_punch(branch, punch, exclude_id=None):
    """The waiter of `branch` whose Punch ID matches `punch` after normalising, else None."""
    key = _norm_punch(punch)
    if not key or branch is None:
        return None
    qs = UserProfile.objects.filter(role='waiter', branch=branch).select_related('user')
    if exclude_id:
        qs = qs.exclude(id=exclude_id)
    for p in qs:
        if _norm_punch(p.punch_id) == key:
            return p
    return None


def _norm_branch_name(value):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(value or ''))).strip().casefold()


def _norm_branch_code(value):
    return re.sub(r'\s+', '', unicodedata.normalize('NFKC', str(value or ''))).casefold()


def _clean_branch_name(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def _punch_for(branch, name):
    """The Punch ID of the one waiter of `branch` whose name is `name`, else ''."""
    if not name:
        return ''
    matches = list(UserProfile.objects.filter(role='waiter', branch=branch, head_cashier_name__iexact=name.strip())[:2])
    return matches[0].punch_id if len(matches) == 1 else ''


ENTRY_STAGES = [
    ('awaiting_sales', 'Awaiting Sales Review'),
    ('awaiting_collection', 'Awaiting Collection'),
    ('awaiting_cash_approval', 'Awaiting Cash Approval'),
    ('complete', 'Complete'),
]


def _entry_stage(entry):
    """Where a shift is in its life — the same four stages the Audit list shows."""
    handover = getattr(entry, 'collector', None)
    if not entry.is_audited:
        return 'awaiting_sales'
    if handover is None:
        return 'awaiting_collection'
    if not handover.reconciled:
        return 'awaiting_cash_approval'
    return 'complete'


def _brand_of(name):
    """A branch's brand is the first word of its name: 'Kucu Ibri' -> 'KUCU'."""
    first = (name or '').strip().split(' ')[0]
    return first.upper() or 'OTHER'


def _read_branch_filter(request):
    """Branch names picked in the filter: ?branch_filter=A&branch_filter=B"""
    return [v.strip() for v in request.GET.getlist('branch_filter') if v.strip()]


def _apply_branch_filter(qs, selected, field='branch__name'):
    """Keep only the picked branches. A value that is not an exact branch name
    (an old bookmark such as ?branch_filter=kucu) still works as a text search."""
    if not selected:
        return qs
    known = set(Branch.objects.values_list('name', flat=True))
    q = Q()
    for v in selected:
        q |= Q(**{f'{field}__iexact': v}) if v in known else Q(**{f'{field}__icontains': v})
    return qs.filter(q)


COLLECTED_OPTIONS = [('no', 'Not collected'), ('yes', 'Collected'), ('recon', 'Reconciled')]


def _collected_q(value):
    """Exactly one cash state per shift, so the three pills never overlap:
    not collected (no count from the collector yet) / collected (counted, Audit has not approved yet) / reconciled (Audit approved)."""
    if value == 'no':
        return Q(collector__isnull=True)
    if value == 'yes':
        return Q(collector__isnull=False, collector__reconciled=False)
    return Q(collector__isnull=False, collector__reconciled=True)


def _read_collected(request):
    valid = {v for v, _ in COLLECTED_OPTIONS}
    return [v for v in request.GET.getlist('collected') if v in valid]


def _apply_collected(qs, selected):
    """Any combination of the pills; none picked (or all three) shows everything."""
    picked = {v for v in selected}
    if not picked or len(picked) == len(COLLECTED_OPTIONS):
        return qs
    q = Q()
    for v in picked:
        q |= _collected_q(v)
    return qs.filter(q)


def _collected_context(qs, selected):
    """Pill data: how many shifts are in each cash state under the OTHER filters."""
    return {
        'collected_options': [(v, label, qs.filter(_collected_q(v)).count()) for v, label in COLLECTED_OPTIONS],
        'selected_collected': selected,
        'collected_qs': ''.join(f'collected={v}&' for v in selected),
    }


def _branch_picker_context(selected):
    """Everything the shared branch picker needs: branches grouped by brand,
    which are ticked, a query-string fragment that keeps the choice in links,
    and a short label ('All KUCU, Fresh Seeb') for headings."""
    groups = {}
    for b in Branch.objects.order_by('name'):
        groups.setdefault(_brand_of(b.name), []).append(
            {'name': b.name, 'checked': b.name in selected, 'inactive': not b.is_active})
    ordered, parts, covered = [], [], set()
    for brand, branches in sorted(groups.items()):
        all_checked = bool(branches) and all(x['checked'] for x in branches)
        ordered.append({'brand': brand, 'branches': branches, 'all_checked': all_checked})
        if all_checked and len(branches) > 1:
            parts.append(f'All {brand}')
            covered.update(x['name'] for x in branches)
    parts += [n for n in selected if n not in covered]
    label = ', '.join(parts[:3]) + (f' +{len(parts) - 3} more' if len(parts) > 3 else '')
    return {
        'branch_picker_groups': ordered,
        'branch_selected_count': len(selected),
        'branch_qs': ''.join(f'branch_filter={quote(n)}&' for n in selected),
        'branch_filter': label,
    }


_ARABIC_DIGITS = str.maketrans('٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹', '01234567890123456789')


@never_cache
@role_required('waiter')
def business_date_view(request):
    """Tiny JSON answer for the waiter's form: which business date a report would get
    right now, and whether the branch is inside its opening hours. The form asks again
    every half minute (and when the tab is shown again), so the date updates by itself.
    The date that is actually SAVED is always computed by the server when Submit is pressed."""
    branch = request.user.profile.branch
    if branch is None:
        return JsonResponse({'error': 'no branch'}, status=400)
    day = branch.business_date()
    return JsonResponse({
        'date': day.isoformat(),
        'label': date_filter(day, 'd M Y'),
        'outside_hours': not branch.in_business_hours(),
        'custom': branch.has_custom_hours,
        'open': branch.open_label,
        'close': branch.close_label,
        'next_day': branch.closes_next_day,
    })


def _parse_hhmm(raw):
    """A time somebody TYPED -> datetime.time (to the minute), or None.
    Accepts 10:00, 10.30, 1000, 930, 10, 3, 22:15, 10 pm, 10:30pm — and Arabic digits."""
    import re
    text = (raw or '').translate(_ARABIC_DIGITS).strip().lower()
    suffix = None
    m = re.search(r'\s*(am|pm)$', text)
    if m:
        suffix, text = m.group(1), text[:m.start()].strip()
    text = re.sub(r'[\s.,:٫،]+', ':', text)
    if re.fullmatch(r'\d{1,2}:\d{1,2}', text):
        hour, minute = (int(x) for x in text.split(':'))
    elif re.fullmatch(r'\d{3,4}', text):
        hour, minute = int(text[:-2]), int(text[-2:])
    elif re.fullmatch(r'\d{1,2}', text):
        hour, minute = int(text), 0
    else:
        return None
    if suffix:
        if not 1 <= hour <= 12:
            return None
        hour = hour % 12 + (12 if suffix == 'pm' else 0)
    if hour > 23 or minute > 59:
        return None
    return datetime.time(hour, minute)


def _day_status(branch, date):
    """Where a business day stands: which of the branch's shifts have been submitted and
    approved by Audit, and whether the day can be closed (Foodics for the whole day)."""
    entries = list(ShiftEntry.objects.filter(branch=branch, date=date, is_archived=False).select_related('collector').order_by('shift'))
    by_shift = {}
    for e in entries:
        by_shift.setdefault(str(e.shift), e)
    wanted = [str(s) for s in range(1, max(int(branch.shifts_per_day or 1), 1) + 1)]
    extra = sorted(s for s in by_shift if s not in wanted)
    rows, missing, waiting = [], [], []
    for s in wanted + extra:
        e = by_shift.get(s)
        if e is None:
            rows.append({'shift': s, 'entry': None, 'state': 'missing'})
            missing.append(s)
        elif e.is_audited:
            rows.append({'shift': s, 'entry': e, 'state': 'approved'})
        else:
            rows.append({'shift': s, 'entry': e, 'state': 'waiting'})
            waiting.append(s)
    total = sum((e.sales_actual for e in entries), Decimal('0'))
    day = DayClose.objects.filter(branch=branch, date=date).first()
    return {
        'branch': branch, 'date': date, 'rows': rows, 'missing': missing, 'waiting': waiting,
        'total_actual': total, 'day': day, 'can_close': not missing and not waiting and bool(entries),
        'shifts_per_day': len(wanted),
    }


def _close_day(request, entry):
    """Audit closes (or re-closes) the day of the opened shift: one Foodics figure for the
    whole day. Every change is logged as from -> to, like the rest of the audit trail."""
    status = _day_status(entry.branch, entry.date)
    back = redirect(_reopen_url(request, '/dashboard/', entry.id))
    if not status['can_close']:
        parts = []
        if status['missing']:
            parts.append('not submitted yet: shift ' + ', '.join(status['missing']))
        if status['waiting']:
            parts.append('waiting for sales review: shift ' + ', '.join(status['waiting']))
        messages.error(request, 'The day cannot be closed yet — ' + '; '.join(parts) + '.')
        return back
    raw = (request.POST.get('day_foodics') or '').strip()
    if not raw:
        messages.error(request, "Please enter the day's Foodics figure first.")
        return back
    foodics = _dec(raw)
    note = (request.POST.get('day_note') or '').strip()
    day = status['day']
    actual = status['total_actual']
    if day is None:
        day = DayClose.objects.create(branch=entry.branch, date=entry.date, expected_foodics=foodics,
                                      note=note, closed_by=request.user)
        variance = actual - foodics
        details = (f'Day closed: Foodics {foodics:.3f} · Sales Actual {actual:.3f} · Variance {variance:.3f}'
                   + (f'\nNote: "{note}"' if note else ''))
    else:
        old_foodics, old_variance, old_note = Decimal(str(day.expected_foodics)), day.variance, day.note
        lines = []
        if old_foodics != foodics:
            lines.append(f'Foodics: {old_foodics:.3f} → {foodics:.3f}')
        new_variance = actual - foodics
        if old_variance != new_variance:
            lines.append(f'Variance: {old_variance:.3f} → {new_variance:.3f}')
        if old_note != note:
            lines.append(f'Note: "{note}"' if note else 'Note removed')
        day.expected_foodics = foodics
        day.note = note
        day.closed_by = request.user
        day.save()
        details = 'Day re-closed\n' + '\n'.join(lines) if lines else 'Day re-closed, nothing changed'
    log_activity(request, 'day_closed', description=day.label, details=details)
    messages.success(request, f'{entry.branch.name} · {entry.date} closed.')
    return back


@role_required('audit', 'manager', 'admin')
def audit_settings_view(request):
    """Audit's Settings page: each branch's opening and closing time, typed in by
    hand (the closing time may be on the next calendar day, e.g. 10:00 -> 03:00). A
    report belongs to the business day it was submitted in; anything submitted
    after the day ended but before the next one starts still counts for the day
    that just closed. Managers can look but not change."""
    is_viewer = request.user.profile.role == 'manager'

    if request.method == 'POST':
        if is_viewer:
            raise PermissionDenied('Managers have view-only access.')
        saved, bad, same, saved_shifts = 0, [], [], 0
        for b in Branch.objects.all():
            raw_shifts = (request.POST.get(f'shifts_{b.id}') or '').strip()
            if raw_shifts in ('1', '2', '3') and int(raw_shifts) != b.shifts_per_day:
                old_n = b.shifts_per_day
                b.shifts_per_day = int(raw_shifts)
                b.save(update_fields=['shifts_per_day'])
                log_activity(request, 'branch_edited', description=f'{b.name}: shifts per day',
                             details=f'Shifts per day changed from {old_n} to {b.shifts_per_day}')
                saved_shifts += 1
            raw_start, raw_end = request.POST.get(f'start_{b.id}', ''), request.POST.get(f'end_{b.id}', '')
            if not raw_start.strip() and not raw_end.strip():
                continue
            start, end = _parse_hhmm(raw_start), _parse_hhmm(raw_end)
            if start is None or end is None:
                bad.append(b.name)
                continue
            if start == end:
                same.append(b.name)
                continue
            old_window = b.day_window
            old_start, old_end = b.day_cutoff, b.effective_end
            if (start, end) == (old_start, old_end):
                continue
            b.day_cutoff = start
            b.day_end = end                                   # exactly what was typed — nothing is derived
            b.save(update_fields=['day_cutoff', 'day_end'])
            log_activity(request, 'branch_edited', description=f'{b.name}: business day',
                         details=f'Opening hours changed from {old_window} to {b.day_window}')
            saved += 1
        if bad:
            messages.error(request, 'Type the times like 10 am, 3:30 pm or 22:30. Not a valid time for: ' + ', '.join(bad))
        if same:
            messages.error(request, "Opening and closing can't be the same time: " + ', '.join(same))
        if saved:
            messages.success(request, f'Saved the opening hours of {saved} branch{"es" if saved != 1 else ""}.')
        if saved_shifts:
            messages.success(request, f'Saved the number of shifts of {saved_shifts} branch{"es" if saved_shifts != 1 else ""}.')
        if not saved and not saved_shifts and not bad and not same:
            messages.info(request, 'Nothing changed.')
        return redirect('audit_settings')

    groups = {}
    for b in Branch.objects.order_by('name'):
        groups.setdefault(_brand_of(b.name), []).append({
            'id': b.id, 'name': b.name, 'inactive': not b.is_active,
            'start': _fmt12(b.day_cutoff), 'end': _fmt12(b.effective_end),
            'start24': b.day_cutoff.strftime('%H:%M'), 'end24': b.effective_end.strftime('%H:%M'),
            'window': b.day_window, 'today': b.business_date(),
            'shifts': b.shifts_per_day,
        })
    return render(request, 'salesapp/audit_settings.html', {
        'active_tab': 'audit_settings',
        'brand_groups': [{'brand': k, 'branches': v} for k, v in sorted(groups.items())],
        'is_viewer': is_viewer,
        'now': timezone.localtime(),
    })


def _daily_report_context(request):
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
    selected_branches = _read_branch_filter(request)
    shift_filter = request.GET.getlist('shift')
    selected_collected = _read_collected(request)

    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=False)
    if date_from:
        qs = qs.filter(date__gte=date_from)
    if date_to:
        qs = qs.filter(date__lte=date_to)
    qs = _apply_branch_filter(qs, selected_branches)
    if shift_filter:
        qs = qs.filter(shift__in=shift_filter)
    collected_ctx = _collected_context(qs, selected_collected)
    qs = _apply_collected(qs, selected_collected)
    entries = list(qs.order_by('-date', 'branch__name', 'shift'))

    zero = Decimal('0')

    def dec(v):
        return Decimal(str(v or 0))

    # Foodics is one figure per day: it sits on the day's last shift row, and the totals count it once.
    day_closes = {(d.branch_id, d.date): d for d in DayClose.objects.filter(
        branch_id__in={e.branch_id for e in entries}, date__in={e.date for e in entries})}
    last_shift = {}
    for e in entries:
        k = (e.branch_id, e.date)
        if k not in last_shift or int(e.shift) > int(last_shift[k]):
            last_shift[k] = e.shift

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
    sales_wait = zero; n_sales_wait = 0
    cash_collected = zero; n_collected = 0      # counted by the collector, not reconciled yet
    cash_missing = zero; n_missing = 0          # not collected: the waiter's cash still to come
    rows = []
    for e in entries:
        h = getattr(e, 'collector', None)
        sales_ok = e.is_audited
        cash_ok = h is not None and h.reconciled
        n_sales += 1 if sales_ok else 0
        n_cash += 1 if cash_ok else 0
        if not sales_ok:
            sales_wait += dec(e.sales_actual); n_sales_wait += 1
        if h is None:
            cash_missing += dec(e.cash_total); n_missing += 1
        elif not cash_ok:
            cash_collected += dec(h.cash_total); n_collected += 1

        k = (e.branch_id, e.date)
        day = day_closes.get(k) if str(last_shift[k]) == str(e.shift) else None
        dl = e.delivery_data or {}
        vals = {
            'discount': e.staff_discount, 'visa': e.visa_total,
            'del_cancel': e.delivery_cancel_amount, 'del_net': e.delivery_total,
            'orders': sum(int((dl.get(k, {}) or {}).get('orders') or 0) for k, _ in DELIVERY_SOURCES),
            'sales_actual': e.sales_actual,
            'foodics': day.expected_foodics if day else None,
            'variance': day.variance if day else None,
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
         'hint': 'cash + visa · approved by sales review',
         'lines': [
             {'label': 'Waiting for sales review', 'amount': sales_wait, 'n': n_sales_wait, 'cls': 'wait'},
             {'label': 'All shifts', 'amount': totals['sales_actual'] + sales_wait, 'n': len(entries), 'cls': 'all'},
         ]},
        {'title': 'Cash', 'amount': totals['col_cash'], 'shifts': n_cash,
         'hint': 'as counted by the collector · reconciled by audit',
         'lines': [
             {'label': 'Collected, waiting for audit', 'amount': cash_collected, 'n': n_collected, 'cls': 'mid'},
             {'label': 'Not collected yet (waiter cash)', 'amount': cash_missing, 'n': n_missing, 'cls': 'wait'},
         ]},
    ]

    return {
        'active_tab': 'daily_report',
        'cards': cards,
        'columns': columns,
        'sales_col_count': len(sales_cols),
        'cash_col_count': len(cash_cols),
        'rows': rows,
        'total_cells': [{'value': totals[c['key']], 'int': c['key'] == 'orders'} for c in columns],
        'entry_count': len(entries),
        **_branch_picker_context(selected_branches),
        'shift_choices': SHIFT_CHOICES,
        'date_from': date_from,
        'date_to': date_to,
        'shift_filter': shift_filter,
        **collected_ctx,
        'query_string': request.GET.urlencode(),
    }


REPORT_ROLES = ('audit', 'manager', 'sales_manager', 'admin')


@role_required(*REPORT_ROLES)
def daily_sales_report_view(request):
    return render(request, 'salesapp/daily_sales_report.html', _daily_report_context(request))


@role_required(*REPORT_ROLES)
def daily_sales_report_xlsx_view(request):
    """The same report (same filters) as an Excel file."""
    import io
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter

    ctx = _daily_report_context(request)
    columns, rows = ctx['columns'], ctx['rows']

    wb = Workbook()
    ws = wb.active
    ws.title = 'Daily Sales Report'
    navy, cream, grey = '1F3B4D', 'F7F5EE', '9A9585'
    thin = Side(style='thin', color='E3DFD3')
    NUM = '#,##0.000;[Red]-#,##0.000'

    def text(cell, value):
        """Write user-supplied text as plain text — never as a formula (a name starting with = would otherwise run)."""
        cell.value = '' if value is None else str(value)
        cell.data_type = 's'

    n_lead = 7                                   # Date, Branch, Submitted By, Shift, Ref, Sales, Cash
    first_val_col = n_lead + 1
    last_col = n_lead + len(columns)
    sales_col, cash_col = 6, 7                   # status columns that decide what a total counts
    title_row = 1
    grp_row, head_row = 3, 4
    first = head_row + 1
    last = head_row + len(rows)
    total_row = last + 2

    ws.cell(title_row, 1, 'Daily Sales Report').font = Font(bold=True, size=16, color=navy)

    # group header
    sales_n = ctx['sales_col_count']
    ws.cell(grp_row, first_val_col, 'Daily Sales')
    ws.merge_cells(start_row=grp_row, start_column=first_val_col, end_row=grp_row, end_column=first_val_col + sales_n - 1)
    ws.cell(grp_row, first_val_col + sales_n, 'Cash')
    ws.merge_cells(start_row=grp_row, start_column=first_val_col + sales_n, end_row=grp_row, end_column=last_col)
    for col in range(1, last_col + 1):
        g = ws.cell(grp_row, col)
        g.font = Font(bold=True, color=navy)
        g.alignment = Alignment(horizontal='center')
        g.fill = PatternFill('solid', fgColor='E9E5D8' if col >= first_val_col else 'FFFFFF')

    heads = ['Date', 'Branch', 'Submitted By', 'Shift', 'Ref', 'Sales Review', 'Cash Status'] + [c['label'] for c in columns]
    for i, h in enumerate(heads, start=1):
        c = ws.cell(head_row, i, h)
        c.font = Font(bold=True, color='FFFFFF')
        c.fill = PatternFill('solid', fgColor=navy)
        c.alignment = Alignment(horizontal='left' if i <= n_lead else 'right', vertical='center', wrap_text=True)
    ws.row_dimensions[head_row].height = 32

    cash_label = {'reconciled': 'Reconciled', 'collected': 'Collected', 'not collected': 'Not collected'}
    for r, row in enumerate(rows, start=first):
        e = row['entry']
        c = ws.cell(r, 1, e.date); c.number_format = 'dd mmm yyyy'; c.alignment = Alignment(horizontal='left')
        text(ws.cell(r, 2), e.branch.name)
        who = e.accountant or ''
        if e.submitted_punch:
            who = f'{who} · {e.submitted_punch}' if who else str(e.submitted_punch)
        text(ws.cell(r, 3), who)
        text(ws.cell(r, 4), e.shift)
        text(ws.cell(r, 5), e.reference_id)
        text(ws.cell(r, 6), 'Approved' if row['sales_ok'] else 'Pending')
        text(ws.cell(r, 7), cash_label.get(row['cash_state'], row['cash_state']))
        for i, cell in enumerate(row['cells']):
            xc = ws.cell(r, first_val_col + i)
            if cell['value'] is None:
                continue
            xc.value = int(cell['value']) if cell['int'] else float(cell['value'])
            xc.number_format = '0' if cell['int'] else NUM
            xc.alignment = Alignment(horizontal='right')
            if not cell['counted']:
                xc.font = Font(color='B5B0A0', italic=True)

    # totals: live formulas that add only the completed shifts
    ws.cell(total_row, 1, 'Total — completed shifts only').font = Font(bold=True, color='FFFFFF')
    for col in range(1, last_col + 1):
        ws.cell(total_row, col).fill = PatternFill('solid', fgColor=navy)
    if rows:
        for i, c in enumerate(columns):
            letter = get_column_letter(first_val_col + i)
            key_col = get_column_letter(sales_col if c['side'] == 'sales' else cash_col)
            crit = 'Approved' if c['side'] == 'sales' else 'Reconciled'
            t = ws.cell(total_row, first_val_col + i,
                        f'=SUMIFS({letter}{first}:{letter}{last},{key_col}{first}:{key_col}{last},"{crit}")')
            t.number_format = '0' if c['key'] == 'orders' else NUM
            t.font = Font(bold=True, color='FFFFFF')
            t.alignment = Alignment(horizontal='right')

    widths = {1: 13, 2: 24, 3: 24, 4: 7, 5: 16, 6: 14, 7: 15}
    for col in range(1, last_col + 1):
        ws.column_dimensions[get_column_letter(col)].width = widths.get(col, 14)
    ws.freeze_panes = ws.cell(first, first_val_col)
    if rows:
        ws.auto_filter.ref = f'A{head_row}:{get_column_letter(last_col)}{last}'
    ws.page_setup.orientation = 'landscape'
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.sheet_view.showGridLines = False
    for r in range(first, last + 1):
        for col in range(1, last_col + 1):
            ws.cell(r, col).border = Border(bottom=thin)

    buf = io.BytesIO()
    wb.save(buf)
    name = f"daily_sales_report_{timezone.localdate().isoformat()}.xlsx"
    resp = HttpResponse(buf.getvalue(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    resp['Content-Disposition'] = f'attachment; filename="{name}"'
    return resp


@role_required('audit', 'admin')
def edit_entry_view(request, entry_id):
    entry = get_object_or_404(ShiftEntry, id=entry_id)

    if request.method == 'POST':
        entry.date = request.POST.get('date')
        entry.shift = request.POST.get('shift')
        entry.accountant = request.POST.get('accountant', '').strip()
        visa_rows = _apply_waiter_financials(request, entry)
        if 'expected_foodics' in request.POST:   # Foodics is now entered once per day (Day Close)
            entry.expected_foodics = _dec(request.POST.get('expected_foodics'))
        entry.notes = request.POST.get('notes', '')
        if request.FILES.get('notes_attachment'):
            entry.notes_attachment = request.FILES['notes_attachment']

        entry.save()  # reference_id is untouched since it's already set
        _save_visa_files(entry, visa_rows)
        _save_notes_files(entry, request)

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
        'visa_urls': _visa_urls(entry),
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
            _dup = _find_waiter_by_punch(branch, punch_id, exclude_id=profile.id)
            if _dup:
                messages.error(request, f'{branch.name} already has a different waiter with this Punch ID ("{_dup.punch_id}", {_dup.head_cashier_name}).')
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
    if entry.request_status in ('pending', 'rejected'):
        messages.error(request, 'This is a waiter request. Decide it from the Audit dashboard.')
        return redirect('dashboard')
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
    qs = ShiftEntry.objects.select_related('branch', 'collector').filter(is_archived=True).exclude(request_status__in=['pending', 'rejected']).order_by('-created_at')

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
        'my_requests': list(ShiftEntry.objects.filter(branch=branch).exclude(request_status='').order_by('-created_at')[:15]),
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
    elif action == 'save_note':
        note = request.POST.get('note', '').strip()
        if not handovers:
            messages.error(request, 'That shift was already reconciled or no longer exists.')
        elif not note:
            messages.error(request, 'Please write the Audit note first.')
        else:
            h = handovers[0]
            h.reconcile_note = note
            h.save(update_fields=['reconcile_note'])
            log_activity(request, 'cash_reconciled', description=h.shift_entry.reference_id,
                         details=f'Audit note (cash not approved yet):\n"{note}"')
            messages.success(request, 'Audit note saved.')
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
