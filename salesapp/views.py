import csv
import io
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.core.cache import cache
from django.db.models import Sum
from django.utils import timezone

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
        if not profile.user.is_active:
            messages.error(request, 'This account is deactivated. Contact your admin.')
            return redirect('login')

        if not profile.user.check_password(password):
            _register_failed_attempt(cache_key)
            log_activity(request, 'login_failed', description=f'branch code: {branch_code}, punch id: {punch_id}', username_override=profile.user.username)
            messages.error(request, 'Invalid branch code, Punch ID, or password.')
            return redirect('login')

        _clear_attempts(cache_key)
        login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
        log_activity(request, 'login_success', user=profile.user, description=f'branch: {branch.name}')
        return redirect('entry')
    return render(request, 'salesapp/branch_login.html')


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        log_activity(request, 'logout')
    logout(request)
    return redirect('login')


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
    if profile.role == 'audit':
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


def log_activity(request, action, description='', user=None, username_override=None):
    """Record one line in the audit trail. Pass `user` explicitly right
    after a successful login (before/without relying on request.user), or
    `username_override` for failed-login attempts where there's no user
    object at all — just the username someone typed in."""
    actor = user or (request.user if request.user.is_authenticated else None)
    snapshot = username_override or (actor.username if actor else '')
    ActivityLog.objects.create(
        user=actor,
        username_snapshot=snapshot,
        action=action,
        description=description[:255],
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

        serials = request.POST.getlist('visa_serial[]')
        amounts = request.POST.getlist('visa_amount[]')
        visa_files = request.FILES.getlist('visa_attachment[]')
        visa_entries = [
            {'serial': s, 'amount': float(_dec(a))}
            for s, a in zip(serials, amounts) if s or a
        ]

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
            visa_cancel_amount=_dec(request.POST.get('visa_cancel_amount')),
            delivery_data=delivery_data,
            delivery_cancel_source=request.POST.get('delivery_cancel_source', '').strip(),
            delivery_cancel_amount=_dec(request.POST.get('delivery_cancel_amount')),
            notes=request.POST.get('notes', ''),
            # expected_foodics is set later by Audit, not by the waiter.
        )
        if request.FILES.get('discount_attachment'):
            entry.staff_discount_attachment = request.FILES['discount_attachment']
        if request.FILES.get('notes_attachment'):
            entry.notes_attachment = request.FILES['notes_attachment']
        if request.FILES.get('cash_cancel_attachment'):
            entry.cash_cancel_attachment = request.FILES['cash_cancel_attachment']
        if request.FILES.get('visa_cancel_attachment'):
            entry.visa_cancel_attachment = request.FILES['visa_cancel_attachment']
        if request.FILES.get('delivery_cancel_attachment'):
            entry.delivery_cancel_attachment = request.FILES['delivery_cancel_attachment']
        for key, _label in DELIVERY_SOURCES:
            uploaded = request.FILES.get(f'delivery_attachment_{key}')
            if uploaded:
                setattr(entry, f'delivery_attachment_{key}', uploaded)
        entry.save()

        for i, s in enumerate(serials):
            if i < len(visa_files):
                VisaMachineFile.objects.create(entry=entry, serial=s, file=visa_files[i])

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
    }
    return render(request, 'salesapp/entry.html', context)


@role_required('collector', 'admin')
def collector_view(request):
    if request.method == 'POST':
        entry_id = request.POST.get('shift_entry_id')
        shift_entry = get_object_or_404(ShiftEntry, id=entry_id)

        cash_counts = {d: int(request.POST.get(f'cdenom_{d}', 0) or 0) for d in DENOMS}

        handover, _ = CollectorHandover.objects.get_or_create(shift_entry=shift_entry)
        handover.collector_name = request.POST.get('collector_name', '').strip()
        handover.cash_counts = cash_counts
        handover.visa_total = _dec(request.POST.get('visa_total'))
        handover.delivery_total = _dec(request.POST.get('delivery_total'))
        handover.notes = request.POST.get('notes', '')
        handover.save()

        log_activity(request, 'handover_saved', description=shift_entry.reference_id)
        messages.success(request, 'Collector handover saved.')
        return redirect(f"/collector/?entry_id={entry_id}")

    selected_entry = None
    selected_handover = None

    search_ref = request.GET.get('search_ref', '').strip()
    entry_id = request.GET.get('entry_id')

    if search_ref and not entry_id:
        matched = ShiftEntry.objects.filter(reference_id__iexact=search_ref).first()
        if matched:
            return redirect(f"/collector/?entry_id={matched.id}")
        messages.error(request, f'No entry found with reference ID "{search_ref}".')

    if entry_id:
        selected_entry = get_object_or_404(ShiftEntry, id=entry_id)
        selected_handover = getattr(selected_entry, 'collector', None)

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
        agg = all_entries_qs.aggregate(
            total_cash=Sum('cash_total'), total_visa=Sum('visa_total'),
            total_delivery=Sum('delivery_total'), total_actual=Sum('actual_total'),
            total_expected=Sum('expected_foodics'),
        )
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
            'total_cash': Decimal('0'), 'total_visa': Decimal('0'),
            'total_delivery': Decimal('0'), 'total_actual': Decimal('0'),
            'total_expected': Decimal('0'), 'total_variance': Decimal('0'),
        })
        group['entries'].append(e)
        e.simple_status = 'audited' if e.is_audited else ('collected' if getattr(e, 'collector', None) else 'not_collected')
        group['total_cash'] += e.cash_total
        group['total_visa'] += e.visa_total
        group['total_delivery'] += e.delivery_total
        group['total_actual'] += e.actual_total
        group['total_expected'] += e.expected_foodics
        group['total_variance'] += e.variance
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

    context = {
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
        'delivery_sources': DELIVERY_SOURCES,
        'search_ref': search_ref,
        'active_tab': 'collector',
    }
    return render(request, 'salesapp/collector.html', context)


@role_required('audit', 'admin')
def dashboard_view(request):
    threshold = Decimal(str(settings.VARIANCE_THRESHOLD))

    if request.method == 'POST':
        entry_id = request.POST.get('entry_id')
        entry = get_object_or_404(ShiftEntry, id=entry_id)
        entry.audit_notes = request.POST.get('audit_notes', '').strip()
        if 'expected_foodics' in request.POST:
            entry.expected_foodics = _dec(request.POST.get('expected_foodics'))
        entry.is_audited = True
        entry.save()  # full save so recalculate() persists the updated variance too
        log_activity(request, 'entry_audited', description=entry.reference_id)
        messages.success(request, f'{entry.reference_id} marked as audited.')
        return redirect(f"/dashboard/?entry_id={entry_id}")

    selected_entry = None
    selected_handover = None
    entry_id = request.GET.get('entry_id')
    if entry_id:
        selected_entry = get_object_or_404(ShiftEntry, id=entry_id)
        selected_handover = getattr(selected_entry, 'collector', None)

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
        handover = getattr(e, 'collector', None)
        if handover is None:
            status = 'not_collected'
            diff_waiter_flag = False
            diff_expected_flag = False
        else:
            status = handover.status(threshold)
            diff_waiter_flag = abs(handover.diff_from_waiter) > threshold
            diff_expected_flag = abs(handover.diff_from_expected) > threshold
        has_issue = diff_waiter_flag or diff_expected_flag

        # Simple 3-stage progress badge: Not Collected -> Collected -> Audited.
        # (has_issue still separately drives the red highlighting on the numbers.)
        if e.is_audited:
            simple_status = 'audited'
        elif handover is not None:
            simple_status = 'collected'
        else:
            simple_status = 'not_collected'

        group = branch_groups_map.setdefault(e.branch_id, {
            'branch': e.branch,
            'rows': [],
            'total_variance': Decimal('0'),
            'total_actual': Decimal('0'),
        })
        group['rows'].append({
            'entry': e, 'collector': handover, 'status': status,
            'simple_status': simple_status, 'has_issue': has_issue,
        })
        group['total_variance'] += e.variance
        group['total_actual'] += e.actual_total

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
        'branch_groups': branch_groups,
        'shift_filter': shift_filter,
        'shift_choices': SHIFT_CHOICES,
        'branch_filter': branch_filter,
        'date_from': date_from,
        'date_to': date_to,
        'search_ref': search_ref,
        'denoms': DENOMS,
        'delivery_sources': DELIVERY_SOURCES,
        'selected_entry': selected_entry,
        'selected_handover': selected_handover,
        'entry_denoms': entry_denoms,
        'entry_aed_denoms': entry_aed_denoms,
        'entry_visa_rows': entry_visa_rows,
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


@role_required('audit', 'admin')
def edit_entry_view(request, entry_id):
    entry = get_object_or_404(ShiftEntry, id=entry_id)

    if request.method == 'POST':
        entry.date = request.POST.get('date')
        entry.shift = request.POST.get('shift')
        entry.accountant = request.POST.get('accountant', '').strip()
        entry.staff_discount = _dec(request.POST.get('staff_discount'))
        entry.petty_cash = _dec(request.POST.get('petty_cash'))

        entry.cash_counts = {d: int(request.POST.get(f'denom_{d}', 0) or 0) for d in DENOMS}
        entry.cash_counts_aed = {d: int(request.POST.get(f'denom_aed_{d}', 0) or 0) for d in AED_DENOMS}
        entry.aed_exchange_rate = _dec(request.POST.get('aed_exchange_rate'), default='0.1000')

        serials = request.POST.getlist('visa_serial[]')
        amounts = request.POST.getlist('visa_amount[]')
        visa_files = request.FILES.getlist('visa_attachment[]')
        entry.visa_entries = [
            {'serial': s, 'amount': float(_dec(a))}
            for s, a in zip(serials, amounts) if s or a
        ]

        delivery_data = {}
        for key, _label in DELIVERY_SOURCES:
            delivery_data[key] = {
                'orders': int(request.POST.get(f'orders_{key}', 0) or 0),
                'amount': float(_dec(request.POST.get(f'amount_{key}', 0))),
                'cancel_orders': int(request.POST.get(f'cancel_orders_{key}', 0) or 0),
                'cancel_amount': float(_dec(request.POST.get(f'cancel_amount_{key}', 0))),
            }
        entry.delivery_data = delivery_data
        entry.cash_cancel_amount = _dec(request.POST.get('cash_cancel_amount'))
        entry.visa_cancel_amount = _dec(request.POST.get('visa_cancel_amount'))
        entry.delivery_cancel_source = request.POST.get('delivery_cancel_source', '').strip()
        entry.delivery_cancel_amount = _dec(request.POST.get('delivery_cancel_amount'))
        entry.expected_foodics = _dec(request.POST.get('expected_foodics'))
        entry.notes = request.POST.get('notes', '')
        if request.FILES.get('discount_attachment'):
            entry.staff_discount_attachment = request.FILES['discount_attachment']
        if request.FILES.get('notes_attachment'):
            entry.notes_attachment = request.FILES['notes_attachment']
        if request.FILES.get('cash_cancel_attachment'):
            entry.cash_cancel_attachment = request.FILES['cash_cancel_attachment']
        if request.FILES.get('visa_cancel_attachment'):
            entry.visa_cancel_attachment = request.FILES['visa_cancel_attachment']
        if request.FILES.get('delivery_cancel_attachment'):
            entry.delivery_cancel_attachment = request.FILES['delivery_cancel_attachment']
        for key, _label in DELIVERY_SOURCES:
            uploaded = request.FILES.get(f'delivery_attachment_{key}')
            if uploaded:
                setattr(entry, f'delivery_attachment_{key}', uploaded)

        entry.save()  # reference_id is untouched since it's already set

        for i, s in enumerate(serials):
            if i < len(visa_files):
                VisaMachineFile.objects.create(entry=entry, serial=s, file=visa_files[i])

        messages.success(request, f'Entry {entry.reference_id} updated.')
        log_activity(request, 'entry_edited', description=entry.reference_id)
        return redirect('dashboard')

    context = {
        'entry': entry,
        'denoms': DENOMS,
        'aed_denoms': AED_DENOMS,
        'denom_pairs': list(zip(DENOMS, AED_DENOMS)),
        'delivery_sources': DELIVERY_SOURCES,
        'shift_choices': SHIFT_CHOICES,
        'active_tab': 'dashboard',
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
    tracked_actions = ['handover_saved', 'entry_audited', 'entry_edited']
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
            'simple_status': 'audited' if e.is_audited else ('collected' if getattr(e, 'collector', None) else 'not_collected'),
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
