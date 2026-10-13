from salesapp.models import ShiftEntry, UserProfile
done = skipped = 0
for e in ShiftEntry.objects.filter(submitted_punch=''):
    people = list(UserProfile.objects.filter(role='waiter', branch=e.branch, head_cashier_name__iexact=(e.accountant or '').strip())[:2])
    if len(people) == 1 and people[0].punch_id:
        e.submitted_punch = people[0].punch_id
        e.save(update_fields=['submitted_punch'])
        done += 1
    else:
        skipped += 1
print('Punch ID added to', done, 'reports; left empty (no single matching waiter):', skipped)
