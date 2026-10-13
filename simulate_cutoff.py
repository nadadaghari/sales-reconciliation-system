import os, datetime
from django.utils import timezone
from salesapp.models import Branch
b = Branch.objects.filter(name__iexact=os.environ['BR']).first()
if b is None:
    print('No branch with that name. Branches:', [x.name for x in Branch.objects.all()])
else:
    day = datetime.date.fromisoformat(os.environ['DAY'])
    print(b.name, '| hours:', b.day_window)
    for h in range(24):
        t = timezone.make_aware(datetime.datetime.combine(day, datetime.time(h, 0)))
        print(t.strftime('%d %b %I:%M %p'), '->', b.business_date(t).strftime('%a %d %b'), '|', 'open' if b.in_business_hours(t) else 'closed')
