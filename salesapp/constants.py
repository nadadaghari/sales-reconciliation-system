# Cash denominations shown on the paper form (OMR: baisa + rial notes).
DENOMS = ['0.005', '0.01', '0.025', '0.05', '0.1', '0.5', '1', '5', '10', '20', '50']

# AED (UAE Dirham) note denominations — for branches that also collect AED cash.
AED_DENOMS = ['5', '10', '20', '50', '100', '200', '500', '1000']

# Delivery / order sources shown on the paper form.
DELIVERY_SOURCES = [
    ('talabat', 'Talabat'),
    ('tmdone', 'TM Done'),
    ('khedmah', 'Khedmah'),
    ('callcenter', 'Call Center'),
]

SHIFT_CHOICES = [
    ('1', 'Shift 1'),
    ('2', 'Shift 2'),
    ('3', 'Shift 3'),
]
