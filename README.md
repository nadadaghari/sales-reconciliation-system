# Daily Sales Reconciliation System — Django Prototype

## What this is
A Django rebuild of the sales reconciliation prototype: three pages —
**Waiter Entry**, **Collector Handover**, **Audit Dashboard** — backed by a
real relational database (SQLite by default, swappable to PostgreSQL),
now with **login and role-based access**.

## Roles

| Role | Can access |
|---|---|
| Waiter | Waiter Entry only — locked to their assigned branch |
| Collector | Collector Handover only |
| Audit | Audit Dashboard only |
| Admin | Everything, plus Users and Branches management pages |

## Run it locally

```bash
# 1. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the database tables
python manage.py makemigrations
python manage.py migrate

# 4. Create your first Admin account (this account can then create
#    everyone else — waiters, collectors, audit — from the Users page)
python manage.py create_admin youradminname yourpassword
```

> If you already had this project running **before** the login system was
> added, just re-run `makemigrations` and `migrate` — Django will add the
> new `UserProfile` table without touching your existing data.

```bash
# 5. Run the dev server
python manage.py runserver
```

Open **http://127.0.0.1:8000/login/** and log in with the admin account
you just created.

## Setting up your team

1. Log in as Admin.
2. Go to **Branches** → add each of your 32 branches.
3. Go to **Users** → create one login per person (or per branch, if a
   branch shares one login across its accountants):
   - **Waiter** role → pick their branch. They'll only ever see and
     submit entries for that branch.
   - **Collector** role → no branch needed, they see all branches.
   - **Audit** role → no branch needed, they see the dashboard for all
     branches.
4. Share each person's username/password with them.

## Where things live

- `salesapp/models.py` — `Branch`, `UserProfile` (role + branch),
  `ShiftEntry` (waiter data), `CollectorHandover` (collector's recount).
  Totals are calculated **server-side** in each model's `save()` — never
  trust a number sent from the browser.
- `salesapp/decorators.py` — `@role_required(...)` guards each view.
- `salesapp/views.py` — all page logic, including login/logout and the
  admin-only user/branch creation pages.
- `salesapp/templates/salesapp/` — HTML templates (English UI). The nav
  bar shows only the tabs relevant to the logged-in user's role.
- `salesapp/constants.py` — cash denominations and delivery sources.
- `config/settings.py` — `VARIANCE_THRESHOLD` controls how big a variance
  has to be before an entry is flagged (currently 5).

## Moving to production (next steps)

1. **Switch to PostgreSQL** — replace the `DATABASES` block in
   `config/settings.py`, then re-run `migrate`.
2. **Turn off DEBUG** — set `DEBUG = False` in `config/settings.py` and
   set a real `SECRET_KEY` (currently a placeholder) before this goes
   anywhere public. With `DEBUG = True`, errors leak technical details.
3. **Foodics API integration** — replace the manual `expected_foodics`
   field with a scheduled job that pulls the day's expected sales from
   Foodics automatically.
4. **Anti-fraud layer** — void/cancel tracking, discount-rate monitoring,
   statistical anomaly detection, as discussed — would sit on top of the
   same `ShiftEntry` data already being captured here.

This is a working MVP. Before using it with real money or real staff,
also add: password reset flow, HTTPS (any public host should provide
this), and stronger input validation.

