import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Security-sensitive settings now come from environment variables ---
# In development, sensible defaults are used automatically so nothing
# breaks. Before deploying anywhere reachable by the public, set real
# values for these three in your environment (or a .env file loaded by
# your process manager):
#   SECRET_KEY=<a long random string>
#   DEBUG=False
#   ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

DEBUG = os.environ.get('DEBUG', 'True') == 'True'

_allowed_hosts = os.environ.get('ALLOWED_HOSTS', '')
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts.split(',') if h.strip()] or ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'salesapp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# [!] Database connection now comes from environment variables (set once,
# see README "Permanent database configuration" section). This means
# replacing this settings.py file in future updates will NEVER reset your
# database connection back to SQLite - as long as the environment
# variables are set on this machine, Django picks up PostgreSQL
# automatically. If DB_ENGINE isn't set, it falls back to local SQLite
# (handy for a fresh dev machine that hasn't set this up yet).
DATABASES = {
    'default': {
        'ENGINE': os.environ.get('DB_ENGINE', 'django.db.backends.sqlite3'),
        'NAME': os.environ.get('DB_NAME', str(BASE_DIR / 'db.sqlite3')),
        'USER': os.environ.get('DB_USER', ''),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', ''),
        'PORT': os.environ.get('DB_PORT', ''),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Muscat'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Discrepancy threshold (currency units) above which an entry is flagged.
VARIANCE_THRESHOLD = 5

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'entry'
LOGOUT_REDIRECT_URL = 'login'

# --- Basic security hardening ---
# Cookies: JS can't read them, and CSRF cookie isn't sent to other sites.
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
# Only send cookies over HTTPS once you're actually serving over HTTPS
# (turn these on in production - they'd block login over plain http).
SESSION_COOKIE_SECURE = os.environ.get('HTTPS_ENABLED', 'False') == 'True'
CSRF_COOKIE_SECURE = os.environ.get('HTTPS_ENABLED', 'False') == 'True'
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True

# In-memory cache used for login rate limiting (see decorators.py /
# views.py). Fine for a single dev server; swap to Redis for multi-process
# production deployments so the limiter is shared across workers.
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
