import os
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from dotenv import load_dotenv
from datetime import timedelta
from cryptography.fernet import Fernet



load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
PORT = os.getenv("PORT", "8000")

ALLOWED_HOSTS=["127.0.0.1", "localhost", "64.225.122.101"]


# Required for Nginx proxy
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# If you're getting the duplicate IP issue, add this:
USE_X_FORWARDED_PORT = True

# This is  for generating the fernet key regarding MFA
FERNET_KEY = os.getenv("FERNET_KEY")

# CSRF Trusted Origins
CSRF_TRUSTED_ORIGINS = [
    "http://64.225.122.101:8000",
    "http://64.225.122.101",
    "http://64.225.122.101:5173", 
]

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("sqlite"):
    # Use SQLite for testing/CI
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
elif DATABASE_URL:
    # Use PostgreSQL for production (Neon DB)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("PGDATABASE", "neondb"),  # <-- This reads from PGDATABASE
            "USER": os.environ.get("PGUSER", "neondb_owner"),  # <-- This reads from PGUSER
            "PASSWORD": os.environ.get("PGPASSWORD"),  # <-- This reads from PGPASSWORD
            "HOST": os.environ.get("PGHOST"),  # <-- This reads from PGHOST
            "PORT": os.environ.get("PGPORT", "5432"),
            "OPTIONS": {
                "sslmode": os.environ.get("PGSSLMODE", "require"),
            },
        }
    }
else:
    # Fallback to SQLite if no DATABASE_URL
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "obeeomaapp",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist", 
    "django_extensions",
    "drf_yasg",
    "drf_spectacular",
    'corsheaders',
    'django_filters',
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # custom middleware to prevent caching
    "obeeomaapp.Middleware.security_middleware.NoCacheMiddleware",
    
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Media files
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

ROOT_URLCONF = "api.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "api.wsgi.application"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
STATIC_URL = "static/"

AUTH_USER_MODEL = "obeeomaapp.User"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CORS settings
# Allow all origins for development (restrict in production)
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Frontend URL for email links
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://64.225.122.101")

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/overview/"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "My API",
    "DESCRIPTION": "API documentation",
    "VERSION": "1.0.0",
    'ENUM_NAME_OVERRIDES': {
        'NameEnum': 'ResourceTypeEnum'
    },
    "SERVERS": [
        {
            "url": "http://64.225.122.101",
            "description": "Production server"
        },
        {
            "url": "http://127.0.0.1:8000",
            "description": "Local development server"
        },
    ],
}

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'django.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'obeeomaapp': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# EMAIL CONFIGURATION SETTINGS
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True").lower() in ("true", "1", "t")
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False").lower() in ("true", "1", "t")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "obeeoma256@gmail.com")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "Obeeoma256@gmail.com")
EMAIL_TIMEOUT = int(os.getenv("EMAIL_TIMEOUT", "10"))

# Gmail API settings (optional, for Gmail API instead of SMTP)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://developers.google.com/oauthplayground")

# OAuth Scopes for Gmail API (for the authorization flow)
GMAIL_SCOPES = [
    "https://mail.google.com/",  # Full Gmail access (includes send)
]

AWS_ACCESS_KEY_ID = os.environ.get("DO_SPACES_KEY")
AWS_SECRET_ACCESS_KEY = os.environ.get("DO_SPACES_SECRET")
AWS_STORAGE_BUCKET_NAME = os.environ.get("DO_SPACES_NAME")        # example: "my-space"
AWS_S3_ENDPOINT_URL = os.environ.get("DO_SPACES_ENDPOINT")       # e.g. "https://nyc3.digitaloceanspaces.com"
AWS_S3_REGION_NAME = os.environ.get("DO_SPACES_REGION")          # e.g. "nyc3"
AWS_S3_SIGNATURE_VERSION = "s3v4"

# --- Sana AI / OpenAI configuration ---
# The MentalHealthAI service reads OPENAI_API_KEY / OPENAI_MODEL from settings or the environment.
# Defining them here makes it explicit and avoids "undefined" attribute errors.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")



