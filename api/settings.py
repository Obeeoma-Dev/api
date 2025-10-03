# import os

# from pathlib import Path
# from urllib.parse import urlparse, parse_qsl
# from dotenv import load_dotenv

# load_dotenv()

# BASE_DIR = Path(__file__).resolve().parent.parent

# # Security
# SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
# DEBUG = os.getenv("DEBUG", "true").lower() in ("true", "1", "t")
# ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
# PORT = os.getenv("PORT", "8000")

# # Database
# tmpPostgres = urlparse(os.getenv('DATABASE_URL', ''))

# # DATABASES = {
# #     'default': {
# #         'ENGINE': 'django.db.backends.postgresql',
# #         'NAME': tmpPostgres.path.lstrip('/'),
# #         'USER': tmpPostgres.username,
# #         'PASSWORD': tmpPostgres.password,
# #         'HOST': tmpPostgres.hostname,
# #         'PORT': tmpPostgres.port or 5432,
# #         'OPTIONS': {
# #             'sslmode': 'require',
# #             **dict(parse_qsl(tmpPostgres.query)),
# #         },
# #     }
# # }

# # Database
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': os.getenv('PGDATABASE', ''),
#         'USER': os.getenv('PGUSER', ''),
#         'PASSWORD': os.getenv('PGPASSWORD', ''),
#         'HOST': os.getenv('PGHOST', ''),
#         'PORT': os.getenv('PGPORT', '5432'),
#         'OPTIONS': {
#             'sslmode': os.getenv('PGSSLMODE', '5432'),
#         },
#     }
# }


# INSTALLED_APPS = [
#     'django.contrib.admin',
#     'django.contrib.auth',
#     'django.contrib.contenttypes',
#     'django.contrib.sessions',
#     'django.contrib.messages',
#     'django.contrib.staticfiles',
#     'obeeomaapp',
#     'rest_framework',

#     'rest_framework_simplejwt',
#     'django_extensions',


#     'drf_yasg',


# ]

# #  Middleware
# MIDDLEWARE = [
#     "django.middleware.security.SecurityMiddleware",
#     'whitenoise.middleware.WhiteNoiseMiddleware',
#     "whitenoise.middleware.WhiteNoiseMiddleware",
#     "django.contrib.sessions.middleware.SessionMiddleware",
#     "django.middleware.common.CommonMiddleware",
#     "django.middleware.csrf.CsrfViewMiddleware",
#     "django.contrib.auth.middleware.AuthenticationMiddleware",
#     "django.contrib.messages.middleware.MessageMiddleware",
#     "django.middleware.clickjacking.XFrameOptionsMiddleware",
# ]
# # Media files
# MEDIA_URL = '/media/'
# MEDIA_ROOT = BASE_DIR / 'media'


# ROOT_URLCONF = "api.urls"

# TEMPLATES = [
#     {
#         "BACKEND": "django.template.backends.django.DjangoTemplates",
#         "DIRS": [],
#         "APP_DIRS": True,
#         "OPTIONS": {
#             "context_processors": [
#                 "django.template.context_processors.request",
#                 "django.contrib.auth.context_processors.auth",
#                 "django.contrib.messages.context_processors.messages",
#             ],
#         },
#     },
# ]

# WSGI_APPLICATION = "api.wsgi.application"


# AUTH_PASSWORD_VALIDATORS = [
#     {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
#     {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
#     {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
#     {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
# ]

# LANGUAGE_CODE = "en-us"
# TIME_ZONE = "UTC"
# USE_I18N = True
# USE_TZ = True

# STATIC_ROOT = BASE_DIR / "staticfiles"
# STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
# STATIC_URL = "static/"

# AUTH_USER_MODEL = "obeeomaapp.User"
# DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# LOGIN_URL = "/login/"
# LOGIN_REDIRECT_URL = "/overview/"

# REST_FRAMEWORK = {
#     "DEFAULT_AUTHENTICATION_CLASSES": (
#         "rest_framework_simplejwt.authentication.JWTAuthentication",
#     ),
#     "DEFAULT_PERMISSION_CLASSES": [
#         "rest_framework.permissions.IsAuthenticated",
#     ],
#     "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
# }

# SPECTACULAR_SETTINGS = {
# 'TITLE': 'My API',
#     'DESCRIPTION': 'API documentation',
#     'VERSION': '1.0.0',


# }
import os

from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
PORT = os.getenv("PORT", "8000")
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
# Database
tmpPostgres = urlparse(os.getenv("DATABASE_URL", ""))

import os

DATABASES = {
        "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("PGDATABASE", "neondb"),
        "USER": os.environ.get("PGUSER", "neondb_owner"),
        "PASSWORD": os.environ.get("PGPASSWORD"),
        "HOST": os.environ.get("PGHOST"),
        "PORT": os.environ.get("PGPORT", "5432"),
        "OPTIONS": {
            "sslmode": os.environ.get("PGSSLMODE", "require"),
        },
        "CONN_MAX_AGE": 600,  # Connection pooling (10 minutes)
        "CONN_HEALTH_CHECKS": True,  # Check connection health before reusing
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
    "django_extensions",
    "drf_yasg",
    "drf_spectacular",
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
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
        "DIRS": [],
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

SPECTACULAR_SETTINGS = {
    "TITLE": "My API",
    "DESCRIPTION": "API documentation",
    "VERSION": "1.0.0",
}
