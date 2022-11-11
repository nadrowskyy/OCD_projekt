"""
Django settings for scheduler_project project.

Generated by 'django-admin startproject' using Django 3.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.1/ref/settings/
"""

from pathlib import Path
import os
import pymysql
from google.oauth2 import service_account
import json

pymysql.install_as_MySQLdb()


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ['SECRET_KEY']
# VARIABLES FOR DECODING/ENCODING EMAIL PASSWORD

# SECURITY WARNING: don't run with debug turned on in production!
if os.environ['DEBUG'] == "1":
    DEBUG = True
else:
    DEBUG = False

ALLOWED_HOSTS = ['*']

#DISABLE_COLLECTSTATIC=1

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'schedule',
    'crispy_forms',
    'mathfilters'
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

MIDDLEWARE_CLASSES = (
    # Simplified static file serving.
    # https://warehouse.python.org/project/whitenoise/
    'whitenoise.middleware.WhiteNoiseMiddleware',)


ROOT_URLCONF = 'scheduler_project.urls'

# Templates

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
                'django.template.context_processors.media',

            ],
        },
    },
]

# Wgsi application

WSGI_APPLICATION = 'scheduler_project.wsgi.application'

# Database backend details

DATABASES = {
    'default': {
        'ENGINE': os.environ['DB_ENGINE'],
        'HOST': os.environ['DB_HOST'],
        'PORT': os.environ['DB_PORT'],
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        # 'ENGINE': os.environ['DB_ENGINE'],
        # 'HOST': os.environ['DB_HOST'],
        # 'PORT': os.environ['DB_PORT'],
        # 'NAME': os.environ['DB_NAME'],
        # 'USER': os.environ['DB_USER'],
        # 'PASSWORD': os.environ['DB_PASSWORD'],
        'OPTIONS': {
            'autocommit': True,
        },
    }
}

# Static storage config

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static")
]

# Media storage config

DEFAULT_FILE_STORAGE = os.environ['DEFAULT_FILE_STORAGE']
GS_PROJECT_ID = os.environ['GS_PROJECT_ID']
GS_BUCKET_NAME = os.environ['GS_BUCKET_NAME']
MEDIA_URL = os.environ['MEDIA_URL']



#GS_CREDENTIALS = service_account.Credentials.from_service_account_file(
#    os.path.join(BASE_DIR, 'dev-airlock-366820-871bc63cca31.json')
#)

GS_CREDENTIALS = service_account.Credentials.from_service_account_file(
    os.path.join(BASE_DIR, os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
)


# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


EMAIL_HOST = os.environ['EMAIL_HOST']
EMAIL_PORT = int(os.environ['EMAIL_PORT'])
EMAIL_HOST_USER = os.environ['EMAIL_HOST_USER']
EMAIL_HOST_PASSWORD = os.environ['EMAIL_HOST_PASSWORD']
EMAIL_USE_TLS = True

# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

LANGUAGE_CODE = 'pl-pl'

TIME_ZONE = 'Europe/Warsaw'

USE_I18N = True

USE_L10N = True

USE_TZ = False
