#
# Copyright 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""
Django settings for rbac project.

Generated by 'django-admin startproject' using Django 2.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""
import os

import datetime
import sys
import logging
import pytz
import redis

from boto3 import client as boto_client
from corsheaders.defaults import default_headers
from dateutil.parser import parse as parse_dt
from app_common_python import LoadedConfig, KafkaTopics


# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases


from . import database

from .env import ENVIRONMENT

# Sentry monitoring configuration
# Note: Sentry is disabled unless it is explicitly turned on by setting DSN
# Note: Although we are using sentry-sdk we are connecting to Glitchtip DSN

GLITCHTIP_DSN = os.getenv("GLITCHTIP_DSN", "")
if GLITCHTIP_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.redis import RedisIntegration

    sentry_sdk.init(dsn=GLITCHTIP_DSN, integrations=[DjangoIntegration(), RedisIntegration()])
    print("Sentry SDK initialization using Glitchtip was successful!")
else:
    print("GLITCHTIP_DSN was not set, skipping Glitchtip initialization.")

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GIT_COMMIT = ENVIRONMENT.get_value("GIT_COMMIT", default="local-dev")

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# The SECRET_KEY is provided via an environment variable in OpenShift
SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    # safe value used for development when DJANGO_SECRET_KEY might not be set
    "asvuhxowz)zjbo4%7pc$ek1nbfh_-#%$bq_x8tkh=#e24825=5",
)

# SECURITY WARNING: don't run with debug turned on in production!
# Default value: False
DEBUG = False if os.getenv("DJANGO_DEBUG", "False") == "False" else True  # pylint: disable=R1719

ALLOWED_HOSTS = ["*"]

# Application definition

INSTALLED_APPS = [
    # django
    # 'django.contrib.admin',
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third-party
    "rest_framework",
    "django_filters",
    "corsheaders",
    "django_prometheus",
    "django_extensions",
    # local apps
    "api",
    "management",
]

SHARED_APPS = (
    "management",
    "api",
    "django.contrib.contenttypes",
    # 'django.contrib.admin',
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "django_extensions",
)

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "rbac.middleware.DisableCSRF",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "rbac.middleware.IdentityHeaderMiddleware",
    "internal.middleware.InternalIdentityHeaderMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
    "rbac.middleware.ReadOnlyApiMiddleware",
]

DEVELOPMENT = ENVIRONMENT.bool("DEVELOPMENT", default=False)
if DEVELOPMENT:
    MIDDLEWARE.insert(5, "rbac.dev_middleware.DevelopmentIdentityHeaderMiddleware")
# Don't try to go verify Principals against the BOP user service
BYPASS_BOP_VERIFICATION = ENVIRONMENT.bool("BYPASS_BOP_VERIFICATION", default=False)

AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.AllowAllUsersModelBackend"]


ROOT_URLCONF = "rbac.urls"

WSGI_APPLICATION = "rbac.wsgi.application"

DATABASES = {"default": database.config()}

PROMETHEUS_EXPORT_MIGRATIONS = False

# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/


API_PATH_PREFIX = os.getenv("API_PATH_PREFIX", "/")
STATIC_API_PATH_PREFIX = API_PATH_PREFIX
if STATIC_API_PATH_PREFIX != "" and (not STATIC_API_PATH_PREFIX.endswith("/")):
    STATIC_API_PATH_PREFIX = STATIC_API_PATH_PREFIX + "/"

STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATIC_URL = "{}/static/".format(API_PATH_PREFIX.rstrip("/"))

STATICFILES_DIRS = [os.path.join(BASE_DIR, "..", "docs/source/specs")]

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

INTERNAL_IPS = ["127.0.0.1"]

DEFAULT_PAGINATION_CLASS = "api.common.pagination.StandardResultsSetPagination"
DEFAULT_EXCEPTION_HANDLER = "api.common.exception_handler.exception_version_handler"

# django rest_framework settings
REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly"],
    "DEFAULT_PAGINATION_CLASS": DEFAULT_PAGINATION_CLASS,
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "EXCEPTION_HANDLER": DEFAULT_EXCEPTION_HANDLER,
    "ORDERING_PARAM": "order_by",
}

# CW settings
if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False):
    if ENVIRONMENT.bool("CW_NULL_WORKAROUND", default=True):
        CW_AWS_ACCESS_KEY_ID = None
        CW_AWS_SECRET_ACCESS_KEY = None
        CW_AWS_REGION = None
        CW_LOG_GROUP = None
    else:
        CW_AWS_ACCESS_KEY_ID = LoadedConfig.logging.cloudwatch.accessKeyId
        CW_AWS_SECRET_ACCESS_KEY = LoadedConfig.logging.cloudwatch.secretAccessKey
        CW_AWS_REGION = LoadedConfig.logging.cloudwatch.region
        CW_LOG_GROUP = LoadedConfig.logging.cloudwatch.logGroup
else:
    CW_AWS_ACCESS_KEY_ID = ENVIRONMENT.get_value("CW_AWS_ACCESS_KEY_ID", default=None)
    CW_AWS_SECRET_ACCESS_KEY = ENVIRONMENT.get_value("CW_AWS_SECRET_ACCESS_KEY", default=None)
    CW_AWS_REGION = ENVIRONMENT.get_value("CW_AWS_REGION", default="us-east-1")
    CW_LOG_GROUP = ENVIRONMENT.get_value("CW_LOG_GROUP", default="platform-dev")

CW_CREATE_LOG_GROUP = ENVIRONMENT.bool("CW_CREATE_LOG_GROUP", default=False)

LOGGING_FORMATTER = os.getenv("DJANGO_LOG_FORMATTER", "simple")
DJANGO_LOGGING_LEVEL = os.getenv("DJANGO_LOG_LEVEL", "INFO")
RBAC_LOGGING_LEVEL = os.getenv("RBAC_LOG_LEVEL", "INFO")
LOGGING_HANDLERS = os.getenv("DJANGO_LOG_HANDLERS", "console").split(",")
VERBOSE_FORMATTING = "%(levelname)s %(asctime)s %(module)s " "%(process)d %(thread)d %(message)s"

if DEBUG and "ecs" in LOGGING_HANDLERS:
    DEBUG_LOG_HANDLERS = [v for v in LOGGING_HANDLERS if v != "ecs"]
    if DEBUG_LOG_HANDLERS == []:
        DEBUG_LOG_HANDLERS = ["console"]
else:
    DEBUG_LOG_HANDLERS = LOGGING_HANDLERS

LOG_DIRECTORY = os.getenv("LOG_DIRECTORY", BASE_DIR)
DEFAULT_LOG_FILE = os.path.join(LOG_DIRECTORY, "app.log")
LOGGING_FILE = os.getenv("DJANGO_LOG_FILE", DEFAULT_LOG_FILE)

if CW_AWS_ACCESS_KEY_ID:
    LOGGING_HANDLERS += ["watchtower"]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {"format": VERBOSE_FORMATTING},
        "simple": {"format": "[%(asctime)s] %(levelname)s: %(message)s"},
        "ecs_formatter": {"()": "rbac.ECSCustom.ECSCustomFormatter"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": LOGGING_FORMATTER},
        "file": {
            "level": RBAC_LOGGING_LEVEL,
            "class": "logging.FileHandler",
            "filename": LOGGING_FILE,
            "formatter": LOGGING_FORMATTER,
        },
        "ecs": {"class": "logging.StreamHandler", "formatter": "ecs_formatter"},
    },
    "loggers": {
        "django": {"handlers": LOGGING_HANDLERS, "level": DJANGO_LOGGING_LEVEL},
        "django.server": {"handlers": DEBUG_LOG_HANDLERS, "level": DJANGO_LOGGING_LEVEL, "propagate": False},
        "django.request": {"handlers": DEBUG_LOG_HANDLERS, "level": DJANGO_LOGGING_LEVEL, "propagate": False},
        "api": {"handlers": LOGGING_HANDLERS, "level": RBAC_LOGGING_LEVEL},
        "internal": {"handlers": LOGGING_HANDLERS, "level": RBAC_LOGGING_LEVEL},
        "rbac": {"handlers": LOGGING_HANDLERS, "level": RBAC_LOGGING_LEVEL},
        "management": {"handlers": LOGGING_HANDLERS, "level": RBAC_LOGGING_LEVEL},
        "migration_tool": {"handlers": LOGGING_HANDLERS, "level": RBAC_LOGGING_LEVEL},
    },
}

if CW_AWS_ACCESS_KEY_ID:
    NAMESPACE = ENVIRONMENT.get_value("APP_NAMESPACE", default="unknown")

    boto3_logs_client = boto_client(
        "logs",
        region_name=CW_AWS_REGION,
        aws_access_key_id=CW_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=CW_AWS_SECRET_ACCESS_KEY,
    )

    WATCHTOWER_HANDLER = {
        "level": RBAC_LOGGING_LEVEL,
        "class": "watchtower.CloudWatchLogHandler",
        "boto3_client": boto3_logs_client,
        "log_group_name": CW_LOG_GROUP,
        "stream_name": NAMESPACE,
        "formatter": LOGGING_FORMATTER,
        "use_queues": True,
        "create_log_group": CW_CREATE_LOG_GROUP,
    }
    LOGGING["handlers"]["watchtower"] = WATCHTOWER_HANDLER

# Cors Setup
# See https://github.com/ottoyiu/django-cors-headers
CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_HEADERS = default_headers + ("x-rh-identity", "HTTP_X_RH_IDENTITY")

APPEND_SLASH = False

# Celery settings
if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False):
    REDIS_HOST = LoadedConfig.inMemoryDb.hostname
    REDIS_PORT = LoadedConfig.inMemoryDb.port
    REDIS_PASSWORD = LoadedConfig.inMemoryDb.password
else:
    REDIS_HOST = ENVIRONMENT.get_value("REDIS_HOST", default="localhost")
    REDIS_PORT = ENVIRONMENT.get_value("REDIS_PORT", default="6379")
    REDIS_PASSWORD = ENVIRONMENT.get_value("REDIS_PASSWORD", default=None)

REDIS_SSL = REDIS_PASSWORD is not None

ACCESS_CACHE_DB = 1
ACCESS_CACHE_LIFETIME = 10 * 60
ACCESS_CACHE_ENABLED = ENVIRONMENT.bool("ACCESS_CACHE_ENABLED", default=True)
ACCESS_CACHE_CONNECT_SIGNALS = ENVIRONMENT.bool("ACCESS_CACHE_CONNECT_SIGNALS", default=True)

REDIS_MAX_CONNECTIONS = ENVIRONMENT.get_value("REDIS_MAX_CONNECTIONS", default=10)
REDIS_SOCKET_CONNECT_TIMEOUT = ENVIRONMENT.get_value("REDIS_SOCKET_CONNECT_TIMEOUT", default=0.1)
REDIS_SOCKET_TIMEOUT = ENVIRONMENT.get_value("REDIS_SOCKET_TIMEOUT", default=0.1)
REDIS_CACHE_CONNECTION_PARAMS = dict(
    max_connections=REDIS_MAX_CONNECTIONS,
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=ACCESS_CACHE_DB,
    socket_connect_timeout=REDIS_SOCKET_CONNECT_TIMEOUT,
    socket_timeout=REDIS_SOCKET_TIMEOUT,
)

if REDIS_SSL:
    REDIS_CACHE_CONNECTION_PARAMS["connection_class"] = redis.SSLConnection
    REDIS_CACHE_CONNECTION_PARAMS["password"] = REDIS_PASSWORD
    DEFAULT_REDIS_URL = f"rediss://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0?ssl_cert_reqs=required"
else:
    DEFAULT_REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

CELERY_BROKER_URL = ENVIRONMENT.get_value("CELERY_BROKER_URL", default=DEFAULT_REDIS_URL)

ROLE_CREATE_ALLOW_LIST = ENVIRONMENT.get_value("ROLE_CREATE_ALLOW_LIST", default="").split(",")

# Dual write migration configuration
REPLICATION_TO_RELATION_ENABLED = ENVIRONMENT.bool("REPLICATION_TO_RELATION_ENABLED", default=False)
V2_MIGRATION_APP_EXCLUDE_LIST = ENVIRONMENT.get_value("V2_MIGRATION_APP_EXCLUDE_LIST", default="").split(",")
V2_MIGRATION_RESOURCE_EXCLUDE_LIST = ENVIRONMENT.get_value("V2_MIGRATION_RESOURCE_EXCLUDE_LIST", default="").split(",")
V2_BOOTSTRAP_TENANT = ENVIRONMENT.bool("V2_BOOTSTRAP_TENANT", default=False)

# Migration Setup
TENANT_PARALLEL_MIGRATION_MAX_PROCESSES = ENVIRONMENT.int("TENANT_PARALLEL_MIGRATION_MAX_PROCESSES", default=2)
TENANT_PARALLEL_MIGRATION_CHUNKS = ENVIRONMENT.int("TENANT_PARALLEL_MIGRATION_CHUNKS", default=2)

# Seeding Setup
PERMISSION_SEEDING_ENABLED = ENVIRONMENT.bool("PERMISSION_SEEDING_ENABLED", default=True)
ROLE_SEEDING_ENABLED = ENVIRONMENT.bool("ROLE_SEEDING_ENABLED", default=True)
GROUP_SEEDING_ENABLED = ENVIRONMENT.bool("GROUP_SEEDING_ENABLED", default=True)
MAX_SEED_THREADS = ENVIRONMENT.int("MAX_SEED_THREADS", default=None)

try:
    DESTRUCTIVE_SEEDING_OK_UNTIL = parse_dt(
        os.environ.get("RBAC_DESTRUCTIVE_SEEDING_ENABLED_UNTIL", "not-a-real-time")
    )
    if DESTRUCTIVE_SEEDING_OK_UNTIL.tzinfo is None:
        DESTRUCTIVE_SEEDING_OK_UNTIL = DESTRUCTIVE_SEEDING_OK_UNTIL.replace(tzinfo=pytz.UTC)
except ValueError as e:
    DESTRUCTIVE_SEEDING_OK_UNTIL = datetime.datetime(1970, 1, 1, tzinfo=pytz.UTC)

# disable log messages less than CRITICAL when running unit tests.
if len(sys.argv) > 1 and sys.argv[1] == "test" and not ENVIRONMENT.bool("LOG_TEST_OUTPUT", default=False):
    logging.disable(logging.CRITICAL)

# Optionally log all DB queries
if ENVIRONMENT.bool("LOG_DATABASE_QUERIES", default=False):
    LOGGING["loggers"]["django.db.backends"] = {"handlers": ["console"], "level": "DEBUG", "propagate": False}

# Internal API Configuration
INTERNAL_API_PATH_PREFIXES = ["/_private/"]

try:
    INTERNAL_DESTRUCTIVE_API_OK_UNTIL = parse_dt(
        os.environ.get("RBAC_DESTRUCTIVE_API_ENABLED_UNTIL", "not-a-real-time")
    )
    if INTERNAL_DESTRUCTIVE_API_OK_UNTIL.tzinfo is None:
        INTERNAL_DESTRUCTIVE_API_OK_UNTIL = INTERNAL_DESTRUCTIVE_API_OK_UNTIL.replace(tzinfo=pytz.UTC)
except ValueError as e:
    INTERNAL_DESTRUCTIVE_API_OK_UNTIL = datetime.datetime(1970, 1, 1, tzinfo=pytz.UTC)

KAFKA_ENABLED = ENVIRONMENT.get_value("KAFKA_ENABLED", default=False)
MOCK_KAFKA = ENVIRONMENT.get_value("MOCK_KAFKA", default=False)

NOTIFICATIONS_ENABLED = ENVIRONMENT.get_value("NOTIFICATIONS_ENABLED", default=False)
NOTIFICATIONS_RH_ENABLED = ENVIRONMENT.get_value("NOTIFICATIONS_RH_ENABLED", default=False)
NOTIFICATIONS_TOPIC = ENVIRONMENT.get_value("NOTIFICATIONS_TOPIC", default=None)

EXTERNAL_SYNC_TOPIC = ENVIRONMENT.get_value("EXTERNAL_SYNC_TOPIC", default=None)
EXTERNAL_CHROME_TOPIC = ENVIRONMENT.get_value("EXTERNAL_CHROME_TOPIC", default=None)

# if we don't enable KAFKA we can't use the notifications
if not KAFKA_ENABLED:
    NOTIFICATIONS_ENABLED = False
    NOTIFICATIONS_RH_ENABLED = False
    NOTIFICATIONS_TOPIC = None

# Kafka settings
KAFKA_SERVERS = []

if KAFKA_ENABLED:
    KAFKA_AUTH = {}
    if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False):
        kafka_brokers = LoadedConfig.kafka.brokers
        broker_index = 0
        if not kafka_brokers:
            raise ValueError("No kafka brokers available")
        for broker in kafka_brokers:
            if broker and broker.hostname != None and broker.port != None:
                kafka_host = broker.hostname
                kafka_port = broker.port
                kafka_info = f"{kafka_host}:{kafka_port}"
                KAFKA_SERVERS.append(kafka_info)

                if broker.authtype != None and broker.authtype.value == "sasl":
                    broker_index = kafka_brokers.index(broker)
            else:
                raise ValueError("Broker value is none. It does not contain hostname, port, or authtype")
        try:
            if kafka_brokers[broker_index].authtype.value == "sasl":
                KAFKA_AUTH.update(
                    {
                        "bootstrap_servers": KAFKA_SERVERS,
                        "sasl_plain_username": kafka_brokers[broker_index].sasl.username,
                        "sasl_plain_password": kafka_brokers[broker_index].sasl.password,
                        "sasl_mechanism": kafka_brokers[broker_index].sasl.saslMechanism.upper(),
                        "security_protocol": kafka_brokers[broker_index].sasl.securityProtocol.upper(),
                    }
                )
            if kafka_brokers[broker_index].cacert:
                KAFKA_AUTH["ssl_cafile"] = LoadedConfig.kafka_ca()
        except AttributeError:
            KAFKA_AUTH = {}
    else:
        kafka_host = "localhost"
        kafka_port = "9092"
        kafka_info = f"{kafka_host}:{kafka_port}"
        KAFKA_SERVERS.append(kafka_info)

    clowder_notifications_topic = KafkaTopics.get(NOTIFICATIONS_TOPIC)
    if clowder_notifications_topic:
        NOTIFICATIONS_TOPIC = clowder_notifications_topic.name

    clowder_sync_topic = KafkaTopics.get(EXTERNAL_SYNC_TOPIC)
    if clowder_sync_topic:
        EXTERNAL_SYNC_TOPIC = clowder_sync_topic.name

    clowder_chrome_topic = KafkaTopics.get(EXTERNAL_CHROME_TOPIC)
    if clowder_chrome_topic:
        EXTERNAL_CHROME_TOPIC = clowder_chrome_topic.name

# BOP TLS settings
if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False) and ENVIRONMENT.bool("USE_CLOWDER_CA_FOR_BOP", default=False):
    BOP_CLIENT_CERT_PATH = LoadedConfig.tlsCAPath
else:
    BOP_CLIENT_CERT_PATH = os.path.join(BASE_DIR, "management", "principal", "certs", "client.pem")

# IT settings for the service accounts fetching.
IT_BYPASS_PERMISSIONS_MODIFY_SERVICE_ACCOUNTS = ENVIRONMENT.bool(
    "IT_BYPASS_PERMISSIONS_MODIFY_SERVICE_ACCOUNTS", default=False
)
IT_BYPASS_IT_CALLS = ENVIRONMENT.bool("IT_BYPASS_IT_CALLS", default=False)
IT_BYPASS_TOKEN_VALIDATION = ENVIRONMENT.bool("IT_BYPASS_TOKEN_VALIDATION", default=False)
IT_SERVICE_BASE_PATH = ENVIRONMENT.get_value("IT_SERVICE_BASE_PATH", default="/auth/realms/redhat-external/apis")
IT_SERVICE_HOST = ENVIRONMENT.get_value("IT_SERVICE_HOST", default="localhost")
IT_SERVICE_PORT = ENVIRONMENT.int("IT_SERVICE_PORT", default="443")
IT_SERVICE_PROTOCOL_SCHEME = ENVIRONMENT.get_value("IT_SERVICE_PROTOCOL_SCHEME", default="https")
IT_SERVICE_TIMEOUT_SECONDS = ENVIRONMENT.int("IT_SERVICE_TIMEOUT_SECONDS", default=10)
IT_TOKEN_JKWS_CACHE_LIFETIME = ENVIRONMENT.int("IT_TOKEN_JKWS_CACHE_LIFETIME", default=28800)

PRINCIPAL_USER_DOMAIN = ENVIRONMENT.get_value("PRINCIPAL_USER_DOMAIN", default="localhost")

# Settings for enabling/disabling deletion in principal cleanup job via UMB
PRINCIPAL_CLEANUP_DELETION_ENABLED_UMB = ENVIRONMENT.bool("PRINCIPAL_CLEANUP_DELETION_ENABLED_UMB", default=False)
PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB = ENVIRONMENT.bool("PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB", default=False)
UMB_JOB_ENABLED = ENVIRONMENT.bool("UMB_JOB_ENABLED", default=True)
UMB_HOST = ENVIRONMENT.get_value("UMB_HOST", default="localhost")
UMB_PORT = ENVIRONMENT.get_value("UMB_PORT", default="61612")
# Service account name
SA_NAME = ENVIRONMENT.get_value("SA_NAME", default="nonprod-hcc-rbac")

RELATION_API_SERVER = ENVIRONMENT.get_value("RELATION_API_SERVER", default="localhost:9000")
ENV_NAME = ENVIRONMENT.get_value("ENV_NAME", default="stage")

# Versioned API settings
V2_APIS_ENABLED = ENVIRONMENT.bool("V2_APIS_ENABLED", default=False)
V2_READ_ONLY_API_MODE = ENVIRONMENT.bool("V2_READ_ONLY_API_MODE", default=False)
READ_ONLY_API_MODE = ENVIRONMENT.get_value("READ_ONLY_API_MODE", default=False)
