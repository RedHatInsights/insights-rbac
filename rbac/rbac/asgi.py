"""ASGI config."""
import os

import django

from .env import ENVIRONMENT

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")
django.setup()

from channels.auth import AuthMiddlewareStack  # noqa: E402, I202
from channels.http import AsgiHandler  # noqa: E402
from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402

import rbac.urls  # noqa: E402

application = ProtocolTypeRouter(
    {"http": AsgiHandler(), "websocket": AuthMiddlewareStack(URLRouter(rbac.urls.websocket_urlpatterns))}
)

USE_OTLP = ENVIRONMENT.bool("OTLP_ENABLED", default=False)
if USE_OTLP:
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

    application = OpenTelemetryMiddleware(application)
