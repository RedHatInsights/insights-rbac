import json
import socket
import django

from ecs_logging import StdlibFormatter


class ECSCustomFormatter(StdlibFormatter):
    def format_to_ecs(self, record):
        if record.request:
            if isinstance(record.request, socket.socket):
                # TODO: format socket object in loggable manner and return
                return "Socket Object, can't log"
            if isinstance(record.request, django.core.handlers.wsgi.WSGIRequest):
                # TODO: format request object in loggable manner and return
                return "WSGI Request, can't log"

        result = super().format_to_ecs(record)

        return result
