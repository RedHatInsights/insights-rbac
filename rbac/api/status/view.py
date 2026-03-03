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

"""View for server status."""

from rest_framework import permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from api.status.model import Status
from api.status.serializer import StatusSerializer
from management.group.model import Group


def _is_seeding_complete():
    """Check if seeding has been completed (by worker or init container).

    We verify seeding by checking for the platform default group (last step in seeding).
    """
    try:
        return Group.objects.public_tenant_only().filter(platform_default=True).exists()
    except Exception:
        return False


@api_view(["GET", "HEAD"])
@permission_classes((permissions.AllowAny,))
def ready(request):
    """Readiness probe: returns 200 when service can accept traffic.

    When the service does not run seeding (MIGRATE_AND_SEED_ON_INIT=False),
    returns 503 until the worker has completed seeding. This prevents the
    service from receiving traffic before roles/groups/permissions exist.
    """
    if _is_seeding_complete():
        return Response({"status": "ready"}, status=200)
    return Response({"status": "waiting for seeding"}, status=503)


@api_view(["GET", "HEAD"])
@permission_classes((permissions.AllowAny,))
def status(request):
    """Provide the server status information.

    @api {get} /api/v1/status/ Request server status
    @apiName GetStatus
    @apiGroup Status
    @apiVersion 1.0.0
    @apiDescription Request server status.

    @apiSuccess {Number} api_version The version of the API.
    @apiSuccess {String} commit  The commit hash of the code base.
    @apiSuccess {Object} modules  The code modules found on the server.
    @apiSuccess {Object} platform_info  The server platform information.
    @apiSuccess {String} python_version  The version of python on the server.
    @apiSuccess {String} server_address  The address of the server.
    @apiSuccessExample {json} Success-Response:
        HTTP/1.1 200 OK
        {
            "api_version": 1,
            "commit": "178d2ea",
            "server_address": "127.0.0.1:8000",
            "platform_info": {
                "system": "Darwin",
                "node": "node-1.example.com",
                "release": "17.5.0",
                "version": "Darwin Kernel Version 17.5.0",
                "machine": "x86_64",
                "processor": "i386"
                },
            "python_version": "3.6.1",
            "modules": {
                "coverage": "4.5.1",
                "coverage.version": "4.5.1",
                "coverage.xmlreport": "4.5.1",
                "cryptography": "2.0.3",
                "ctypes": "1.1.0",
                "ctypes.macholib": "1.0",
                "decimal": "1.70",
                "django": "1.11.5",
                "django.utils.six": "1.10.0",
                "django_filters": "1.0.4",
                "http.server": "0.6"
                }
        }
    """
    status_info = Status()
    serializer = StatusSerializer(status_info)
    server_info = serializer.data
    return Response(server_info)
