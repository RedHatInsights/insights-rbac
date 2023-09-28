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

"""Serializer for Audit Logs."""
from management.models import AuditLogModel
from rest_framework import serializers


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for Audit Log."""

    RESOURCE_CHOICES = (
        ("group", AuditLogModel.GROUP),
        ("role", AuditLogModel.ROLE),
        ("user", AuditLogModel.USER),
        ("permission", AuditLogModel.PERMISSION),
    )
    ACTION_CHOICES = (
        ("delete", AuditLogModel.DELETE),
        ("add", AuditLogModel.ADD),
        ("edit", AuditLogModel.EDIT),
        ("create", AuditLogModel.CREATE),
        ("remove", AuditLogModel.REMOVE),
    )

    requester = serializers.CharField(required=True, max_length=255)
    description = serializers.CharField(required=True, max_length=255)
    resource = serializers.ChoiceField(choices=RESOURCE_CHOICES)
    action = serializers.ChoiceField(choices=ACTION_CHOICES)

    class Meta:
        model = AuditLogModel
        fields = ("requester", "description", "resource", "action")
