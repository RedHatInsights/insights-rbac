#
# Copyright 2020 Red Hat, Inc.
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

"""Serializer for CrossAccountRequest."""
from rest_framework import serializers

from .model import CrossAccountRequest


class CrossAccountRequestSerializer(serializers.ModelSerializer):
    """Serializer for the cross access request model."""

    request_id = serializers.UUIDField(read_only=True)
    target_account = serializers.CharField(max_length=15)
    user_id = serializers.CharField(max_length=15)
    start_date = serializers.DateTimeField(format="%d %b %Y")
    end_date = serializers.DateTimeField(format="%d %b %Y")
    created = serializers.DateTimeField(format="%d %b %Y, %H:%M UTC")
    status = serializers.CharField(max_length=10)

    class Meta:
        """Metadata for the serializer."""

        model = CrossAccountRequest
        fields = ("request_id", "target_account", "user_id", "start_date", "end_date", "created", "status")
