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

"""Serializer for group management."""
from management.group.model import Group
from management.principal.serializer import PrincpalInputSerializer, PrincpalSerializer
from rest_framework import serializers


class GroupInputSerializer(serializers.ModelSerializer):
    """Serializer for Group input model."""

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = ('uuid', 'name')


class GroupSerializer(serializers.ModelSerializer):
    """Serializer for the Group model."""

    principals = PrincpalSerializer(read_only=True, many=True)

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = ('uuid', 'name', 'principals')


class GroupPrincipalInputSerializer(serializers.Serializer):
    """Serializer for adding principals to a group."""

    principals = PrincpalInputSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        fields = ('principals',)
