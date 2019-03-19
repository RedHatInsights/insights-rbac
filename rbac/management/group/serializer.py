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
from rest_framework.validators import UniqueValidator


class GroupInputSerializer(serializers.ModelSerializer):
    """Serializer for Group input model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True,
                                 max_length=150,
                                 validators=[UniqueValidator(queryset=Group.objects.all())])
    description = serializers.CharField(allow_null=True, required=False)
    principalCount = serializers.IntegerField(read_only=True)
    policyCount = serializers.IntegerField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = ('uuid', 'name', 'description',
                  'principalCount', 'policyCount',
                  'created', 'modified')


class GroupSerializer(serializers.ModelSerializer):
    """Serializer for the Group model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    principals = PrincpalSerializer(read_only=True, many=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = ('uuid', 'name', 'description', 'principals', 'created', 'modified')


class GroupPrincipalInputSerializer(serializers.Serializer):
    """Serializer for adding principals to a group."""

    principals = PrincpalInputSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        fields = ('principals',)
