#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""API models for import organization."""
from base64 import b64decode
from json import loads as json_loads

from django.db import transaction
from django.utils.translation import gettext as _
from rest_framework import serializers

from api.common import RH_IDENTITY_HEADER
from api.models import Tenant, User
from api.status.serializer import StatusSerializer  # noqa: F401


def error_obj(key, message):
    """Create an error object."""
    error = {
        key: [_(message)]
    }
    return error


def extract_header(request, header):
    """Extract and decode json header.

    Args:
        request(object): The incoming request
        header(str): The header to decode
    Returns:
        Encoded(str): Base64 header
        Decoded(dict): Identity dictionary
    """
    rh_auth_header = request.META[header]
    decoded_rh_auth = b64decode(rh_auth_header)
    json_rh_auth = json_loads(decoded_rh_auth)
    return (rh_auth_header, json_rh_auth)


def create_schema_name(account):
    """Create a database schema name."""
    return f'acct{account}'


def _create_user(username, email, tenant):
    """Create a user."""
    user = User(username=username,
                email=email,
                tenant=tenant)
    user.save()
    return user


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the User model."""

    class Meta:
        """Metadata for the serializer."""

        model = User
        fields = ('uuid', 'username', 'email')

    @transaction.atomic
    def create(self, validated_data):
        """Create a user from validated data."""
        user = None
        tenant = None
        request = self.context.get('request')
        if request and hasattr(request, 'META'):
            _, json_rh_auth = extract_header(request, RH_IDENTITY_HEADER)
            if (json_rh_auth and 'identity' in json_rh_auth and  # noqa: W504
                'account_number' in json_rh_auth['identity']):
                account = json_rh_auth['identity']['account_number']
            if account:
                schema_name = create_schema_name(account)
                try:
                    tenant = Tenant.objects.get(schema_name=schema_name)
                except Tenant.DoesNotExist:
                    tenant = Tenant(schema_name=schema_name)
                    tenant.save()
                    tenant = Tenant.objects.get(schema_name=schema_name)
            else:
                key = 'detail'
                message = 'Tenant for requesting user could not be found.'
                raise serializers.ValidationError(error_obj(key, message))

        user = _create_user(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            tenant=tenant)

        return user
