#
# Copyright 2026 Red Hat, Inc.
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
"""Contains the API for tenants opting into V2."""

from typing import Optional

from management.atomic_transactions import atomic_with_retry
from management.permissions import AdminAccessPermission
from management.tenant_mapping.model import TenantMapping
from management.tenant_mapping.v2_activation import set_v2_opt_in_state
from management.tenant_mapping.v2_eligibility import OptInEligibleState, OptInIneligibleState, check_v2_eligibility
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from api.models import Tenant


class _OptInPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if view.action == "status":
            return True

        return AdminAccessPermission().has_permission(request, view)


class _OptInRequestSerializer(serializers.Serializer):
    v2_opted_in = serializers.BooleanField(required=False, allow_null=True)

    def to_internal_value(self, data):
        result = super().to_internal_value(data)

        # DRF treats an absent v2_opted_in as None (since allow_null is True) then, *in contradiction with its
        # documentation*, calls validate_v2_opted_in if defined. Since validate_v2_opted_in can't distinguish between
        # an explicit null and an absent value, we have to this manually here.
        if ("v2_opted_in" in data) and (result["v2_opted_in"] is not True):
            raise serializers.ValidationError({"v2_opted_in": "v2_opted_in, if present, can only be set to true"})

        return result


class _OptInIneligibleRoleSerializer(serializers.Serializer):
    uuid = serializers.UUIDField()
    name = serializers.CharField()
    ineligible_applications = serializers.ListSerializer(child=serializers.CharField())

    def to_representation(self, instance):
        return {
            "uuid": str(instance.role.uuid),
            "name": instance.role.name,
            "ineligible_applications": list(sorted(instance.ineligible_applications)),
        }


class _OptInIneligibleGroupSerializer(serializers.Serializer):
    uuid = serializers.UUIDField()
    name = serializers.CharField()
    ineligible_system_roles = _OptInIneligibleRoleSerializer(many=True)

    def to_representation(self, instance):
        return {
            "uuid": str(instance.group.uuid),
            "name": instance.group.name,
            "ineligible_system_roles": self.fields["ineligible_system_roles"].to_representation(
                instance.ineligible_system_roles
            ),
        }


class _OptInIneligibilitySerializer(serializers.Serializer):
    bootstrapped = serializers.BooleanField()
    ineligible_custom_roles = _OptInIneligibleRoleSerializer(many=True)
    ineligible_groups = _OptInIneligibleGroupSerializer(many=True)

    def to_representation(self, instance):
        result = super().to_representation(instance)
        result["eligible"] = False

        return result


class OptInViewSet(ViewSet):
    """API for updating a tenant's V2 opt-in state."""

    permission_classes = (_OptInPermission,)

    def _state_response_for(self, tenant: Tenant, headers: Optional[dict[str, str]] = None):
        tenant_mapping = TenantMapping.objects.filter(tenant=tenant).first()

        if headers is None:
            headers = {}

        # A non-bootstrapped tenant cannot be opted into V2.
        if tenant_mapping is None:
            return Response({"v2_opted_in": False}, headers=headers)

        return Response({"v2_opted_in": tenant_mapping.v2_opted_in_at is not None}, headers=headers)

    def _format_eligibility_data(self, eligibility: OptInEligibleState | OptInIneligibleState):
        if isinstance(eligibility, OptInEligibleState):
            return {"eligible": True}

        if not isinstance(eligibility, OptInIneligibleState):
            raise AssertionError(f"Unexpected eligibility: {eligibility!r}")

        return _OptInIneligibilitySerializer(eligibility).data

    def status(self, request):
        """Get the current opt-in state of the requestor's tenant."""
        return self._state_response_for(request.tenant, headers={"Cache-Control": "max-age=120, private"})

    @atomic_with_retry(retries=5)
    def partial_update(self, request):
        """(Possibly) update the requestor's tenant's V2 opt-in state."""
        serializer = _OptInRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        requested_state = serializer.validated_data.get("v2_opted_in")

        if requested_state is None:
            # We've not been asked to opt the tenant in, so we have nothing to do.
            return self._state_response_for(request.tenant)

        if requested_state is not True:
            raise AssertionError("Validation should have rejected v2_opted_in being false")

        eligibility_result = check_v2_eligibility(request.tenant)

        if not isinstance(eligibility_result, OptInEligibleState):
            return Response(self._format_eligibility_data(eligibility_result), status.HTTP_422_UNPROCESSABLE_ENTITY)

        set_v2_opt_in_state(request.tenant, True)
        return self._state_response_for(request.tenant)

    @atomic_with_retry(retries=5)
    def eligibility(self, request):
        """Determine whether the requestor's tenant can be opted into V2."""
        result = check_v2_eligibility(request.tenant)
        return Response(self._format_eligibility_data(result), status.HTTP_200_OK)
