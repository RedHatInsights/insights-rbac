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

"""Handler for cross-account request clean up."""
import logging

from django.db.models import Q
from django.utils import timezone
from management.models import Principal

from api.models import CrossAccountRequest, Tenant
from api.serializers import create_tenant_name

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def check_cross_request_expiry():
    """Check if a cross-account requests have expired, tag them if so."""
    expired_cars = []
    cars = CrossAccountRequest.objects.filter(Q(status="pending") | Q(status="approved"))
    logger.info("Running expiry check on %d cross-account requests.", len(cars))
    for car in cars:
        logger.debug("Checking for expiration of cross-account request %s.", car.pk)
        if car.end_date < timezone.now():
            logger.info("Expiring cross-account request with uuid: %s", car.pk)
            car.status = "expired"
            expired_cars.append(car.pk)
            car.save()

    logger.info("Completed clean up of %d cross-account requests, %d expired.", len(cars), len(expired_cars))


def create_cross_principal(target_account, user_id, target_org=None):
    """Create a cross account principal in the target account."""
    # Principal would have the pattern acctxxx-123456.
    principal_name = get_cross_principal_name(target_account, user_id)
    tenant_name = create_tenant_name(target_account)
    associate_tenant = Tenant.objects.get(tenant_name=tenant_name)
    # Create the principal in public schema
    cross_account_principal = create_principal_with_tenant(principal_name, associate_tenant)

    return cross_account_principal


def get_cross_principal_name(target_account, user_id):
    """Get cross-account principal string from account and UID."""
    return f"{target_account}-{user_id}"


def create_principal_with_tenant(principal_name, associate_tenant):
    """Create cross-account principal in tenant."""
    cross_account_principal, _ = Principal.objects.get_or_create(
        username=principal_name, cross_account=True, tenant=associate_tenant
    )
    return cross_account_principal
