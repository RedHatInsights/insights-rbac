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
from prometheus_client import Counter, Summary
from tenant_schemas.utils import tenant_context

from api.models import CrossAccountRequest, Tenant
from api.serializers import create_schema_name

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

# Create processing time metric
PROCESSING_TIME = Summary(
    "cross_account_expiry_processing_second", "Time spent checking and expiring cross-account requests"
)
PROCESSING_COUNT = Counter(
    "cross_account_expiration_calls", "Number of times cross-account request expiration check has run"
)


@PROCESSING_TIME.time()
def check_cross_request_expiry():
    """Check if a cross-account requests have expired, tag them if so."""
    with tenant_context(Tenant.objects.get(schema_name="public")):
        expired_cars = []
        cars = CrossAccountRequest.objects.filter(Q(status="pending") | Q(status="approved"))
        logger.info("Running expiry check on %d cross-account requests.", len(cars))
        for car in cars:
            target_account = car.target_account
            user_id = car.user_id
            logger.debug("Checking for expiration of cross-account request %s.", car.pk)
            if car.end_date < timezone.now():
                logger.info("Expiring cross-account request with uuid: %s", car.pk)
                if car.status == "approved":
                    try:
                        remove_cross_principal(target_account, user_id)
                    except Exception as e:
                        logger.warning(f"Error deleting cross-account principal {target_account}-{user_id}: ", e)
                car.status = "expired"
                expired_cars.append(car.pk)
                car.save()

        PROCESSING_COUNT.inc()
        logger.info(
            "Completed clean up of %d cross-account requests, %d expired.", len(cars), len(expired_cars),
        )


def create_cross_principal(target_account, user_id):
    """Create a cross account principal in the target account."""
    # Principal would have the pattern acctxxx-123456.
    principal_name = get_cross_principal_name(target_account, user_id)
    tenant_schema = create_schema_name(target_account)
    with tenant_context(Tenant.objects.get(schema_name=tenant_schema)):
        cross_account_principal = Principal.objects.get_or_create(username=principal_name, cross_account=True)

    return cross_account_principal


def remove_cross_principal(target_account, user_id):
    """Remove a cross account principal in the target account."""
    # Principal has the pattern acctxxx-123456.
    principal_name = get_cross_principal_name(target_account, user_id)
    tenant_schema = create_schema_name(target_account)
    with tenant_context(Tenant.objects.get(schema_name=tenant_schema)):
        princ = Principal.objects.get(username__iexact=principal_name)
        if princ:
            logger.info(f"Removing cross-account principal {principal_name} from tenant {target_account}")
            princ.delete()


def get_cross_principal_name(target_account, user_id):
    """Get cross-account principal string from account and UID."""
    return f"{target_account}-{user_id}"
