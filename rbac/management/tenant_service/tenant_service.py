"""Common objects for tenant services."""

import logging
from typing import NamedTuple, Optional, Protocol

from management.principal.model import Principal
from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace

from api.models import Tenant, User

logger = logging.getLogger(__name__)


def _ensure_principal_with_user_id_in_tenant(user: User, tenant: Tenant, upsert: bool = False):
    created = False
    principal = None

    if upsert:
        principal, created = Principal.objects.get_or_create(
            username=user.username,
            tenant=tenant,
            defaults={"user_id": user.user_id},
        )
    else:
        try:
            principal = Principal.objects.get(username=user.username, tenant=tenant)
        except Principal.DoesNotExist:
            pass
        except Principal.MultipleObjectsReturned:
            logger.warning(
                f"Multiple principals returned for the same username. username={user.username} org_id={tenant.org_id}"
            )

    if not created and principal and principal.user_id != user.user_id:
        principal.user_id = user.user_id
        principal.save()


class BootstrappedTenant(NamedTuple):
    """Tenant information."""

    tenant: Tenant
    mapping: Optional[TenantMapping]
    default_workspace: Optional[Workspace] = None
    root_workspace: Optional[Workspace] = None


class TenantBootstrapService(Protocol):
    """Service for bootstrapping users in tenants."""

    def update_user(
        self,
        user: User,
        upsert: bool = False,
        bootstrapped_tenant: Optional[BootstrappedTenant] = None,
        ready_tenant: bool = True,
    ) -> Optional[BootstrappedTenant]:
        """Bootstrap a user in a tenant."""
        ...

    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        ...
