"""Tenant management business logic."""

from django.conf import settings
from management.role.relation_api_dual_write_handler import RelationReplicator
from management.tenant_service.tenant_service import TenantBootstrapService
from management.tenant_service.v1 import V1TenantBootstrapService
from management.tenant_service.v2 import V2TenantBootstrapService


def get_tenant_bootstrap_service(replicator: RelationReplicator) -> "TenantBootstrapService":
    """Get a UserBootstrapService instance based on settings."""
    return V2TenantBootstrapService(replicator) if settings.V2_BOOTSTRAP_TENANT else V1TenantBootstrapService()
