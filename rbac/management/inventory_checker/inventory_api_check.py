#
# Copyright 2024 Red Hat, Inc.
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

"""Inventory checker class which checks assignments on Inventory API."""


import logging
from typing import List, Union

from django.conf import settings
from google.protobuf import json_format
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.inventory.v1beta2 import (
    inventory_service_pb2_grpc,
    reporter_reference_pb2,
    resource_reference_pb2,
    subject_reference_pb2,
)
from kessel.inventory.v1beta2.check_request_pb2 import CheckRequest
from management.cache import JWTCache
from management.utils import create_client_channel

jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class InventoryApiBaseChecker:
    """Base class used for assignment checks on inventory api."""

    def check_inventory_core(self, checks: Union[CheckRequest, List[CheckRequest]]) -> bool:
        """
        Core method to check relation(s) via gRPC.

        Accepts either a single check request or list of check requests.
        """
        token = jwt_manager.get_jwt_from_redis()

        if isinstance(checks, CheckRequest):
            checks = [checks]

            with create_client_channel(settings.INVENTORY_API_SERVER) as channel:
                stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)
                metadata = [("authorization", f"Bearer {token}")]

                responses = [stub.Check(req, metadata=metadata) for req in checks]
                return all(self._is_allowed(res) for res in responses)
        return False

    def _is_allowed(self, response):
        response_dict = json_format.MessageToDict(response)
        return response_dict.get("allowed", "") != "ALLOWED_FALSE"


class GroupPrincipalInventoryChecker(InventoryApiBaseChecker):
    """Subclass to check group principal relations are correct on inventory api."""

    def check_relationships(self, relationships):
        """Core logic to check group principal relations are correct."""
        inventory_relation_assignments = {"group_uuid": "", "principal_relations": []}
        for r in relationships:
            # Build the check request
            check_request = CheckRequest(
                object=resource_reference_pb2.ResourceReference(
                    resource_id=r.resource.id,
                    resource_type=r.resource.type.name,
                    reporter=reporter_reference_pb2.ReporterReference(type=r.resource.type.namespace),
                ),
                relation=r.relation,
                subject=subject_reference_pb2.SubjectReference(
                    resource=resource_reference_pb2.ResourceReference(
                        resource_id=r.subject.subject.id,
                        resource_type=r.subject.subject.type.name,
                        reporter=reporter_reference_pb2.ReporterReference(type=r.subject.subject.type.namespace),
                    )
                ),
            )
            relation_exists = self.check_inventory_core(check_request)
            inventory_relation_assignments["group_uuid"] = r.resource.id
            inventory_relation_assignments["principal_relations"].append(
                {"id": r.subject.subject.id, "relation_exists": relation_exists}
            )
            if not relation_exists:
                logger.warning(
                    f"Relation missing: User ID {r.subject.subject.id} is not associated with Group ID {r.resource.id}"
                )
        return inventory_relation_assignments


class BootstrappedTenantInventoryChecker(InventoryApiBaseChecker):
    """Subclass to check bootstrapped tenants are correct on inventory api."""

    def check_bootstrapped_tenants(self, mapping):
        """Core logic to check bootstrapped tenants are correct."""
        if mapping:
            # If mapping provided create the correct check requests for check_relation_core
            checks = [
                # Check root workspace has correct default workspace
                CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=mapping["root_workspace"],
                        resource_type="workspace",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation="parent",
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=mapping["default_workspace"],
                            resource_type="workspace",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                ),
                # Check default workspace has correct default role binding
                CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=mapping["default_workspace"],
                        resource_type="workspace",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation="binding",
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=mapping["tenant_mapping"]["default_role_binding_uuid"],
                            resource_type="role_binding",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                ),
                # Check default workspace has correct default admin role binding
                CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=mapping["default_workspace"],
                        resource_type="workspace",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation="binding",
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=mapping["tenant_mapping"]["default_admin_role_binding_uuid"],
                            resource_type="role_binding",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                ),
                # Check default role binding is assigned to correct group
                CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=mapping["tenant_mapping"]["default_role_binding_uuid"],
                        resource_type="role_binding",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation="subject",
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=mapping["tenant_mapping"]["default_group_uuid"],
                            resource_type="group",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                ),
                # Check default admin role binding is assigned to correct group
                CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=mapping["tenant_mapping"]["default_admin_role_binding_uuid"],
                        resource_type="role_binding",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation="subject",
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=mapping["tenant_mapping"]["default_admin_group_uuid"],
                            resource_type="group",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                ),
            ]
            bootstrapped_tenant_correct = self.check_inventory_core(checks)
            if not bootstrapped_tenant_correct:
                logger.warning(f'{mapping["org_id"]} does not have the expected hierarchy for bootstrapped tenant.')
            else:
                logger.info(f'{mapping["org_id"]} is correctly bootstrapped.')
        return bootstrapped_tenant_correct


class WorkspaceRelationInventoryChecker(InventoryApiBaseChecker):
    """Subclass to check workspace parent relations are correct on inventory api."""

    def check_workspace(self, workspace_id, workspace_parent_id):
        """Core logic to check workspace relation on inventory api."""
        # Build the check request for checking parent-child workspace relationship
        check_request = CheckRequest(
            object=resource_reference_pb2.ResourceReference(
                resource_id=workspace_parent_id,
                resource_type="workspace",
                reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
            ),
            relation="parent",
            subject=subject_reference_pb2.SubjectReference(
                resource=resource_reference_pb2.ResourceReference(
                    resource_id=workspace_id,
                    resource_type="workspace",
                    reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                )
            ),
        )

        workspace_check = self.check_inventory_core(check_request)
        if not workspace_check:
            logger.warning(f"{workspace_id} does not have the expected parent workspace.")
        else:
            logger.info(f"{workspace_id} has the correct parent workspace.")
        return workspace_check


class RoleRelationInventoryChecker(InventoryApiBaseChecker):
    """Subclass to check role relations are correct on inventory api."""

    def check_role(self, role_relations, role_uuid):
        """Core logic to check role V2 relation on inventory api."""
        check_requests = []
        for role_relation in role_relations:
            # Build the check request for each of the relations generated for the role
            check_request = CheckRequest(
                object=resource_reference_pb2.ResourceReference(
                    resource_id=role_relation["resource"]["id"],
                    resource_type=role_relation["resource"]["type"]["name"],
                    reporter=reporter_reference_pb2.ReporterReference(
                        type=role_relation["resource"]["type"]["namespace"]
                    ),
                ),
                relation=role_relation["relation"],
                subject=subject_reference_pb2.SubjectReference(
                    resource=resource_reference_pb2.ResourceReference(
                        resource_id=role_relation["subject"]["subject"]["id"],
                        resource_type=role_relation["subject"]["subject"]["type"]["name"],
                        reporter=reporter_reference_pb2.ReporterReference(
                            type=role_relation["subject"]["subject"]["type"]["namespace"]
                        ),
                    )
                ),
            )
            check_requests.append(check_request)
        role_check = self.check_inventory_core(check_requests)
        if not role_check:
            logger.warning(f"Role: {role_uuid} does not have the expected V2 relations.")
        else:
            logger.info(f"Role: {role_uuid} has the correct V2 relations.")
        return role_check
