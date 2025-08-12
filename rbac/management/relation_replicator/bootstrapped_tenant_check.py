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

"""RelationReplicator which check relations on Relations API."""


import logging

from django.conf import settings
from google.protobuf import json_format
from grpc import RpcError
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import check_pb2
from kessel.relations.v1beta1 import check_pb2_grpc
from kessel.relations.v1beta1 import common_pb2
from management.cache import JWTCache
from management.utils import create_client_channel

jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationsApiTenantChecker:
    """Checks bootstrapped tenants via the Relations API over gRPC."""

    def replicate(self, tenant_mappings):
        """Check the given event is correct on Kessel Relations via the gRPC API."""
        assignments = self._check_bootstrapped_tenants(tenant_mappings)
        return assignments

    def _check_bootstrapped_tenants(self, mappings):
        bootstrapped_tenants = {"org_id": "", "workspaces": []}
        for mapping in mappings:
            bootstrapped_tenant_correct = self.check_relation_core(mapping)
            bootstrapped_tenants["org_id"] = mapping["org_id"]
            bootstrapped_tenants["workspaces"].append(
                {
                    "root_workspace": mapping["root_workspace"],
                    "default_workspace": mapping["default_workspace"],
                    "bootstrapped_correct": bootstrapped_tenant_correct,
                }
            )
            if not bootstrapped_tenant_correct:
                logger.warning(f'{mapping["org_id"]} does not have the expected hierarchy for bootstrapped tenant.')
            else:
                logger.info(f'{mapping["org_id"]} is correctly bootstrapped.')
        return bootstrapped_tenant_correct

    def check_relation_core(self, mapping: dict) -> bool:
        """
        Core function to check relation between a resource and a subject using gRPC.

        Returns True if relation exists, False otherwise.
        """
        token = jwt_manager.get_jwt_from_redis()

        try:
            with create_client_channel(settings.RELATION_API_SERVER) as channel:
                stub = check_pb2_grpc.KesselCheckServiceStub(channel)
                metadata = [("authorization", f"Bearer {token}")]

                checks = [
                    # Check root workspace has correct default workspace
                    check_pb2.CheckRequest(
                        resource=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(namespace="rbac", name="workspace"),
                            id=mapping["root_workspace"],
                        ),
                        relation="parent",
                        subject=common_pb2.SubjectReference(
                            subject=common_pb2.ObjectReference(
                                type=common_pb2.ObjectType(namespace="rbac", name="workspace"),
                                id=mapping["default_workspace"],
                            ),
                        ),
                    ),
                    # Check default workspace has correct default role binding
                    check_pb2.CheckRequest(
                        resource=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(namespace="rbac", name="workspace"),
                            id=mapping["default_workspace"],
                        ),
                        relation="binding",
                        subject=common_pb2.SubjectReference(
                            subject=common_pb2.ObjectReference(
                                type=common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                                id=mapping["tenant_mapping"]["default_role_binding_uuid"],
                            ),
                        ),
                    ),
                    # Check default workspace has correct default admin role binding
                    check_pb2.CheckRequest(
                        resource=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(namespace="rbac", name="workspace"),
                            id=mapping["default_workspace"],
                        ),
                        relation="binding",
                        subject=common_pb2.SubjectReference(
                            subject=common_pb2.ObjectReference(
                                type=common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                                id=mapping["tenant_mapping"]["default_admin_role_binding_uuid"],
                            ),
                        ),
                    ),
                    # Check default role binding is assigned to correct group
                    check_pb2.CheckRequest(
                        resource=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                            id=mapping["tenant_mapping"]["default_role_binding_uuid"],
                        ),
                        relation="subject",
                        subject=common_pb2.SubjectReference(
                            relation="member",
                            subject=common_pb2.ObjectReference(
                                type=common_pb2.ObjectType(namespace="rbac", name="group"),
                                id=mapping["tenant_mapping"]["default_group_uuid"],
                            ),
                        ),
                    ),
                    # Check default admin role binding is assigned to correct group
                    check_pb2.CheckRequest(
                        resource=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                            id=mapping["tenant_mapping"]["default_admin_role_binding_uuid"],
                        ),
                        relation="subject",
                        subject=common_pb2.SubjectReference(
                            relation="member",
                            subject=common_pb2.ObjectReference(
                                type=common_pb2.ObjectType(namespace="rbac", name="group"),
                                id=mapping["tenant_mapping"]["default_admin_group_uuid"],
                            ),
                        ),
                    ),
                ]

                responses = [stub.Check(req, metadata=metadata) for req in checks]

                if all(is_allowed(res) for res in responses):
                    return True

        except RpcError as e:
            logger.error(f"[gRPC] check_relation failed: {e}")
        except Exception as e:
            logger.error(f"[Unexpected] check_relation failed: {e}")
        return False


def is_allowed(response):
    """Check that the relationship exists in the relations API."""
    response_dict = json_format.MessageToDict(response)
    return response_dict.get("allowed", "") != "ALLOWED_FALSE"
