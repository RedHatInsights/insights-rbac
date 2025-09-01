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
from typing import List, Union

from django.conf import settings
from google.protobuf import json_format
from grpc import RpcError
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import check_pb2
from kessel.relations.v1beta1 import check_pb2_grpc
from kessel.relations.v1beta1 import common_pb2
from kessel.relations.v1beta1.check_pb2 import CheckRequest
from management.cache import JWTCache
from management.utils import create_client_channel

jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationsApiBaseChecker:
    """Base class used for assignment checks on relations api."""

    def check_relation_core(self, checks: Union[CheckRequest, List[CheckRequest]]) -> bool:
        """
        Core method to check relation(s) via gRPC.

        Accepts either a single check request or list of check requests.
        """
        token = jwt_manager.get_jwt_from_redis()

        if isinstance(checks, CheckRequest):
            checks = [checks]

        try:
            with create_client_channel(settings.RELATION_API_SERVER) as channel:
                stub = check_pb2_grpc.KesselCheckServiceStub(channel)
                metadata = [("authorization", f"Bearer {token}")]

                responses = [stub.Check(req, metadata=metadata) for req in checks]
                return all(self._is_allowed(res) for res in responses)

        except RpcError as e:
            logger.error(f"[gRPC] check_relation_core failed: {e}")
        except Exception as e:
            logger.error(f"[Unexpected] check_relation_core failed: {e}")

        return False

    def _is_allowed(self, response):
        response_dict = json_format.MessageToDict(response)
        return response_dict.get("allowed", "") != "ALLOWED_FALSE"


class GroupPrincipalRelationChecker(RelationsApiBaseChecker):
    """Subclass to check group principal relations are correct on relations api."""

    def check_relationships(self, relationships):
        """Core logic to check group principal relations are correct."""
        relations_assignments = {"group_uuid": "", "principal_relations": []}
        for r in relationships:
            # Build the check request
            check_request = check_pb2.CheckRequest(
                resource=common_pb2.ObjectReference(
                    type=common_pb2.ObjectType(namespace=r.resource.type.namespace, name=r.resource.type.name),
                    id=r.resource.id,
                ),
                relation=r.relation,
                subject=common_pb2.SubjectReference(
                    relation=r.subject.relation,
                    subject=common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(
                            namespace=r.subject.subject.type.namespace, name=r.subject.subject.type.name
                        ),
                        id=r.subject.subject.id,
                    ),
                ),
            )
            relation_exists = self.check_relation_core(check_request)
            relations_assignments["group_uuid"] = r.resource.id
            relations_assignments["principal_relations"].append(
                {"id": r.subject.subject.id, "relation_exists": relation_exists}
            )
            if not relation_exists:
                logger.warning(
                    f"Relation missing: User ID {r.subject.subject.id} is not associated with Group ID {r.resource.id}"
                )
        return relations_assignments


class BootstrappedTenantRelationChecker(RelationsApiBaseChecker):
    """Subclass to check bootstrapped tenants are correct on relations api."""

    def check_bootstrapped_tenants(self, mapping):
        """Core logic to check bootstrapped tenants are correct."""
        if mapping:
            # If mapping provided create the correct check requests for check_relation_core
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
            bootstrapped_tenant_correct = self.check_relation_core(checks)
            if not bootstrapped_tenant_correct:
                logger.warning(f'{mapping["org_id"]} does not have the expected hierarchy for bootstrapped tenant.')
            else:
                logger.info(f'{mapping["org_id"]} is correctly bootstrapped.')
        return bootstrapped_tenant_correct
