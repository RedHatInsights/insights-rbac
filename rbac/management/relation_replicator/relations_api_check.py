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

import http.client
import json
import logging
from contextlib import contextmanager

import grpc
from django.conf import settings
from google.protobuf import json_format
from google.rpc import error_details_pb2
from grpc import RpcError
from grpc_status import rpc_status
from kessel.relations.v1beta1 import check_pb2
from kessel.relations.v1beta1 import check_pb2_grpc
from kessel.relations.v1beta1 import common_pb2
from management.cache import JWTCache
from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEvent


class JWTProvider:
    """Class to handle creation of JWT token."""

    # Instance variable for the class.
    _instance = None

    def __new__(cls, *args, **kwargs):
        """Create a single instance of the class."""
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)

        return cls._instance

    def __init__(self):
        """Establish SSO connection information."""
        self.connection = None

    def get_conn(self):
        """Get connection to sso stage."""
        if settings.REDHAT_SSO is not None:
            self.connection = http.client.HTTPSConnection(settings.REDHAT_SSO)
        return self.connection

    def get_jwt_token(self, client_id, client_secret):
        """Retrieve jwt token from Redhat SSO."""
        connection = self.get_conn()

        # Test the connection
        if connection is None:
            return None

        if client_id is None or client_secret is None:
            raise Exception("Missing client_id or client_secret in environment file.")

        payload = (
            f"grant_type={settings.TOKEN_GRANT_TYPE}&"
            f"client_id={settings.RELATIONS_API_CLIENT_ID}&"
            f"client_secret={settings.RELATIONS_API_CLIENT_SECRET}&"
            f"scope={settings.SCOPE}"
        )

        headers = {"content-type": "application/x-www-form-urlencoded"}

        connection.request("POST", settings.OPENID_URL, payload, headers)

        res = connection.getresponse()
        data = res.read()
        json_data = json.loads(data)

        token = json_data["access_token"]
        return token


class JWTManager:
    """Class to handle management of JWT tokens."""

    def __init__(self, jwt_provider, jwt_cache):
        """Establish connection to JWT cache and provider."""
        self.jwt_cache = jwt_cache
        self.jwt_provider = jwt_provider

    def get_jwt_from_redis(self):
        """Retrieve jwt token from redis or generate from Redhat SSO if not exists in redis."""
        try:
            # Try retrieve token from redis
            token = self.jwt_cache.get_jwt_response()

            # If token not is redis
            if not token:
                token = self.jwt_provider.get_jwt_token(
                    settings.RELATIONS_API_CLIENT_ID, settings.RELATIONS_API_CLIENT_SECRET
                )
                # Token obtained store it in redis
                if token:
                    self.jwt_cache.set_jwt_response(token)
                    logger.info("Token stored in redis.")
                else:
                    logger.error("Failed to store jwt token in redis.")
            else:
                # Token exists return it
                logger.info("Token retrieved from redis.")
            return token

        except Exception as e:
            logger.error(f"error occurred when trying to retrieve JWT token. {e}")
            return None


jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


@contextmanager
def create_client_channel(addr):
    """Create secure channel for grpc requests."""
    secure_channel = grpc.insecure_channel(addr)
    yield secure_channel


class RelationsApiAssignmentCheck(RelationReplicator):
    """Checks relations via the Relations API over gRPC."""

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the gRPC API."""
        assignments = self._check_relationships(relationships=event.add)
        return assignments

    def _check_relationships(self, relationships):
        relations_assignments = {"group_uuid": "", "principal_relations": []}
        for r in relationships:
            relation_exists = check_relation_core(r)
            relations_assignments["group_uuid"] = r.resource.id
            relations_assignments["principal_relations"].append(
                {"id": r.subject.subject.id, "relation_exists": relation_exists}
            )
            if not relation_exists:
                logger.warning(
                    f"Relation missing: User ID {r.subject.subject.id} is not associated with Group ID {r.resource.id}"
                )
        return relations_assignments


def check_relation_core(r: common_pb2.Relationship) -> bool:
    """
    Core function to check relation between a resource and a subject using gRPC.

    Returns True if relation exists, False otherwise.
    """
    token = jwt_manager.get_jwt_from_redis()
    try:
        with create_client_channel(settings.RELATION_API_SERVER) as channel:
            stub = check_pb2_grpc.KesselCheckServiceStub(channel)

            request_data = check_pb2.CheckRequest(
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

            metadata = [("authorization", f"Bearer {token}")]
            response = stub.Check(request_data, metadata=metadata)

            if response:
                response_dict = json_format.MessageToDict(response)
                return response_dict.get("allowed", "") != "ALLOWED_FALSE"

    except RpcError as e:
        logger.error(f"[gRPC] check_relation failed: {e}")
    except Exception as e:
        logger.error(f"[Unexpected] check_relation failed: {e}")
    return False


class GRPCError:
    """A wrapper for a gRPC error."""

    code: grpc.StatusCode
    reason: str
    message: str
    metadata: dict

    def __init__(self, error: grpc.RpcError):
        """Initialize the error."""
        self.code = error.code()
        self.message = error.details()

        status = rpc_status.from_call(error)
        if status is not None:
            detail = status.details[0]
            info = error_details_pb2.ErrorInfo()
            detail.Unpack(info)
            self.reason = info.reason
            self.metadata = json.loads(str(info.metadata).replace("'", '"'))
