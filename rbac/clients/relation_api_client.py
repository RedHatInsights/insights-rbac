from __future__ import print_function

import grpc
from clients.relation_api_grpc import relationships_pb2
from clients.relation_api_grpc import relationships_pb2_grpc
from rbac.env import ENVIRONMENT


relation_api_gRPC_server = ENVIRONMENT.get_value("RELATION_API_HOST", default="") + ":" + ENVIRONMENT.get_value("RELATION_API_PORT", default="")
print("hello")
print(relation_api_gRPC_server)
print("hello")

def test_grpc_call():
    with grpc.insecure_channel(relation_api_gRPC_server) as channel:
        stub = relationships_pb2_grpc.RelationshipsStub(channel)

        request = relationships_pb2.CreateRelationshipsRequest(
            touch=True,
            relationships=[
                relationships_pb2.Relationship(
                    object=relationships_pb2.ObjectReference(type="group", id="bob_club"),
                    relation="member",
                    subject=relationships_pb2.SubjectReference(
                        object=relationships_pb2.ObjectReference(type="user", id="bob")
                    )
                )
            ]
        )

        response = stub.CreateRelationships(request)
    print(response.SerializeToString())
    print("End of CreateRelationshipsRequest")

    print("Start of ReadRelationshipsRequest")
    with grpc.insecure_channel(relation_api_gRPC_server) as channel:
        stub = relationships_pb2_grpc.RelationshipsStub(channel)

        request = relationships_pb2.ReadRelationshipsRequest(filter=relationships_pb2.RelationshipFilter(
                object_type="group",
                object_id="bob_club",
                relation="member"
            ))

        response = stub.ReadRelationships(request)
    print(response)
    print("End of ReadRelationshipsRequest")
