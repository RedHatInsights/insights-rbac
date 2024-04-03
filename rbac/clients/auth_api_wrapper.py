import grpc
from clients.relation_api_grpc import relationships_pb2
from clients.relation_api_grpc import relationships_pb2_grpc
from rbac.env import ENVIRONMENT
import requests

class AuthAPIWrapper:
    def __init__(self):
        #self.grpc_server_address = ENVIRONMENT.get_value("RELATION_API_GRPC_HOST", default="") + ":" + ENVIRONMENT.get_value("RELATION_API_GRPC_PORT", default="")
        self.grpc_server_address = "relationships-relationships:9000"
        self.rest_server_address = ENVIRONMENT.get_value("RELATION_API_REST_HOST", default="") + ":" + ENVIRONMENT.get_value("RELATION_API_REST_PORT", default="")
        #self.is_grpc = ENVIRONMENT.get_value("RELATION_API_REST_OR_GRPC", default="") == "grpc"
        self.is_grpc = "grpc"

    def test_rest_call(self):
        params = {
            'filter.objectType': 'group',
            'filter.objectId': 'bob_club',
            'filter.relation': 'member'
        }


        url = 'http://' + self.rest_server_address + '/api/authz/v1/relationships'

        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()
            print(data)
        else:
            print(f"Failed to fetch data. Status code: {response.status_code}")

    def test_grpc_call(self):
        with grpc.insecure_channel(self.grpc_server_address) as channel:
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
        with grpc.insecure_channel(self.grpc_server_address) as channel:
            stub = relationships_pb2_grpc.RelationshipsStub(channel)

            request = relationships_pb2.ReadRelationshipsRequest(filter=relationships_pb2.RelationshipFilter(
                    object_type="group",
                    object_id="bob_club",
                    relation="member"
                ))

            response = stub.ReadRelationships(request)
        print(response)
        print("End of ReadRelationshipsRequest")


    def test_call(self):
        if self.is_grpc:
            self.test_grpc_call()
        else:
            self.test_rest_call()
