"""
Copyright 2019 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Sequence

import authzed.api.v1
from authzed.api.v1 import (
    Client,
    ObjectReference,
    ReadSchemaRequest,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
)
from grpcutil import insecure_bearer_token_credentials
from models import Relationship


client = Client("localhost:50051", insecure_bearer_token_credentials("token"))


def write_relationships(rels: Sequence[Relationship]):
    """Write a sequence of relationships to the server."""
    updates = []
    for rel in rels:
        updates.append(
            RelationshipUpdate(
                operation=RelationshipUpdate.Operation.OPERATION_TOUCH,
                relationship=authzed.api.v1.Relationship(
                    resource=ObjectReference(
                        object_type=cleanNameForV2SchemaCompatibility(rel.resource_type), object_id=rel.resource_id
                    ),
                    relation=rel.relation,
                    subject=SubjectReference(
                        object=ObjectReference(
                            object_type=cleanNameForV2SchemaCompatibility(rel.subject_type), object_id=rel.subject_id
                        )
                    ),
                ),
            )
        )
        if len(rels) > 950:
            client.WriteRelationships(WriteRelationshipsRequest(updates=updates))
            updates = []

    client.WriteRelationships(WriteRelationshipsRequest(updates=updates))


# Translated from: https://gitlab.corp.redhat.com/ciam-authz/loadtesting-spicedb/-/blob/main/spicedb/
# prbac-schema-generator/main.go?ref_type=heads#L286
def cleanNameForV2SchemaCompatibility(name: str):
    """Clean a name for compatibility with the v2 schema."""
    return name.lower().replace("-", "_").replace(".", "_").replace(":", "_").replace(" ", "_").replace("*", "all")


if __name__ == "__main__":
    response = client.ReadSchema(ReadSchemaRequest())
    print(response)
