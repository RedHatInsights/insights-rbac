#
# Copyright 2026 Red Hat, Inc.
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
"""Domain models for RBAC."""

import dataclasses
import re
from typing import ClassVar, Optional

from kessel.relations.v1beta1.common_pb2 import ObjectReference, ObjectType, Relationship, SubjectReference


@dataclasses.dataclass(frozen=True)
class RelationTuple:
    """
    Domain representation of a relation tuple.

    This is an internal abstraction over the external SpiceDB/Kessel relation concept.
    Use as_message() to convert to the protobuf Relationship type for replication.
    """

    resource_type_namespace: str
    resource_type_name: str
    resource_id: str
    relation: str
    subject_type_namespace: str
    subject_type_name: str
    subject_id: str
    subject_relation: Optional[str]

    _type_regex: ClassVar[re.Pattern] = re.compile(r"^[A-Za-z0-9_]+$")
    _id_regex: ClassVar[re.Pattern] = re.compile(r"^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$")

    def _relation_type_error(self, msg: str) -> TypeError:
        return TypeError(msg + f"\nFull relationship: {self!r}")

    def _relation_value_error(self, msg: str) -> ValueError:
        return ValueError(msg + f"\nFull relationship: {self!r}")

    def _validate_required(self, attr: str):
        value = getattr(self, attr)

        if value is None:
            raise self._relation_type_error(f"{attr} is required, but was None.")

        if not isinstance(value, str):
            raise self._relation_type_error(f"{attr} must be a string.")

        if value == "":
            raise self._relation_value_error(
                f"{attr} cannot be empty. (You may have initialized a message with None.)"
            )

    def _validate_optional(self, attr: str):
        value = getattr(self, attr)

        if value is None:
            return

        if not isinstance(value, str):
            raise self._relation_type_error(f"{attr} must be a string or None.")

        if value == "":
            raise self._relation_value_error(f"{attr} cannot be empty (for an absent value, use None).")

    def _validate_type_name(self, attr: str):
        value = getattr(self, attr)

        if not re.fullmatch(self._type_regex, value):
            raise self._relation_value_error(
                f"Expected {attr} to be composed of alphanumeric characters and underscores, but got: {value!r}"
            )

    def _validate_object_id(self, attr: str, allow_asterisk: bool):
        value = getattr(self, attr)

        if not allow_asterisk and value == "*":
            raise self._relation_value_error(f"Expected {attr} not to be an asterisk.")

        if not re.fullmatch(self._id_regex, value):
            raise self._relation_value_error(
                f"Expected {attr} to be composed of alphanumeric characters, underscores, hyphens, pipes, "
                f"equals signs, plus signs, and forward slashes, "
                + (", or to be exactly '*', " if allow_asterisk else "")
                + f"but got: {value!r}"
            )

    def __post_init__(self):
        """Check that this RelationTuple is valid."""
        self._validate_required("resource_type_namespace")
        self._validate_required("resource_type_name")
        self._validate_required("resource_id")
        self._validate_required("relation")
        self._validate_required("subject_type_namespace")
        self._validate_required("subject_type_name")
        self._validate_required("subject_id")

        self._validate_optional("subject_relation")

        self._validate_type_name("resource_type_name")
        self._validate_type_name("subject_type_name")

        self._validate_object_id("resource_id", allow_asterisk=False)
        self._validate_object_id("subject_id", allow_asterisk=True)

    @classmethod
    def from_message_dict(cls, relationship: dict) -> "RelationTuple":
        """Create a RelationTuple from a Relationship message dict."""

        def as_optional(value: str) -> Optional[str]:
            return value if value != "" else None

        return RelationTuple(
            resource_type_namespace=relationship["resource"]["type"]["namespace"],
            resource_type_name=relationship["resource"]["type"]["name"],
            resource_id=relationship["resource"]["id"],
            relation=relationship["relation"],
            subject_type_namespace=relationship["subject"]["subject"]["type"]["namespace"],
            subject_type_name=relationship["subject"]["subject"]["type"]["name"],
            subject_id=relationship["subject"]["subject"]["id"],
            subject_relation=as_optional(relationship["subject"]["relation"]),
        )

    @classmethod
    def from_message(cls, relationship: Relationship) -> "RelationTuple":
        """Create a RelationTuple from a protobuf Relationship message."""

        def as_optional(value: str) -> Optional[str]:
            return value if value != "" else None

        return RelationTuple(
            resource_type_namespace=relationship.resource.type.namespace,
            resource_type_name=relationship.resource.type.name,
            resource_id=relationship.resource.id,
            relation=relationship.relation,
            subject_type_namespace=relationship.subject.subject.type.namespace,
            subject_type_name=relationship.subject.subject.type.name,
            subject_id=relationship.subject.subject.id,
            subject_relation=as_optional(relationship.subject.relation),
        )

    def as_message(self) -> Relationship:
        """Convert to a protobuf Relationship message for replication."""
        return Relationship(
            resource=ObjectReference(
                type=ObjectType(
                    namespace=self.resource_type_namespace,
                    name=self.resource_type_name,
                ),
                id=self.resource_id,
            ),
            relation=self.relation,
            subject=SubjectReference(
                subject=ObjectReference(
                    type=ObjectType(
                        namespace=self.subject_type_namespace,
                        name=self.subject_type_name,
                    ),
                    id=self.subject_id,
                ),
                relation=self.subject_relation,
            ),
        )

    @classmethod
    def validate_message(cls, message: Relationship):
        """Check that the provided Relationship represents a valid tuple."""
        parsed = RelationTuple.from_message(message)
        assert parsed.as_message() == message

    def stringify(self) -> str:
        """Display all attributes in one line."""
        subject_part = f"{self.subject_type_namespace}/{self.subject_type_name}:{self.subject_id}"
        if self.subject_relation:
            subject_part += f"#{self.subject_relation}"
        return (
            f"{self.resource_type_namespace}/{self.resource_type_name}:{self.resource_id}#{self.relation}"
            f"@{subject_part}"
        )
