from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CreateRelationshipsRequest(_message.Message):
    __slots__ = ("touch", "relationships")
    TOUCH_FIELD_NUMBER: _ClassVar[int]
    RELATIONSHIPS_FIELD_NUMBER: _ClassVar[int]
    touch: bool
    relationships: _containers.RepeatedCompositeFieldContainer[Relationship]
    def __init__(self, touch: bool = ..., relationships: _Optional[_Iterable[_Union[Relationship, _Mapping]]] = ...) -> None: ...

class CreateRelationshipsResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReadRelationshipsRequest(_message.Message):
    __slots__ = ("filter",)
    FILTER_FIELD_NUMBER: _ClassVar[int]
    filter: RelationshipFilter
    def __init__(self, filter: _Optional[_Union[RelationshipFilter, _Mapping]] = ...) -> None: ...

class ReadRelationshipsResponse(_message.Message):
    __slots__ = ("relationships",)
    RELATIONSHIPS_FIELD_NUMBER: _ClassVar[int]
    relationships: _containers.RepeatedCompositeFieldContainer[Relationship]
    def __init__(self, relationships: _Optional[_Iterable[_Union[Relationship, _Mapping]]] = ...) -> None: ...

class DeleteRelationshipsRequest(_message.Message):
    __slots__ = ("filter",)
    FILTER_FIELD_NUMBER: _ClassVar[int]
    filter: RelationshipFilter
    def __init__(self, filter: _Optional[_Union[RelationshipFilter, _Mapping]] = ...) -> None: ...

class DeleteRelationshipsResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RelationshipFilter(_message.Message):
    __slots__ = ("object_type", "object_id", "relation", "subject_filter")
    OBJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    RELATION_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FILTER_FIELD_NUMBER: _ClassVar[int]
    object_type: str
    object_id: str
    relation: str
    subject_filter: SubjectFilter
    def __init__(self, object_type: _Optional[str] = ..., object_id: _Optional[str] = ..., relation: _Optional[str] = ..., subject_filter: _Optional[_Union[SubjectFilter, _Mapping]] = ...) -> None: ...

class SubjectFilter(_message.Message):
    __slots__ = ("relation", "subject_id", "subject_type")
    RELATION_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    relation: str
    subject_id: str
    subject_type: str
    def __init__(self, relation: _Optional[str] = ..., subject_id: _Optional[str] = ..., subject_type: _Optional[str] = ...) -> None: ...

class Relationship(_message.Message):
    __slots__ = ("object", "relation", "subject")
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    RELATION_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    object: ObjectReference
    relation: str
    subject: SubjectReference
    def __init__(self, object: _Optional[_Union[ObjectReference, _Mapping]] = ..., relation: _Optional[str] = ..., subject: _Optional[_Union[SubjectReference, _Mapping]] = ...) -> None: ...

class SubjectReference(_message.Message):
    __slots__ = ("relation", "object")
    RELATION_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    relation: str
    object: ObjectReference
    def __init__(self, relation: _Optional[str] = ..., object: _Optional[_Union[ObjectReference, _Mapping]] = ...) -> None: ...

class ObjectReference(_message.Message):
    __slots__ = ("type", "id")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    type: str
    id: str
    def __init__(self, type: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...
