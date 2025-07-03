"""Validation schemas for /_private/api/relations/ endpoints."""

# Common schemas
TYPE_SCHEMA = {
    "type": "object",
    "properties": {
        "namespace": {"type": "string"},
        "name": {"type": "string"},
    },
    "required": ["namespace", "name"],
}

TYPE_SCHEMA_TWO = {
    "type": "object",
    "properties": {
        "type": TYPE_SCHEMA,
        "id": {"type": "string"},
    },
    "required": ["type", "id"],
}

ENTITY_SCHEMA = {
    "type": "object",
    "properties": {
        "type": TYPE_SCHEMA,
        "id": {"type": "string"},
    },
    "required": ["type", "id"],
}

RELATIONS_TOOL_INPUT_SCHEMAS = [
    # "api/relations/lookup_resource/"
    {
        "type": "object",
        "properties": {
            "resource_type": TYPE_SCHEMA,
            "relation": {"type": "string"},
            "subject": {
                "type": "object",
                "properties": {"subject": ENTITY_SCHEMA},
                "required": ["subject"],
            },
        },
        "required": ["resource_type", "relation", "subject"],
    },
    # "api/relations/check_relation/"
    {
        "type": "object",
        "properties": {
            "resource": TYPE_SCHEMA_TWO,
            "relation": {"type": "string"},
            "subject": {
                "type": "object",
                "relation": {"type": "string"},
                "properties": {"subject": ENTITY_SCHEMA},
                "required": ["subject", "relation"],
            },
        },
        "required": ["resource", "relation", "subject"],
    },
]

RELATION_INPUT_SCHEMAS = {
    "lookup_resources": RELATIONS_TOOL_INPUT_SCHEMAS[0],
    "check_relation": RELATIONS_TOOL_INPUT_SCHEMAS[1],
}
