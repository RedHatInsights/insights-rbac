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

ENTITY_SCHEMA = {
    "type": "object",
    "properties": {
        "type": TYPE_SCHEMA,
        "id": {"type": "string"},
    },
    "required": ["type", "id"],
}

RELATIONS_TOOL_INPUT_SCHEMAS = [
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
    }
]

RELATION_INPUT_SCHEMAS = {"lookup_resources": RELATIONS_TOOL_INPUT_SCHEMAS[0]}