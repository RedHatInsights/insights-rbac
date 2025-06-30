"""Validation schemas for /_private/api/relations/ endpoints."""

RELATIONS_TOOL_INPUT_SCHEMAS = [
    # /_private/api/relations/lookup_resource/ schema
    {
        "type": "object",
        "properties": {
            "resource_type": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
                "required": ["name", "namespace"],
            },
            "relation": {"type": "string"},
            "subject": {
                "type": "object",
                "properties": {
                    "subject": {
                        "type": "object",
                        "properties": {
                            "type": {
                                "type": "object",
                                "properties": {
                                    "namespace": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                                "required": ["namespace", "name"],
                            },
                            "id": {"type": "string"},
                        },
                        "required": ["type", "id"],
                    }
                },
                "required": ["subject"],
            },
        },
        "required": ["resource_type", "relation", "subject"],
    }
]
