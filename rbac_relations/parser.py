"""Parsing utilities for RBAC relation strings."""

import re
from typing import Optional, Dict


# Relation regex pattern
_RELATION_RE = re.compile(
    r"(?P<rtype>\w+):(?P<rid>[a-zA-Z0-9\-\*\/\.]+)"
    r"#(?P<rel>\w+)@(?P<stype>\w+):(?P<sid>[a-zA-Z0-9\-\*\/\.]+)"
    r"(?:#(?P<srel>\w+))?"
)


def parse_relation(line: str) -> Optional[Dict]:
    """
    Parse a relation line like:
    role_binding:9ccf2995-104c-465f-b6e2-71a9300ce9ca#role@role:b28522be-6044-4592-9f3f-65641fb645a3
    group:94bb1277-4e83-464c-9812-5447ca43b053#member@principal:localhost/lpichler-eng

    Args:
        line: The relation string to parse

    Returns:
        dict with resource_type, resource_id, relation, subject_type, subject_id, subject_relation
        or None if not a valid relation
    """
    m = _RELATION_RE.match(line.strip())
    if not m:
        return None

    return {
        "resource_type": m.group("rtype"),
        "resource_id": m.group("rid"),
        "relation": m.group("rel"),
        "subject_type": m.group("stype"),
        "subject_id": m.group("sid"),
        "subject_relation": m.group("srel"),
        "raw": line.strip(),
    }


def extract_relations_from_line(line: str) -> Optional[Dict]:
    """
    Extract relation from a log line.
    Handles different log formats:
    - Migration tool: INFO: role:UUID#relation@subject:ID
    - Dual write JSON logs: {"log":{"original":"role:UUID#relation@subject:ID"}}
    - Direct relation format: role:UUID#relation@subject:ID

    Args:
        line: Log line to extract relation from

    Returns:
        Parsed relation dict or None
    """
    # Look for lines that contain relation patterns
    if "#" not in line or "@" not in line:
        return None

    # Try to extract from JSON log format first
    if '"original":"' in line or '"original":' in line:
        import json

        try:
            # Find the JSON part
            if (json_start := line.find("{")) != -1:
                json_obj = json.loads(line[json_start:])
                if "log" in json_obj and "original" in json_obj["log"]:
                    if result := parse_relation(json_obj["log"]["original"]):
                        return result
        except (json.JSONDecodeError, KeyError):
            pass

    # Try to extract the relation part after INFO:
    if "INFO:" in line:
        parts = line.split("INFO:", 1)
        if len(parts) == 2:
            content = parts[1].strip()
            # Remove RELATION_ADDED: or RELATION_REMOVED: prefix if present
            for prefix in ["RELATION_ADDED:", "RELATION_REMOVED:", "REMOVE:"]:
                if content.startswith(prefix):
                    content = content[len(prefix) :].strip()
                    break
            if result := parse_relation(content):
                return result

    # Try parsing the whole line (for direct relation format)
    return parse_relation(line)
