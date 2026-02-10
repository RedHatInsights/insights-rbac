---
name: relationship-query
description: Query relationships in SpiceDB/Kessel via the RBAC relations API
---

# Relationship Query Tool

Use this skill to query relationships stored in SpiceDB/Kessel via the RBAC internal relations API.

## Prerequisites

Before running queries, you MUST:

0. **Check for config.env file**: Verify that `.cursor/skills/config.env` exists. If it does not exist:
   - Copy the example file: `cp .cursor/skills/config.env.example .cursor/skills/config.env`
   - Update the values in `config.env` with your environment-specific settings (STAGE_DOMAIN, PROD_DOMAIN, PROXY)
   - **WARNING**: The script will fail if `config.env` is missing or incomplete. Always ensure `config.env` exists before proceeding.

1. **Check if SESSION is set**: If the `SESSION` environment variable is not set, ask the user to get the token from the Turnpike Session by pasting the URL into their browser:
   - For stage: `${STAGE_DOMAIN}/api/turnpike/session/` (domain from `.cursor/skills/config.env`)
   - For prod: `${PROD_DOMAIN}/api/turnpike/session/` (domain from `.cursor/skills/config.env`)
   - Copy the token from the browser response and set it with `export SESSION=<token_value>`
   - Do NOT run queries without a valid SESSION.

2. **Confirm the environment**: If the environment (stage or prod) is not explicitly specified by the user, ask them to confirm which environment they want to query.

### Setting up SESSION

You can obtain the SESSION value using one of these methods:

#### Method 1: Get token from Turnpike Session API (Recommended)

Get the session token by pasting the URL into your browser:

**For stage environment:**
1. Paste this URL into your browser: `${STAGE_DOMAIN}/api/turnpike/session/` (where `STAGE_DOMAIN` is from `.cursor/skills/config.env`, default: `https://internal.console.stage.redhat.com`)
2. Copy the token from the browser response
3. Set it: `export SESSION=<token_from_response>`

**For prod environment:**
1. Paste this URL into your browser: `${PROD_DOMAIN}/api/turnpike/session/` (where `PROD_DOMAIN` is from `.cursor/skills/config.env`, default: `https://internal.console.redhat.com`)
2. Copy the token from the browser response
3. Set it: `export SESSION=<token_from_response>`

#### Method 2: Get session cookie from browser

Alternatively, the session cookie can be obtained from browser cookies when logged into console.stage.redhat.com or console.redhat.com:

1. Log in to the console (stage or prod)
2. Open browser DevTools (F12)
3. Go to Application/Storage tab → Cookies
4. Copy the value of the `session` cookie
5. Set it: `export SESSION=<session_cookie_value>`

## Usage

Run the script at `.cursor/skills/relationship/scripts/relationship.sh`:

```bash
sh .cursor/skills/relationship/scripts/relationship.sh <stage|prod> <read_tuples|lookup_resource> '<JSON_PAYLOAD>'
```

**Important**: Always verify SESSION is set and environment is confirmed before executing queries.

## Workflow

When a user requests a relationship query:

0. **Check for config.env**: Verify `.cursor/skills/config.env` exists
   - If NOT found: Inform the user that `config.env` is required and provide instructions to create it from the example file
   - Do NOT proceed until `config.env` exists

1. **Check SESSION**: Verify if `SESSION` environment variable is set
   - If NOT set: Ask the user to get the token by pasting the Turnpike Session URL into their browser:
     - For stage: `${STAGE_DOMAIN}/api/turnpike/session/` (domain from `.cursor/skills/config.env`)
     - For prod: `${PROD_DOMAIN}/api/turnpike/session/` (domain from `.cursor/skills/config.env`)
   - Ask the user to copy the token from the browser response and set it with `export SESSION=<token_value>`
   - Do NOT proceed with the query until SESSION is set

2. **Confirm Environment**: Determine which environment to query
   - If user specified stage/prod: Use that environment
   - If unclear: Ask the user to confirm (stage or prod)

3. **Execute Query**: Only after config.env exists, SESSION is set, and environment is confirmed, run the relationship query script

## Common Queries

### Read tuples for a role_binding

Find all relationships for a specific role binding:

```bash
sh .cursor/skills/relationship/scripts/relationship.sh stage read_tuples '{
  "filter": {
    "resource_namespace": "rbac",
    "resource_type": "role_binding",
    "resource_id": "<role_binding_uuid>",
    "relation": "",
    "subject_filter": {
      "subject_namespace": "rbac",
      "subject_type": "group",
      "subject_id": ""
    }
  }
}'
```

### Read tuples for a group (find members)

Find all principals that are members of a group:

```bash
sh .cursor/skills/relationship/scripts/relationship.sh stage read_tuples '{
  "filter": {
    "resource_namespace": "rbac",
    "resource_type": "group",
    "resource_id": "<group_uuid>",
    "relation": "member",
    "subject_filter": {
      "subject_namespace": "rbac",
      "subject_type": "principal",
      "subject_id": ""
    }
  }
}'
```

### Read role relation for a role_binding

Find what role is assigned to a role binding:

```bash
sh .cursor/skills/relationship/scripts/relationship.sh stage read_tuples '{
  "filter": {
    "resource_namespace": "rbac",
    "resource_type": "role_binding",
    "resource_id": "<role_binding_uuid>",
    "relation": "role",
    "subject_filter": {
      "subject_namespace": "rbac",
      "subject_type": "role",
      "subject_id": ""
    }
  }
}'
```

### Lookup resources (find role bindings for a group)

Find all role bindings where a group is a subject:

```bash
sh .cursor/skills/relationship/scripts/relationship.sh stage lookup_resource '{
  "resource_type": {
    "name": "role_binding",
    "namespace": "rbac"
  },
  "subject": {
    "subject": {
      "type": {
        "name": "group",
        "namespace": "rbac"
      },
      "id": "<group_uuid>"
    }
  },
  "relation": "subject"
}'
```

## Resource Types

Common resource types in the rbac namespace:
- `role_binding` - Binds roles to subjects (groups/principals)
- `group` - Groups of principals
- `role` - Role definitions
- `workspace` - Workspace resources
- `principal` - Individual users/service accounts

## Relations

Common relations:
- `subject` - Subject of a role binding (group or principal)
- `member` - Member of a group
- `role` - Role assigned to a binding
- `parent` - Parent workspace relationship
