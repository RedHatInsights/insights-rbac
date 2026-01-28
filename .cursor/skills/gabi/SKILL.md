---
name: gabi-sql-query
description: Run SQL queries against RBAC database in stage or prod using gabi
---

# Gabi SQL Query Tool

Use this skill to run SQL queries against the RBAC database in stage or prod environments.

## Workflow - Follow These Steps

**BEFORE running any query, you MUST:**

1. **Check if TOKEN is set**: Verify `echo $TOKEN` returns a value (or ask the user)
2. **Confirm environment**: User must specify `stage` or `prod`
3. **If either is missing**: DO NOT run the query. Inform the user and provide instructions.
4. **Only after both are confirmed**: Proceed with running the query

## CRITICAL REQUIREMENTS - READ BEFORE RUNNING QUERIES

**NEVER run a query without BOTH of the following:**
1. **TOKEN environment variable must be set** - Check with `echo $TOKEN` or ask the user
2. **Environment must be explicitly specified** - Must be either `stage` or `prod`

**If TOKEN is not set OR environment is not specified, DO NOT run the query. Instead:**
- Inform the user that the TOKEN and/or environment is required
- Provide instructions on how to obtain the token (see below)
- Wait for the user to set the TOKEN before proceeding

## Prerequisites

### Step 1: Obtain the TOKEN

Get the token from the OpenShift Console by pasting the URL into their browser:
- **Stage**: `${OPENSHIFT_STAGE_CONSOLE}` (domain from `.cursor/skills/config.env`)
- **Prod**: `${OPENSHIFT_PROD_CONSOLE}` (domain from `.cursor/skills/config.env`)

**IMPORTANT**: When displaying these URLs to users, read `.cursor/skills/config.env` and display the actual URLs as clickable markdown links (e.g., `[URL text](URL)`), but keep the variable references in this skill file.

Once logged in, click on your username in the top right corner and select "Copy login command" to get the token.

### Step 2: Set the TOKEN environment variable

```bash
export TOKEN=<TOKEN>
```

### Step 3: Verify TOKEN is set

```bash
echo $TOKEN
```

If this returns empty, the TOKEN is not set and queries must NOT be run.

## Usage

**Only run queries when TOKEN is set AND environment is specified:**

```bash
sh .cursor/skills/gabi/scripts/gabi.sh <stage|prod> "<SQL>"
```

**Example:**
```bash
sh .cursor/skills/gabi/scripts/gabi.sh stage "SELECT * FROM management_group LIMIT 1;"
```

## Common SQL Queries

### Search for tenant by ID

```sql
SELECT * FROM management_tenant WHERE id=<tenant_id>
```

### Search for policy by group_id

```sql
SELECT * FROM management_policy WHERE group_id=<group_id>
```

### Search for roles assigned to a policy

```sql
SELECT pr.*, r.id as role_id, r.uuid as role_uuid, r.name as role_name 
FROM management_policy_roles pr 
LEFT JOIN management_role r ON pr.role_id = r.id 
WHERE pr.policy_id=<policy_id>
```

### Search for all permissions a group is assigned by the group's uuid
```sql
SELECT DISTINCT
    p.permission,
    p.application,
    p.resource_type,
    p.verb,
    p.description
FROM management_permission p
JOIN management_access a ON a.permission_id = p.id
JOIN management_role r ON a.role_id = r.id
JOIN management_policy_roles pr ON pr.role_id = r.id
JOIN management_policy pol ON pr.policy_id = pol.id
JOIN management_group g ON pol.group_id = g.id
WHERE g.uuid = '<group-uuid-here>'
ORDER BY p.application, p.resource_type, p.verb;
```

### Search for all permissions a group is assigned by the group's id
```sql
SELECT DISTINCT
    p.permission,
    p.application,
    p.resource_type,
    p.verb,
    p.description
FROM management_permission p
JOIN management_access a ON a.permission_id = p.id
JOIN management_role r ON a.role_id = r.id
JOIN management_policy_roles pr ON pr.role_id = r.id
JOIN management_policy pol ON pr.policy_id = pol.id
JOIN management_group g ON pol.group_id = g.id
WHERE g.id = '<group-id-here>'
ORDER BY p.application, p.resource_type, p.verb;
```