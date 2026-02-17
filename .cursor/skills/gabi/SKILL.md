---
name: gabi-sql-query
description: Run SQL queries against RBAC database in stage or prod using gabi
---

# Gabi SQL Query Tool

Use this skill to run SQL queries against the RBAC database in stage or prod environments.

## Workflow - Follow These Steps

**BEFORE running any query, you MUST:**

0. **Check for config.env**: Verify `.cursor/skills/config.env` exists. If missing, inform the user to create it from the example file.
1. **Check if TOKEN is set**: Verify `echo $TOKEN` returns a value (or ask the user)
2. **Confirm environment**: User must specify `stage` or `prod`
3. **If any are missing**: DO NOT run the query. Inform the user and provide instructions.
4. **Only after all are confirmed**: Proceed with running the query

## CRITICAL REQUIREMENTS - READ BEFORE RUNNING QUERIES

**NEVER run a query without BOTH of the following:**
1. **TOKEN environment variable must be set** - Check with `echo $TOKEN` or ask the user
2. **Environment must be explicitly specified** - Must be either `stage` or `prod`

**If TOKEN is not set OR environment is not specified, DO NOT run the query. Instead:**
- Inform the user that the TOKEN and/or environment is required
- Provide instructions on how to obtain the token (see below)
- Wait for the user to set the TOKEN before proceeding

## Prerequisites

### Step 0: Check for config.env file

**IMPORTANT**: Before proceeding, verify that `.cursor/skills/config.env` exists. If it does not exist:

1. Copy the example file: `cp .cursor/skills/config.env.example .cursor/skills/config.env`
2. Update the values in `config.env` with your environment-specific settings
3. The script will fail if `config.env` is missing or incomplete

**WARNING**: If `config.env` is missing, the script will use fallback defaults which may not work correctly. Always ensure `config.env` exists and is properly configured.

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

### Tenant Queries

#### Search for tenant by ID

```sql
SELECT * FROM api_tenant WHERE id=<tenant_id>
```

#### Search for tenant by org ID

```sql
SELECT * FROM api_tenant WHERE org_id=<org_id>
```

#### Search for tenant by account ID

```sql
SELECT * FROM api_tenant WHERE account_id=<account_id>
```

#### Get tenant information for a group

```sql
SELECT g.id as group_id, g.uuid as group_uuid, g.name as group_name, g.tenant_id, t.id as tenant_id, t.org_id, t.account_id
FROM management_group g
JOIN api_tenant t ON g.tenant_id = t.id
WHERE g.uuid = '<group-uuid-here>';
```

### Group Queries

#### Search for group by UUID

```sql
SELECT * FROM management_group WHERE uuid='<group-uuid-here>'
```

#### Search for group by ID

```sql
SELECT * FROM management_group WHERE id=<group_id>
```

#### List all principals/users in a group

```sql
SELECT DISTINCT
    p.id as principal_id,
    p.username,
    p.user_id,
    p.type as principal_type
FROM management_principal p
JOIN management_group_principals gp ON gp.principal_id = p.id
JOIN management_group g ON gp.group_id = g.id
WHERE g.uuid = '<group-uuid-here>'
ORDER BY p.username;
```

#### Search for roles assigned to a group (by UUID)

```sql
SELECT DISTINCT
    r.id as role_id,
    r.uuid as role_uuid,
    r.name as role_name,
    r.description as role_description,
    pol.id as policy_id,
    pol.name as policy_name
FROM management_role r
JOIN management_policy_roles pr ON pr.role_id = r.id
JOIN management_policy pol ON pr.policy_id = pol.id
JOIN management_group g ON pol.group_id = g.id
WHERE g.uuid = '<group-uuid-here>'
ORDER BY r.name;
```

#### Search for roles assigned to a group (by ID)

```sql
SELECT DISTINCT
    r.id as role_id,
    r.uuid as role_uuid,
    r.name as role_name,
    r.description as role_description,
    pol.id as policy_id,
    pol.name as policy_name
FROM management_role r
JOIN management_policy_roles pr ON pr.role_id = r.id
JOIN management_policy pol ON pr.policy_id = pol.id
JOIN management_group g ON pol.group_id = g.id
WHERE g.id = <group-id-here>
ORDER BY r.name;
```

#### Search for all permissions a group is assigned (by UUID)

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

#### Search for all permissions a group is assigned (by ID)

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
WHERE g.id = <group-id-here>
ORDER BY p.application, p.resource_type, p.verb;
```

### Role Queries

#### Search for role by UUID

```sql
SELECT * FROM management_role WHERE uuid='<role-uuid-here>'
```

#### Search for role by ID

```sql
SELECT * FROM management_role WHERE id=<role_id>
```

#### Search for permissions assigned to a role (by UUID)

```sql
SELECT DISTINCT
    p.id as permission_id,
    p.permission,
    p.application,
    p.resource_type,
    p.verb,
    p.description
FROM management_permission p
JOIN management_access a ON a.permission_id = p.id
JOIN management_role r ON a.role_id = r.id
WHERE r.uuid = '<role-uuid-here>'
ORDER BY p.application, p.resource_type, p.verb;
```

#### Search for permissions assigned to a role (by ID)

```sql
SELECT DISTINCT
    p.id as permission_id,
    p.permission,
    p.application,
    p.resource_type,
    p.verb,
    p.description
FROM management_permission p
JOIN management_access a ON a.permission_id = p.id
JOIN management_role r ON a.role_id = r.id
WHERE r.id = <role-id-here>
ORDER BY p.application, p.resource_type, p.verb;
```

### Policy Queries

#### Search for policy by group_id

```sql
SELECT * FROM management_policy WHERE group_id=<group_id>
```

#### Search for roles assigned to a policy

```sql
SELECT pr.*, r.id as role_id, r.uuid as role_uuid, r.name as role_name
FROM management_policy_roles pr
LEFT JOIN management_role r ON pr.role_id = r.id
WHERE pr.policy_id=<policy_id>
```

### Workspace Queries

#### Search for workspace by ID

```sql
SELECT w.id as workspace_id, w.name as workspace_name, w.type as workspace_type, w.description, w.tenant_id, t.org_id, t.account_id
FROM management_workspace w
JOIN api_tenant t ON w.tenant_id = t.id
WHERE w.id = '<workspace-id-here>';
```

#### Get workspace parent information

```sql
SELECT w.id as workspace_id, w.name as workspace_name, w.parent_id, p.id as parent_workspace_id, p.name as parent_workspace_name, p.type as parent_workspace_type
FROM management_workspace w
LEFT JOIN management_workspace p ON w.parent_id = p.id
WHERE w.id = '<workspace-id-here>';
```

#### Count workspaces for a tenant

```sql
SELECT COUNT(*) as workspace_count
FROM management_workspace
WHERE tenant_id = <tenant_id>;
```

#### List workspaces for a tenant

```sql
SELECT w.id as workspace_id, w.name as workspace_name, w.type as workspace_type, w.description, w.parent_id, w.created, w.modified
FROM management_workspace w
WHERE w.tenant_id = <tenant_id>
ORDER BY w.created;
```

#### Count workspaces for an org

```sql
SELECT COUNT(*) as workspace_count 
FROM management_workspace 
WHERE tenant_id = (SELECT id FROM api_tenant WHERE org_id = '<org_id>');
```

#### List workspaces for an org

```sql
SELECT w.id, w.name, w.type, w.created 
FROM management_workspace w 
JOIN api_tenant t ON w.tenant_id = t.id 
WHERE t.org_id = '<org_id>' 
ORDER BY w.created;
```
