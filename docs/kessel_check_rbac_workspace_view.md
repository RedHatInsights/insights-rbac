# Kessel Permission Check: `rbac_workspace_view` on Tenant

## Command

```bash
zed permission check rbac/tenant:redhat/20228402 rbac_workspace_view rbac/principal:redhat/58887411 --explain
```

| Parameter | Value |
|-----------|-------|
| **Resource** | `rbac/tenant:redhat/20228402` |
| **Permission** | `rbac_workspace_view` |
| **Subject** | `rbac/principal:redhat/58887411` |

**Question being asked:** *"Can principal `redhat/58887411` view workspaces on tenant `redhat/20228402`?"*

---

## SpiceDB Schema Definitions Involved

### 1. `rbac/tenant`

```zed
definition rbac/tenant {
    relation t_binding: rbac/role_binding
    relation t_platform: rbac/platform

    permission rbac_workspace_view =
        t_binding->rbac_workspace_view
        + t_platform->rbac_workspace_view
}
```

The tenant resolves `rbac_workspace_view` by looking at:
- **Direct bindings** on the tenant (`t_binding`)
- **Platform-level bindings** (`t_platform`)

### 2. `rbac/role_binding`

```zed
definition rbac/role_binding {
    relation t_role: rbac/role
    relation t_subject: rbac/principal | rbac/group#member

    permission rbac_workspace_view =
        subject & t_role->rbac_workspace_view
}
```

The role binding uses an **intersection** (`&`):
- The principal must be a **subject** of the binding (left side)
- AND the binding's **role** must grant the permission (right side)

Both conditions must be true simultaneously.

### 3. `rbac/role`

```zed
definition rbac/role {
    relation t_child: rbac/role
    relation t_inventory_groups_read: rbac/principal:*
    relation t_inventory_groups_all: rbac/principal:*
    relation t_inventory_all_read: rbac/principal:*
    relation t_inventory_all_all: rbac/principal:*
    relation t_all_all_all: rbac/principal:*

    permission rbac_workspace_view =
        inventory_groups_read + inventory_groups_all
        + inventory_all_read + inventory_all_all
        + all_all_all
        + t_child->rbac_workspace_view
}
```

A role grants `rbac_workspace_view` if it has **any** of these permission relations, or if any of its **child roles** (`t_child`) grant it.

### 4. `rbac/group` (if subject is via group membership)

```zed
definition rbac/group {
    permission member = t_member
    relation t_member: rbac/principal | rbac/group#member
}
```

---

## Relations Required (Relationship Tuples)

For this check to return **ALLOWED**, the following relationship tuples must exist in SpiceDB:

### Relation 1: Tenant -> RoleBinding

```
rbac/tenant:redhat/20228402#t_binding@rbac/role_binding:<RB_UUID>
```

Attaches a role binding to the tenant.

The tenant can also reach a binding through its platform:

```
rbac/tenant:redhat/20228402#t_platform@rbac/platform:<PLATFORM_ID>
rbac/platform:<PLATFORM_ID>#t_binding@rbac/role_binding:<RB_UUID>
```

### Relation 2: RoleBinding -> Role

```
rbac/role_binding:<RB_UUID>#t_role@rbac/role:<ROLE_UUID>
```

Assigns a role to the role binding.

### Relation 3: RoleBinding -> Subject

The principal must be a subject of the role binding. **Two paths** are possible:

**Path A — Direct subject:**
```
rbac/role_binding:<RB_UUID>#t_subject@rbac/principal:redhat/58887411
```

**Path B — Via group membership (2 tuples):**
```
rbac/role_binding:<RB_UUID>#t_subject@rbac/group:<GRP_UUID>#member
rbac/group:<GRP_UUID>#t_member@rbac/principal:redhat/58887411
```

### Relation 4: Role -> Permission grant

The role must have at least **one** of these relations:

```
rbac/role:<ROLE_UUID>#t_inventory_groups_read@rbac/principal:*
rbac/role:<ROLE_UUID>#t_inventory_groups_all@rbac/principal:*
rbac/role:<ROLE_UUID>#t_inventory_all_read@rbac/principal:*
rbac/role:<ROLE_UUID>#t_inventory_all_all@rbac/principal:*
rbac/role:<ROLE_UUID>#t_all_all_all@rbac/principal:*
```

Or inherited from a child role:
```
rbac/role:<ROLE_UUID>#t_child@rbac/role:<CHILD_ROLE_UUID>
```
(where the child role has one of the above permissions)

---

## Resolution Flow

```
Step 1: START
        Check rbac/tenant:redhat/20228402#rbac_workspace_view@rbac/principal:redhat/58887411

Step 2: TENANT resolves rbac_workspace_view
        = t_binding->rbac_workspace_view + t_platform->rbac_workspace_view
        → Find all role_bindings attached to tenant via t_binding
        → Also traverse t_platform to reach the platform's t_binding role_bindings

Step 3: ROLE_BINDING resolves rbac_workspace_view (AND gate)
        = t_subject & t_role->rbac_workspace_view
        → LEFT:  Is principal:redhat/58887411 a subject? (direct or via group)
        → RIGHT: Does the role grant rbac_workspace_view?
        → BOTH must be true

Step 4: ROLE resolves rbac_workspace_view
        = inventory_groups_read + inventory_groups_all
          + inventory_all_read + inventory_all_all
          + all_all_all
          + t_child->rbac_workspace_view
        → Does the role (or any child role) have one of these permission relations?

Step 5: RESULT
        If all steps resolve → ALLOWED
        If any step fails    → NOT ALLOWED
```

---

## Concrete Example

Given these tuples in SpiceDB:

```
rbac/tenant:redhat/20228402#t_binding@rbac/role_binding:bind-001
rbac/role_binding:bind-001#t_role@rbac/role:workspace-viewer-role
rbac/role_binding:bind-001#t_subject@rbac/group:all-users-group#member
rbac/group:all-users-group#t_member@rbac/principal:redhat/58887411
rbac/role:workspace-viewer-role#t_inventory_groups_read@rbac/principal:*
```

The check resolves as:

```
1. tenant:redhat/20228402 has t_binding → role_binding:bind-001           ✅
2. role_binding:bind-001 checks AND gate:
   a. Subject: principal:redhat/58887411 ∈ group:all-users-group#member   ✅
   b. Role:    role:workspace-viewer-role has inventory_groups_read        ✅
3. Result: ALLOWED                                                        ✅
```

---

## What Permission Does `rbac_workspace_view` Map To?

| SpiceDB Permission | V2 Role Permission Strings |
|---|---|
| `inventory_groups_read` | `inventory:groups:read` |
| `inventory_groups_all` | `inventory:groups:*` |
| `inventory_all_read` | `inventory:*:read` |
| `inventory_all_all` | `inventory:*:*` |
| `all_all_all` | `*:*:*` |

A role with **any** of these V2 permission strings will grant `rbac_workspace_view`.

---

## Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  rbac/tenant:redhat/20228402                                        │
│                                                                      │
│  permission rbac_workspace_view =                                    │
│      t_binding->rbac_workspace_view                                  │
│      + t_platform->rbac_workspace_view                               │
│           │                    │                                     │
└───────────┼────────────────────┼─────────────────────────────────────┘
            │ t_binding          │ t_platform
            ▼                    ▼
                          ┌────────────────────────────┐
                          │ rbac/platform:<PLATFORM_ID> │
                          │   t_binding                 │
                          └──────────────┬─────────────┘
                                         │ t_binding
                                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  rbac/role_binding:<RB_UUID>                                         │
│                                                                      │
│  permission rbac_workspace_view =                                    │
│      subject    &  t_role->rbac_workspace_view                       │
│          │                    │                                       │
└──────────┼────────────────────┼──────────────────────────────────────┘
           │                    │
     ┌─────┘                    └─────┐
     │ t_subject                      │ t_role
     ▼                                ▼
┌─────────────────────┐   ┌───────────────────────────────────────────┐
│ PATH A (direct):    │   │  rbac/role:<ROLE_UUID>                     │
│ rbac/principal:     │   │                                            │
│ redhat/58887411     │   │  permission rbac_workspace_view =          │
│                     │   │    inventory_groups_read                    │
│ PATH B (via group): │   │    + inventory_groups_all                  │
│ rbac/group:<GRP>    │   │    + inventory_all_read                    │
│   #member           │   │    + inventory_all_all                     │
│     │               │   │    + all_all_all                           │
│     ▼               │   │    + t_child->rbac_workspace_view          │
│ rbac/principal:     │   │              │                              │
│ redhat/58887411     │   │              ▼                              │
│                     │   │    rbac/role:<ROLE_UUID>                    │
│                     │   │    #t_inventory_groups_read                 │
│                     │   │    @rbac/principal:*                        │
└─────────────────────┘   └───────────────────────────────────────────┘
         ▲                                ▲
         │                                │
    BOTH MUST PASS (intersection / AND gate)
```
