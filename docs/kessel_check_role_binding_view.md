# Kessel Check: `rbac/workspace:XXXX` `role_binding_view` `rbac/principal:redhat/58887411`

## Overview

This document describes how the generated Kessel/SpiceDB schema evaluates:

```
CheckPermission(
  resource:  rbac/workspace:XXXX
  permission: role_binding_view
  subject:   rbac/principal:redhat/58887411
)
```

The check answers: “Can principal `redhat/58887411` view role bindings on workspace `XXXX`?”

The relation names below are the names exposed by the generated `schema.zed`. The KSL source uses shorter names such as `binding`, `parent`, `subject`, and `role`; the generated schema exposes their `t_*` tuple relations.

## 1. Schema resolution

The current schema resolves the check through these definitions:

```zed
definition rbac/workspace {
    permission role_binding_view = rbac_role_binding_view

    permission rbac_role_binding_view =
        t_binding->rbac_role_binding_view
        + t_parent->rbac_role_binding_view
}

definition rbac/role_binding {
    permission subject = t_subject
    relation t_subject: rbac/principal | rbac/group#member
    relation t_role: rbac/role

    permission rbac_role_binding_view =
        subject & t_role->rbac_role_binding_view
}

definition rbac/role {
    permission rbac_role_binding_view =
        t_rbac_role_binding_view
        + rbac_role_binding_all
        + rbac_all_view
        + rbac_all_all
        + all_all_all
        + t_child->rbac_role_binding_view
}
```

The evaluation therefore has three gates:

1. The target workspace has a direct binding or inherits one from a parent workspace.
2. The role binding has the requesting principal as its subject, directly or through a group.
3. The role grants the RBAC role-binding view permission, directly, through a wildcard, or through a child role.

Tenant and platform bindings are evaluated by the tenant resource check. They are not parent edges in the workspace permission path.

## 2. Feature flag

`RoleBindingKesselAccessPermission` chooses the read relation through the `USE_ROLE_BINDING_VIEW_PERMISSION` feature flag:

| Flag state | Relation checked | Workspace schema entry point |
|---|---|---|
| Enabled (default) | `role_binding_view` | `rbac/workspace.role_binding_view` |
| Disabled | `view` | `rbac/workspace.view` |

The `role_binding_view` path uses RBAC permissions. The compatibility `view` path uses the inventory workspace-view permission family.

## 3. Tuples required for a workspace check

### Direct binding on the target workspace

The workspace must reference a role binding:

```
rbac/workspace:XXXX#t_binding@rbac/role_binding:RB_UUID
```

The role binding must reference both a subject and a role:

```
rbac/role_binding:RB_UUID#t_subject@rbac/principal:redhat/58887411
rbac/role_binding:RB_UUID#t_role@rbac/role:ROLE_UUID
```

For group-based access, use the group permission as the role-binding subject and add the principal to the group:

```
rbac/role_binding:RB_UUID#t_subject@rbac/group:GRP_UUID#member
rbac/group:GRP_UUID#t_member@rbac/principal:redhat/58887411
```

The role must grant `rbac_role_binding_view` through at least one of these generated relations:

```
rbac/role:ROLE_UUID#t_rbac_role_binding_view@rbac/principal:*
rbac/role:ROLE_UUID#t_rbac_role_binding_all@rbac/principal:*
rbac/role:ROLE_UUID#t_rbac_all_view@rbac/principal:*
rbac/role:ROLE_UUID#t_rbac_all_all@rbac/principal:*
rbac/role:ROLE_UUID#t_all_all_all@rbac/principal:*
```

A parent role can provide the same permission through a child role:

```
rbac/role:ROLE_UUID#t_child@rbac/role:CHILD_ROLE_UUID
```

The child role must have one of the permission relations above.

### Parent workspace inheritance

Workspace inheritance uses workspace-to-workspace parent tuples:

```
rbac/workspace:XXXX#t_parent@rbac/workspace:PARENT_UUID
```

The same direct-binding check is then evaluated on `PARENT_UUID`, recursively up the workspace hierarchy. A binding on a root workspace can therefore be inherited by its descendants; a binding on the default workspace can be inherited by its children.

### Tenant and platform checks

A tenant-level role-binding check starts at a tenant resource instead of a workspace:

```
rbac/tenant:TENANT_RESOURCE_ID#t_binding@rbac/role_binding:RB_UUID
rbac/tenant:TENANT_RESOURCE_ID#t_platform@rbac/platform:PLATFORM_ID
rbac/platform:PLATFORM_ID#t_binding@rbac/role_binding:RB_UUID
```

The tenant permission is the union of direct tenant bindings and platform bindings. This path is separate from workspace parent inheritance.

## 4. Permission comparison

| Aspect | `role_binding_view` | `view` |
|---|---|---|
| Workspace alias | `rbac_role_binding_view` | `rbac_workspace_view` |
| Role permission strings | `rbac:role_binding:view`, `rbac:role_binding:*`, `rbac:*:view`, `rbac:*:*`, `*:*:*` | `inventory:groups:read`, `inventory:groups:*`, `inventory:*:read`, `inventory:*:*`, `*:*:*` |
| Use case | View role bindings | View workspace access |
| Workspace inheritance | Direct binding or parent workspace | Direct binding or parent workspace |

The feature flag changes which relation the RBAC API asks Kessel to evaluate. A principal can have inventory workspace access without having the RBAC permission required to view role bindings.

## 5. Application code flow

For a request with `resource_type=workspace` and `resource_id=XXXX`:

```
HTTP request to a role-binding endpoint
    |
    v
RoleBindingSystemUserAccessPermission
    |-- system user without admin --> DENY
    |-- otherwise ------------------> continue
    v
RoleBindingKesselAccessPermission
    |-- workspace --> select relation from feature flag
    |                 role_binding_view (enabled) or view (disabled)
    v
WorkspaceInventoryAccessChecker.check_resource_access()
    |
    v
gRPC CheckForUpdate(
    object:   rbac/workspace:XXXX,
    relation: selected relation,
    subject:  rbac/principal:redhat/58887411,
)
    |
    v
Kessel evaluates the schema graph
    |-- ALLOWED_TRUE  --> allow
    |-- ALLOWED_FALSE --> deny
    |-- transport error --> deny (fail closed)
```

When the request omits resource parameters, the permission class performs a tenant-level read check using the request tenant’s resource ID. For `resource_type=tenant`, the legacy path (`KESSEL_TENANT_AUTH_ENABLED=False`) validates the tenant ID and allows only org admins without calling Kessel. When `KESSEL_TENANT_AUTH_ENABLED=True`, tenant checks use the selected Kessel relation instead.

## 6. Example

With these tuples, the check is allowed through a group subject and a direct role permission:

```
rbac/workspace:XXXX#t_binding@rbac/role_binding:bind-001
rbac/role_binding:bind-001#t_role@rbac/role:role-001
rbac/role_binding:bind-001#t_subject@rbac/group:group-001#member
rbac/group:group-001#t_member@rbac/principal:redhat/58887411
rbac/role:role-001#t_rbac_role_binding_view@rbac/principal:*
```

The result is allowed because the workspace reaches the binding, the principal is a member of the binding’s subject group, and the role grants `rbac_role_binding_view`.
