# SpiceDB Replication Tuples Catalog

Catalog of all SpiceDB relation tuples created and removed by each API operation.

Tuple format: `namespace/type:id#relation@namespace/type:id`

---

## V2 APIs

### Create Role

- Add:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (one per permission)
- Remove: none

### Update Role

- Add:
  - `rbac/role:<role>#<new_perm>@rbac/principal:*` (per added permission)
- Remove:
  - `rbac/role:<role>#<old_perm>@rbac/principal:*` (per removed permission)

Unchanged permissions produce no tuples (minimal diff).

### Delete Role

- Add: none
- Remove:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (per permission)
  - `rbac/role_binding:<bind>#role@rbac/role:<role>` (per associated binding)
  - `rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<bind>` (per associated binding)
  - `rbac/role_binding:<bind>#subject@rbac/group:<group>#member` (per group on each binding)
  - `rbac/role_binding:<bind>#subject@rbac/principal:<domain>/<user_id>` (per principal on each binding)

### Create RoleBindings

Not yet implemented.

### Update RoleBindings by Subject

- Add:
  - `rbac/role_binding:<bind>#role@rbac/role:<role>` (per new binding)
  - `rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<bind>` (per new binding)
  - `rbac/role_binding:<bind>#subject@rbac/group:<group>#member` (per linked group)
  - `rbac/role_binding:<bind>#subject@rbac/principal:<domain>/<user_id>` (per linked principal)
- Remove:
  - `rbac/role_binding:<bind>#role@rbac/role:<role>` (per orphaned binding)
  - `rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<bind>` (per orphaned binding)
  - `rbac/role_binding:<bind>#subject@rbac/group:<group>#member` (per unlinked group)
  - `rbac/role_binding:<bind>#subject@rbac/principal:<domain>/<user_id>` (per unlinked principal)

---

## V1 Dual-Write (current prod)

### Custom Roles

#### Create Custom Role

- Add:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (per permission)
  - `rbac/role_binding:<bind>#role@rbac/role:<role>` (per binding)
  - `rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<bind>` (per binding)
  - `rbac/role_binding:<bind>#subject@rbac/group:<group>#member` (per group)
  - `rbac/role_binding:<bind>#subject@rbac/principal:<domain>/<user_id>` (per user)
- Remove: none

Note: v1 bundles everything (permissions + bindings + subjects + resource scoping)
because v1 does not separate roles from bindings. The migration synthesizes bindings
from the v1 Policy -> Group -> Role chain.

#### Update Custom Role

- Add: same types as Create Custom Role (new state from `migrate_role`)
- Remove: same types as Create Custom Role (old state from `prepare_for_update`)

This is a full replace strategy: all old tuples removed, all new tuples added.

#### Delete Custom Role

- Add: none
- Remove:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (per permission)
  - `rbac/role_binding:<bind>#role@rbac/role:<role>` (per binding)
  - `rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<bind>` (per binding)
  - `rbac/role_binding:<bind>#subject@rbac/group:<group>#member` (per group)
  - `rbac/role_binding:<bind>#subject@rbac/principal:<domain>/<user_id>` (per user)

### System Roles

#### Create System Role

- Add:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (per permission)
  - `rbac/role:<parent>#child@rbac/role:<role>` (if admin_default or platform_default)
- Remove: none

#### Update System Role

- Add: same as Create System Role (new state)
- Remove: same as Create System Role (old state, all scopes)

#### Delete System Role

- Add: none
- Remove:
  - `rbac/role:<role>#<perm>@rbac/principal:*` (per permission)
  - `rbac/role:<parent>#child@rbac/role:<role>` (all scopes)

---

## Key Differences: V1 vs V2

1. **V1 Create bundles everything** (permissions + bindings + subjects + scoping).
   V2 Create only produces permission tuples; bindings are separate API calls.

2. **V1 Update is full replace** (remove all old, add all new).
   V2 Update computes a minimal diff (only changed permissions).

3. **V1 system roles replicate parent-child hierarchy** (`role#child`).
   V2 custom roles do not have this concept.

4. **V2 separates concerns**: `CustomRoleV2.replication_tuples` handles permission
   tuples, `RoleBinding.replication_tuples` handles binding/subject tuples.

---

## Tuple Shapes Reference

### Permission tuple (on role)
```
rbac/role:<role_uuid>#<perm_v2_string>@rbac/principal:*
```
Example: `rbac/role:abc-123#inventory_hosts_read@rbac/principal:*`

### Role relation tuple (on binding)
```
rbac/role_binding:<binding_uuid>#role@rbac/role:<role_uuid>
```

### Resource binding tuple
```
rbac/<resource_type>:<resource_id>#binding@rbac/role_binding:<binding_uuid>
```
Example: `rbac/workspace:org-456#binding@rbac/role_binding:bind-789`

### Group subject tuple
```
rbac/role_binding:<binding_uuid>#subject@rbac/group:<group_uuid>#member
```

### Principal subject tuple
```
rbac/role_binding:<binding_uuid>#subject@rbac/principal:<domain>/<user_id>
```
Example: `rbac/role_binding:bind-789#subject@rbac/principal:redhat.com/jsmith`

### Parent-child role tuple (system roles only)
```
rbac/role:<parent_uuid>#child@rbac/role:<child_uuid>
```

---

## Code Locations

- `CustomRoleV2.replication_tuples` -- `rbac/management/role/v2_model.py`
- `CustomRoleV2._permission_tuple` -- `rbac/management/role/v2_model.py`
- `RoleBinding.replication_tuples` -- `rbac/management/role_binding/model.py`
- `RoleBinding.all_tuples` -- `rbac/management/role_binding/model.py`
- `RoleBinding.binding_tuples` -- `rbac/management/role_binding/model.py`
- `RoleBinding.subject_tuple` -- `rbac/management/role_binding/model.py`
- `RoleV2Service.create` -- `rbac/management/role/v2_service.py`
- `RoleBindingService.update_role_bindings_for_subject` -- `rbac/management/role_binding/service.py`
- `RelationApiDualWriteHandler` -- `rbac/management/role/relation_api_dual_write_handler.py`
- `SeedingRelationApiDualWriteHandler` -- `rbac/management/role/relation_api_dual_write_handler.py`
- `V2rolebinding.as_tuples` -- `rbac/migration_tool/models.py`
- `migrate_role` -- `rbac/migration_tool/migrate_role.py`
