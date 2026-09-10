# Kessel Check: `role_binding_view` diagrams

The diagrams use relation names from the generated `schema.zed`.

## Diagram 1: Workspace evaluation tree

```mermaid
graph TD
    CHECK["CheckForUpdate<br/><b>rbac/workspace:XXXX</b><br/>role_binding_view<br/><b>rbac/principal:redhat/58887411</b>"]
    CHECK --> ALIAS["<b>rbac/workspace</b><br/>role_binding_view = rbac_role_binding_view"]
    ALIAS --> UNION{{"OR (union +)"}}

    UNION --> DIRECT["<b>Direct path</b><br/>t_binding on this workspace"]
    UNION --> PARENT["<b>Inherited path</b><br/>t_parent to a parent workspace"]

    DIRECT --> RB["<b>rbac/role_binding:RB_UUID</b><br/>rbac_role_binding_view"]
    RB --> AND{{"AND (intersection &)"}}
    AND --> SUBJECT["subject = t_subject"]
    AND --> ROLE_PERM["t_role->rbac_role_binding_view"]

    SUBJECT --> SUBJECT_OR{{"OR"}}
    SUBJECT_OR --> PRINCIPAL["t_subject:<br/><b>rbac/principal:redhat/58887411</b>"]
    SUBJECT_OR --> GROUP_SUBJECT["t_subject:<br/><b>rbac/group:GRP#member</b>"]
    GROUP_SUBJECT --> GROUP_MEMBER["rbac/group:GRP<br/>t_member:<br/><b>rbac/principal:redhat/58887411</b>"]

    ROLE_PERM --> ROLE["<b>rbac/role:ROLE_UUID</b><br/>rbac_role_binding_view"]
    ROLE --> ROLE_OR{{"OR (any one)"}}
    ROLE_OR --> R1["t_rbac_role_binding_view<br/><i>rbac:role_binding:view</i>"]
    ROLE_OR --> R2["t_rbac_role_binding_all<br/><i>rbac:role_binding:*</i>"]
    ROLE_OR --> R3["t_rbac_all_view<br/><i>rbac:*:view</i>"]
    ROLE_OR --> R4["t_rbac_all_all<br/><i>rbac:*:*</i>"]
    ROLE_OR --> R5["t_all_all_all<br/><i>*:*:*</i>"]
    ROLE_OR --> R6["t_child->rbac_role_binding_view<br/><i>child role</i>"]

    PARENT --> PARENT_WS["<b>rbac/workspace:PARENT</b><br/>evaluate the same permission"]
    PARENT_WS -.-> UNION

    style CHECK fill:#e1f5fe,stroke:#0288d1,stroke-width:3px
    style UNION fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style AND fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style ROLE_OR fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style SUBJECT_OR fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style R1 fill:#c8e6c9
    style R2 fill:#c8e6c9
    style R3 fill:#c8e6c9
    style R4 fill:#c8e6c9
    style R5 fill:#c8e6c9
    style R6 fill:#c8e6c9
```

## Diagram 2: Required tuples for custom workspace access

```mermaid
graph LR
    subgraph "Workspace binding"
        WS["rbac/workspace:XXXX"]
        RB["rbac/role_binding:RB_UUID"]
        WS -->|"#t_binding"| RB
    end

    subgraph "Binding subject"
        RB2["rbac/role_binding:RB_UUID"]
        P["rbac/principal:redhat/58887411"]
        RB2 -->|"#t_subject"| P
    end

    subgraph "Group subject (alternative)"
        RB3["rbac/role_binding:RB_UUID"]
        G["rbac/group:GRP_UUID#member"]
        GM["rbac/group:GRP_UUID"]
        P2["rbac/principal:redhat/58887411"]
        RB3 -->|"#t_subject"| G
        GM -->|"#t_member"| P2
    end

    subgraph "Binding role"
        RB4["rbac/role_binding:RB_UUID"]
        R["rbac/role:ROLE_UUID"]
        RB4 -->|"#t_role"| R
    end

    subgraph "Role grant (one is sufficient)"
        R2["rbac/role:ROLE_UUID"]
        P1["#t_rbac_role_binding_view"]
        P2R["#t_rbac_role_binding_all"]
        P3["#t_rbac_all_view"]
        P4["#t_rbac_all_all"]
        P5["#t_all_all_all"]
        R2 -.-> P1
        R2 -.-> P2R
        R2 -.-> P3
        R2 -.-> P4
        R2 -.-> P5
    end

    style WS fill:#e1f5fe
    style P fill:#fff9c4
    style P2 fill:#fff9c4
    style P1 fill:#c8e6c9
    style P2R fill:#c8e6c9
    style P3 fill:#c8e6c9
    style P4 fill:#c8e6c9
    style P5 fill:#c8e6c9
```

## Diagram 3: Workspace default access

Bindings on a parent workspace are inherited by descendants. Tenant and platform bindings are shown separately because they belong to tenant-resource checks.

```mermaid
graph TD
    subgraph "Workspace check"
        WS["<b>rbac/workspace:XXXX</b><br/>standard workspace"]
        DEFAULT["<b>rbac/workspace:DEFAULT</b><br/>default workspace"]
        ROOT["<b>rbac/workspace:ROOT</b><br/>root workspace"]
        WS -->|"t_parent"| DEFAULT
        DEFAULT -->|"t_parent"| ROOT

        DEFAULT_RB["rbac/role_binding:DEFAULT_RB"]
        ROOT_RB["rbac/role_binding:ROOT_RB"]
        DEFAULT -->|"t_binding"| DEFAULT_RB
        ROOT -->|"t_binding"| ROOT_RB

        DEFAULT_RB --> SUBJECT1["t_subject<br/>default group or principal"]
        ROOT_RB --> SUBJECT2["t_subject<br/>default group or principal"]
        DEFAULT_RB --> ROLE1["t_role<br/>role granting role_binding_view"]
        ROOT_RB --> ROLE2["t_role<br/>role granting role_binding_view"]
    end

    subgraph "Separate tenant check"
        TENANT["rbac/tenant:TENANT_RESOURCE_ID"]
        PLATFORM["rbac/platform:PLATFORM_ID"]
        TENANT_RB["rbac/role_binding:TENANT_RB"]
        PLATFORM_RB["rbac/role_binding:PLATFORM_RB"]
        TENANT -->|"t_binding"| TENANT_RB
        TENANT -->|"t_platform"| PLATFORM
        PLATFORM -->|"t_binding"| PLATFORM_RB
    end

    style WS fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style ROOT fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style TENANT fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style PLATFORM fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
```

## Diagram 4: Application code flow

```mermaid
flowchart TD
    REQ["HTTP request to role-binding endpoint"]
    REQ --> SYS["RoleBindingSystemUserAccessPermission"]
    SYS -->|"system user without admin"| DENY_SYS["DENY (403)"]
    SYS -->|"otherwise"| ACCESS["RoleBindingKesselAccessPermission"]

    ACCESS -->|"unknown resource_type"| DENY_TYPE["DENY (400)"]
    ACCESS -->|"workspace resource"| RELATION
    ACCESS -->|"tenant resource or no resource params"| TENANT_ID["Resolve request tenant<br/>and matching tenant resource ID"]
    TENANT_ID -->|"missing tenant or mismatch"| DENY_TENANT["DENY"]
    TENANT_ID -->|"matches"| TENANT_AUTH{"KESSEL_TENANT_AUTH_ENABLED?"}
    TENANT_AUTH -->|"No"| ADMIN{"request.user.admin?"}
    ADMIN -->|"No"| DENY_ADMIN["DENY (403)"]
    ADMIN -->|"Yes"| ALLOW_ADMIN["ALLOW"]
    TENANT_AUTH -->|"Yes"| RELATION

    RELATION{"USE_ROLE_BINDING_VIEW_PERMISSION?"}
    RELATION -->|"enabled"| RBV["selected relation = role_binding_view"]
    RELATION -->|"disabled"| VIEW["selected relation = view"]
    RBV --> CHECKER
    VIEW --> CHECKER

    CHECKER["WorkspaceInventoryAccessChecker<br/>check_resource_access()"]
    CHECKER --> GRPC["gRPC CheckForUpdate<br/>object: rbac/{resource_type}:{resource_id}<br/>relation: selected relation<br/>subject: rbac/principal:redhat/58887411"]
    GRPC --> SPICEDB["Kessel/SpiceDB evaluates schema"]
    SPICEDB -->|"ALLOWED_TRUE"| ALLOW["ALLOW"]
    SPICEDB -->|"ALLOWED_FALSE or transport error"| DENY["DENY (fail closed)"]

    style REQ fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style ALLOW fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style ALLOW_ADMIN fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style DENY_SYS fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style DENY_TYPE fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style DENY_TENANT fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style DENY_ADMIN fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style DENY fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style GRPC fill:#fff3e0,stroke:#f57c00,stroke-width:2px
```

## Diagram 5: Workspace hierarchy traversal

```mermaid
graph TD
    TARGET["<b>rbac/workspace:XXXX</b><br/>check t_binding here"]
    PARENT["<b>rbac/workspace:PARENT</b><br/>check t_binding here"]
    ROOT["<b>rbac/workspace:ROOT</b><br/>check t_binding here"]

    TARGET -->|"t_parent"| PARENT
    PARENT -->|"t_parent"| ROOT

    B1["role_binding:RB1<br/>direct binding"]
    B2["role_binding:RB2<br/>parent binding"]
    B3["role_binding:RB3<br/>root/default binding"]
    TARGET -->|"t_binding"| B1
    PARENT -->|"t_binding"| B2
    ROOT -->|"t_binding"| B3

    NOTE["A matching subject and role grant on any reachable workspace binding can satisfy the check.<br/>Tenant/platform bindings are evaluated by a separate tenant-resource check."]

    style TARGET fill:#e1f5fe,stroke:#0288d1,stroke-width:3px
    style ROOT fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style NOTE fill:#fffde7,stroke:#f9a825,stroke-width:1px,stroke-dasharray: 5 5
```

## Diagram 6: `role_binding_view` versus `view`

```mermaid
graph LR
    subgraph "role_binding_view (flag enabled)"
        direction TB
        RBV_WS["rbac/workspace<br/>role_binding_view"]
        RBV_WS --> RBV_ALIAS["rbac_role_binding_view"]
        RBV_ALIAS --> RBV_RB["role_binding<br/>subject & t_role->..."]
        RBV_RB --> RBV_ROLE["Role grants one of:"]
        RBV_ROLE --> RBV_1["rbac:role_binding:view"]
        RBV_ROLE --> RBV_2["rbac:role_binding:*"]
        RBV_ROLE --> RBV_3["rbac:*:view"]
        RBV_ROLE --> RBV_4["rbac:*:*"]
        RBV_ROLE --> RBV_5["*:*:*"]
    end

    subgraph "view (flag disabled)"
        direction TB
        V_WS["rbac/workspace<br/>view"]
        V_WS --> V_ALIAS["rbac_workspace_view"]
        V_ALIAS --> V_RB["role_binding<br/>subject & t_role->..."]
        V_RB --> V_ROLE["Role grants one of:"]
        V_ROLE --> V_1["inventory:groups:read"]
        V_ROLE --> V_2["inventory:groups:*"]
        V_ROLE --> V_3["inventory:*:read"]
        V_ROLE --> V_4["inventory:*:*"]
        V_ROLE --> V_5["*:*:*"]
    end

    DIFF["The application feature flag selects the relation.<br/>Both paths still require a matching subject and role grant."]
    style DIFF fill:#fffde7,stroke:#f9a825,stroke-width:2px
    style RBV_1 fill:#c8e6c9
    style RBV_2 fill:#c8e6c9
    style RBV_3 fill:#c8e6c9
    style RBV_4 fill:#c8e6c9
    style RBV_5 fill:#c8e6c9
    style V_1 fill:#bbdefb
    style V_2 fill:#bbdefb
    style V_3 fill:#bbdefb
    style V_4 fill:#bbdefb
    style V_5 fill:#bbdefb
```

## Diagram 7: Role-binding intersection

```mermaid
graph TD
    RB["rbac/role_binding:RB_UUID<br/>rbac_role_binding_view =<br/>(subject & t_role->rbac_role_binding_view)"]
    RB --> AND{{"AND gate (intersection)"}}
    AND --> LEFT["Subject check"]
    AND --> RIGHT["Role permission check"]

    LEFT --> L1["Direct t_subject principal"]
    LEFT --> L2["t_subject group#member"]
    L2 --> L3["Group t_member includes principal"]

    RIGHT --> R1["Direct or wildcard role permission"]
    RIGHT --> R2["Or inherited through t_child"]

    AND -->|"Both true"| ALLOW["ALLOWED"]
    AND -->|"Either false"| DENY["DENIED"]

    style AND fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    style ALLOW fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style DENY fill:#ffcdd2,stroke:#c62828,stroke-width:2px
```
