import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";
import "@typespec/versioning";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;

@service(#{title:"Role Based Access Control for Kessel Project"})

@server("https://localhost:{port}/{basePath}", "Development Server", { basePath: string="api/rbac/v2", port: string="8000" })
@server("https://console.stage.redhat.com/{basePath}", "Stage Server", { basePath: string="api/rbac/v2" })
@server("https://console.redhat.com/{basePath}", "Production Server", { basePath: string="api/rbac/v2" })
@versioned(Versions)

namespace KesselRBAC;

enum Versions{
    v2,
}

model Timestamps {
    @doc("2019-01-21T17:32:28Z")
    created: offsetDateTime;
    @doc("2019-01-21T17:32:28Z")
    modified: offsetDateTime;
}

@format("uuid")
scalar UUID extends string;

namespace Problems {
    enum ProblemType {
        InsufficientPermission:"http://project-kessel.org/problems/insufficient-permission",
    }

    @error
    model ProblemDetails<Status extends valueof int16> {
        @header("content-type") contentType: "application/problem+json";
        type?: ProblemType;

        @statusCode _: typeof Status;
        status?: typeof Status;

        title?: string;
        detail?: string;

        @format("uri")
        instance?: string;
    }

    @error
    model Problem403 extends ProblemDetails<Status = 403>{
        type: ProblemType.InsufficientPermission,
        title: "You do not have permission to perform this action.";
    }

    alias Problem401 = ProblemDetails<Status = 401>;

    @error
    model Problem404 extends ProblemDetails<Status = 404>{
        title: "Resource was not found",
        @example("Not found")
        detail: string
    }

    alias Problem500 = ProblemDetails<Status = 500>;

    @error
    model Problem400 extends ProblemDetails<Status = 400>{
        title: "The request payload contains invalid syntax.",
        @example("JSON parse error - Expecting value: line 1 column 1 (char 0)")
        detail: string
    }

    alias Problem400AlreadyExists = ProblemDetails<Status = 400>;

    alias CommonProblems = Problem401 | Problem403 | Problem500;

    namespace Workspace {
        model Problem400WorkspaceNotEmpty extends Problems.ProblemDetails<Status = 400>{
            title: "Unable to delete due to workspace dependencies",
        }
    }
}

@route("/workspaces/")
@tag("Workspaces")
@doc("Operations about workspaces")
namespace Workspaces {
    @example(#{ name: "My First Workspace", description: "This is a basic workspace." })
    model BasicWorkspace {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }

    enum WorkspaceTypes {
        "root",
        "default",
        "standard",
        "ungrouped-hosts"
    }

    enum WorkspaceTypesQueryParam {
        "all",
        ...WorkspaceTypes
    }
    @example(#{
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: WorkspaceTypes.standard,
        name: "My first workspace",
        description: "This is a basic workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model Workspace {
        @key id: UUID;
        parent_id?: UUID;
        type: WorkspaceTypes;
        ...BasicWorkspace;
        ...Timestamps;
    }

    model WorkspaceAncestor {
        @key id: UUID;
        parent_id?: UUID;
        name: string;
    }

    @example(#{
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        name: "Alpha Workspace",
        description: "Create a standard workspace."
    })
    model CreateWorkspaceRequest extends BasicWorkspace{
        //if parent_id is not stated within the request for standard workspaces, it is automatically populated from default workspace.
        @doc("Parent ID of Workspace A")
        parent_id?: UUID = "Parent ID of Workspace A";
    }
    @example(#{
        _: 201,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace",
        description: "Create a standard workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model CreateWorkspaceResponse extends Workspace{
        @statusCode _: 201;
    }
    @example(#{
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace",
        description: "Create a standard workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model ReadWorkspaceResponse extends Workspace {
        @statusCode _: 200;
    }
    @example(#{
        ancestry: #[
            #{
                id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
                parent_id: "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
                name: "Default Workspace"
            }
        ],
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace",
        description: "Create a standard workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model ReadWorkspaceWithAncestryResponse extends ReadWorkspaceResponse {
        ancestry: WorkspaceAncestor[];
    }

    @example(#{
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        name: "Alpha Workspace",
        description: "Changing description of alpha workspace to something new."
    })
    model UpdateWorkspaceRequest {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description: string = "Description of Workspace A";
        @doc("Must match current parent_id value. Not updatable directly on the workspace.")
        parent_id: UUID = "Parent ID of Workspace A";
    }
    @example(#{
        name: "Alpha Workspace - closed",
        description: "Create a standard workspace."
    })
    model PatchWorkspaceRequest {
        @doc("Workspace A")
        name?: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }
    @example(#{
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace",
        description: "Changing description of alpha workspace to something new.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model UpdateWorkspaceResponse extends Workspace{
        @statusCode _: 200;
    }

    @example(#{
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace - closed",
        description: "Create a standard workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
    })
    model PatchWorkspaceResponse extends Workspace{
        @statusCode _: 200;
    }

    @example(#{ statusCode: 204 })
    model DeleteWorkspaceResponse{
        @statusCode
        statusCode: 204,
    }

    @example(#{ parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11" })
    model MoveWorkspaceRequest {
      @doc("The UUID of the new parent workspace.")
      parent_id: UUID = "Parent ID of target workspace";
    }
    @example(#{
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "f0e1d2c3-b4a5-4678-9a1b-c2d3e4f5a6b7"
    })
    model MoveWorkspaceResponse{
        @statusCode _: 200;
        @key id: UUID = "Workspace ID of moved workspace";
        parent_id: UUID = "New parent ID of moved workspace";
    }

    model PaginationMeta {
        @doc("Total count of objects")
        @example(10)
        count: int64;

        @doc("Limit of returned objects")
        @example(10)
        limit: int64 = 10;

        @doc("Offset of returned objects")
        @example(10)
        offset: int64;
    }

    model PaginationLinks {
        @doc("The first link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&offset=0")
        @format("uri")
        first: string;

        @doc("The next link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&offset=10")
        @format("uri")
        next: string | null;

        @doc("The previous link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&offset=0")
        @format("uri")
        previous: string | null;

        @doc("The last link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&offset=20")
        @format("uri")
        last: string;
    }

    model Pagination {
        @doc("Pagination metadata")
        meta: PaginationMeta;

        @doc("Pagination links")
        links: PaginationLinks;
    }

    model CursorPaginationMeta {
        @doc("Limit of returned objects")
        @example(10)
        limit: int64 = 10;
    }

    model CursorPaginationLinks {
        @doc("The next link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&cursor=eyJpZCI6IjEyMyJ9")
        @format("uri")
        next: string | null;

        @doc("The previous link in pagination")
        @example("/api/rbac/v2/(resource)/?limit=10&cursor=eyJpZCI6IjEwMCJ9")
        @format("uri")
        previous: string | null;
    }

    @example(#{
        meta: #{
            count: 50,
            limit: 10,
            offset: 0
        },
        links: #{
            first: "/api/rbac/v2/workspaces?limit=10&offset=0",
            next: "/api/rbac/v2/workspaces?limit=10&offset=10",
            previous: null,
            last: "/api/rbac/v2/workspaces?limit=10&offset=40"
        },
        data: #[
            #{
                id: "e4277742-b91c-43f1-a185-b827e8574345",
                parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
                type: WorkspaceTypes.standard,
                name: "My first workspace",
                description: "This is a basic workspace.",
                created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
                modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
            },
        ]
    })
    model WorkspaceListResponse {
        ...Pagination;

        @doc("List of workspaces")
        data: Workspace[];
    }

}

@route("/roles/")
@tag("Roles")
@doc("Read-only APIs for RoleV2 discovery and inspection")
namespace Roles {
  @doc("Lightweight pagination envelope (reuses shared cursor models)")
  model Pagination {
    meta: Workspaces.CursorPaginationMeta;
    links: Workspaces.CursorPaginationLinks;
  }

  enum RoleType {
    platform,
    seeded,
    custom
  }

  enum RoleScope {
    organization,
    root_workspace,
    default_workspace,
    none
  }

  @example(#{
    id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
    name: "Workspace Admin",
    display_name: "Workspace Admin",
    description: "Administrative permissions scoped to a workspace.",
    type: Roles.RoleType.seeded,
    scope: Roles.RoleScope.default_workspace,
    updated_at: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
  })
  model RoleSummary {
    @key id: UUID;
    name: string;
    display_name?: string;
    description?: string;
    type: RoleType;
    @doc("High-level applicability; not a resource binding")
    scope?: RoleScope = RoleScope.none;
    updated_at?: offsetDateTime;

    @doc("Optional, only when requested via include=stats")
    stats?: {
      permissions_count?: int64;
      workspace_count?: int64;
      group_count?: int64;
    };
  }

  @example(#{
    data: #{
      id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
      name: "Workspace Admin",
      display_name: "Workspace Admin",
      description: "Administrative permissions scoped to a workspace.",
      type: Roles.RoleType.seeded,
      scope: Roles.RoleScope.default_workspace,
      updated_at: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
      created_at: offsetDateTime.fromISO("2024-06-01T00:00:00Z"),
      parent: #{
        id: "11111111-2222-3333-4444-555555555555",
        name: "Parent Role"
      },
      children: #[
        #{
          id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          name: "Child Role"
        }
      ]
    }
  })
  model Role {
    data: RoleBody;
  }

  model RoleBody extends RoleSummary {
    @doc("Creation time")
    created_at?: offsetDateTime;

    @doc("Optional parent link when the role is derived")
    parent?: {
      id: UUID;
      name?: string;
    };

    @doc("Optional direct children")
    children?: {
      id: UUID;
      name?: string;
    }[];
  }

  @example(#{
    id: "f3db6c15-45ad-4f57-bbbf-4b1e2bd4c0a1",
    application: "inventory",
    resource: "host",
    action: "read",
    name: "inventory:host:read",
    description: "Read host metadata"
  })
  model Permission {
    @key id: UUID;
    application: string;
    resource: string;
    action: string;
    @doc("<application>:<resource>:<action>")
    name: string;
    description?: string;
  }

  model RoleListResponse {
    ...Pagination;
    data: RoleSummary[];
  }

  model PermissionListResponse {
    ...Pagination;
    data: Permission[];
  }

  // ---------- Operations ----------

  @doc("List roles visible to the caller's tenant")
  @summary("List roles")
  @opExample(#{
    parameters: #{
      x_consistency_zookie: "zkgAAAA...",
      limit: 20,
      filter_name: "admin",
      include: "stats"
    },
    returnType: #{
      meta: #{ limit: 20 },
      links: #{
        next: "/api/rbac/v2/roles/?limit=20&cursor=abc",
        previous: null
      },
      data: #[
        #{
          id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
          name: "Workspace Admin",
          display_name: "Workspace Admin",
          type: Roles.RoleType.seeded,
          scope: Roles.RoleScope.default_workspace,
          stats: #{ permissions_count: 12, workspace_count: 3, group_count: 2 }
        }
      ]
    }
  })
  @get op list(
    @header("X-Consistency-Zookie")
    @doc("Consistency token (zookie). If omitted, service may use an org-level token.")
    x_consistency_zookie?: string;

    @query limit?: int64 = 20;
    @query cursor?: string;

    @query filter_name?: string;
    @query filter_type?: RoleType;
    @query filter_scope?: RoleScope;
    @query filter_application?: string;
    @query filter_action?: string;

    @doc("Optional expansions: stats,parent,children (comma-separated)")
    @example("stats,parent")
    @query include?: string;
  ): RoleListResponse | Problems.CommonProblems;

  @doc("Get a single role")
  @summary("Read role")
  @route("{role_id}/")
  @opExample(#{
    parameters: #{
      role_id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
      include: "stats,children"
    },
    returnType: #{
      data: #{
        id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
        name: "Workspace Admin",
        display_name: "Workspace Admin",
        type: Roles.RoleType.seeded,
        scope: Roles.RoleScope.default_workspace,
        created_at: offsetDateTime.fromISO("2024-06-01T00:00:00Z"),
        updated_at: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        stats: #{ permissions_count: 12 }
      }
    }
  })
  @get op read(
    @header("X-Consistency-Zookie") x_consistency_zookie?: string,
    @path role_id: UUID,
    @query include?: string
  ): Role | Problems.CommonProblems | Problems.Problem404;

  @doc("List permissions that belong to a role")
  @summary("List role permissions")
  @route("{role_id}/permissions/")
  @opExample(#{
    parameters: #{
      role_id: "9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001",
      limit: 50,
      filter_application: "inventory",
      filter_resource: "host"
    },
    returnType: #{
      meta: #{ limit: 50 },
      links: #{
        next: "/api/rbac/v2/roles/9b4ef5f9-8d26-4b61-8c9f-8ab5d9e9c001/permissions/?limit=50&cursor=def",
        previous: null
      },
      data: #[
        #{
          id: "f3db6c15-45ad-4f57-bbbf-4b1e2bd4c0a1",
          application: "inventory",
          resource: "host",
          action: "read",
          name: "inventory:host:read",
          description: "Read host metadata"
        }
      ]
    }
  })
  @get op listPermissions(
    @header("X-Consistency-Zookie") x_consistency_zookie?: string,
    @path role_id: UUID,
    @query limit?: int64 = 50,
    @query cursor?: string,
    @query filter_application?: string,
    @query filter_resource?: string,
    @query filter_action?: string
  ): PermissionListResponse | Problems.CommonProblems | Problems.Problem404;
}

namespace Workspaces {
    @doc("List workspaces in a tenant")
    @summary("List workspaces in a tenant")

    @opExample(
      #{
        parameters: #{
          limit: 10,
          offset: 0
        },
        returnType: #{
          meta: #{
            count: 1,
            limit: 10,
            offset: 0
          },
          links: #{
            first: "/api/rbac/v2/workspaces/?limit=10&offset=0",
            next: "/api/rbac/v2/workspaces/?limit=10&offset=10",
            previous: null,
            last: "/api/rbac/v2/workspaces/?limit=10&offset=20"
          },
          data: #[
            #{
              id: "e4277742-b91c-43f1-a185-b827e8574345",
              parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
              type: WorkspaceTypes.standard,
              name: "My first workspace",
              description: "This is a basic workspace.",
              created: offsetDateTime.fromISO("2024-05-06T12:20-12-0700"),
              modified: offsetDateTime.fromISO("2024-05-06T12:20-12-0700")
            }
          ]
        }
      }
    )
    @get op list(
        @query limit?: int64 = 10;
        @query offset?: int64 = 0;

        @doc("Defaults to all when param is not supplied.")
        @query type?: WorkspaceTypesQueryParam = WorkspaceTypesQueryParam.all;
        @doc("Case sensitive exact match of workspace by name.")
        @query name?: string;
    ): WorkspaceListResponse | Problems.CommonProblems;

    @doc("Create workspace in tenant")
    @summary("Create workspace in tenant")
    @opExample(#{
        parameters: #{
                body: #{
                    name: "Alpha Workspace",
                    description: "Create a standard workspace.",
                }
        },
        returnType: #{
            _: 201,
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
            type: Workspaces.WorkspaceTypes.standard,
            name: "Alpha Workspace",
            description: "Create a standard workspace.",
            created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
            modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
            }
      }
    )
    @post op create(@body body: CreateWorkspaceRequest): CreateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400;

    @doc("Get a workspace in tenant")
    @summary("Get a workspace in tenant")
    @route("{id}/")
    // example for when we want to include ancestry
    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            include_ancestry: true
        },
        returnType: #{
            ancestry: #[
                #{
                    id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
                    parent_id: "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
                    name: "Default Workspace"
                }
            ],
            _: 200,
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
            type: Workspaces.WorkspaceTypes.standard,
            name: "Alpha Workspace",
            description: "Create a standard workspace.",
            created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
            modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
        }
    })
    //example for when we want to not include ancestry
    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            include_ancestry: true
        },
        returnType: #{
            _: 200,
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
            type: Workspaces.WorkspaceTypes.standard,
            name: "Alpha Workspace",
            description: "Create a standard workspace.",
            created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
            modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
        }
    })
    @get op read(
        @doc("Unique identification")
        @path id: UUID;

        @doc("When true, the response will include the ancestry of the workspace.")
        @query include_ancestry?: boolean;
    ): ReadWorkspaceResponse | ReadWorkspaceWithAncestryResponse | Problems.CommonProblems | Problems.Problem404;


    @doc("Edit a workspace")
    @summary("Edit the workspace name or description")
    @route("{id}/")
    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            body: #{
                parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
                name: "Alpha Workspace",
                description: "Changing description of alpha workspace to something new."
            }
        },
        returnType: #{
       _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace",
        description: "Changing description of alpha workspace to something new.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
            }
      }
    )
    @put op update(
        @doc("Unique identification")
        @path id: UUID;
        @body body: UpdateWorkspaceRequest
    ): UpdateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            body: #{
                name: "Alpha Workspace - closed",
                description: "Create a standard workspace."
            }
        },
        returnType: #{
        _: 200,
        id: "e4277742-b91c-43f1-a185-b827e8574345",
        parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11",
        type: Workspaces.WorkspaceTypes.standard,
        name: "Alpha Workspace - closed",
        description: "Create a standard workspace.",
        created: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z")
        }
      }
    )
    @route("{id}/")
    @patch op patch(
        @doc("Unique identification")
        @path id: UUID;
        @body body: PatchWorkspaceRequest
    ): PatchWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @doc("Delete a workspace")
    @summary("Delete the workspace")
    @route("{id}/")
    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345"
        },
        returnType: #{
            statusCode: 204
        }
      }
    )
    @delete op delete(
        @doc("Unique identification")
        @path id: UUID;
    ): DeleteWorkspaceResponse | Problems.CommonProblems | Problems.Workspace.Problem400WorkspaceNotEmpty;

    @doc("Move a workspace to a new parent.")
    @summary("Move a workspace to a new parent.")
    @route("{id}/move/")
    @opExample(#{
        parameters: #{
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            body: #{
                parent_id: "c1f729e2-3e2b-4f9e-b247-a4b568393e11"
            }
        },
        returnType: #{
            _: 200,
            id: "e4277742-b91c-43f1-a185-b827e8574345",
            parent_id: "f0e1d2c3-b4a5-4678-9a1b-c2d3e4f5a6b7"
            }
      }
    )
    @post op move(
        @doc("Unique identification of the workspace to move")
        @path id: UUID;
        @body body: MoveWorkspaceRequest
    ): MoveWorkspaceResponse
      | Problems.CommonProblems
      | Problems.Problem400
      | Problems.Problem404;
}
