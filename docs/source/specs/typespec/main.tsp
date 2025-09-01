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





    model Pagination {
        @doc("Pagination metadata")
        meta: CursorPaginationMeta;

        @doc("Pagination links")
        links: CursorPaginationLinks;
    }


    @example(#{
        meta: #{
            limit: 10
        },
        links: #{
            next: "/api/rbac/v2/workspaces?limit=10&cursor=eyJpZCI6IjE1NiIsImNyZWF0ZWQiOiIyMDI0LTA4LTA0VDEzOjAwOjAwWiJ9",
            previous: null
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

    @doc("List workspaces in a tenant")
    @summary("List workspaces in a tenant")

    @opExample(
      #{
        parameters: #{
          limit: 10,
          cursor: "eyJpZCI6IjEyMyIsImNyZWF0ZWQiOiIyMDI0LTA4LTA0VDEyOjAwOjAwWiJ9"
        },
        returnType: #{
          meta: #{
            limit: 10
          },
          links: #{
            next: "/api/rbac/v2/workspaces/?limit=10&cursor=eyJpZCI6IjE1NiIsImNyZWF0ZWQiOiIyMDI0LTA4LTA0VDEzOjAwOjAwWiJ9",
            previous: null
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

        @doc("Cursor for cursor-based pagination.")
        @query cursor?: string;

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

@route("/role-bindings/")
@tag("Role Bindings")
@doc("Operations about role bindings")
namespace RoleBindings {
    @discriminator("type")
    model BaseSubject {
        @doc("Subject identifier")
        id?: UUID;
        @doc("Type of subject")
        type: string;
    }

    model UserDetails {
        @doc("Name of the user")
        username?: string;
    }

    model UserSubject extends BaseSubject {
        @doc("Type of subject")
        type: "user";
        @doc("User details")
        user?: UserDetails;
    }

    model GroupDetails {
        @doc("Name of the group")
        name?: string;
        @doc("Description of the group")
        description?: string;
        @doc("Number of users in the group")
        user_count?: int64;
    }

    model GroupSubject extends BaseSubject {
        @doc("Type of subject")
        type: "group";
        @doc("Group details")
        group?: GroupDetails;
    }

    alias Subject = UserSubject | GroupSubject;



    @discriminator("type")
    model BaseResource {
        @doc("Resource identifier")
        id?: UUID;
        @doc("Type of resource")
        @example("workspace")
        type: string;
    }

    model WorkspaceDetails {
        @doc("Name of the workspace")
        @example("Workspace A")
        name?: string;
        @example("default")
        type?: string;
        @doc("Description of the workspace")
        description?: string;
    }

    model WorkspaceResource extends BaseResource {
        @doc("Type of resource")
        type: "workspace";
        @doc("Workspace details")
        workspace?: WorkspaceDetails;
    }

    alias Resource = WorkspaceResource;

    model Role {
        @doc("Role identifier")
        id?: UUID;
        @doc("Name of the role")
        name?: string;
    }

    @example(#{
        last_modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
        subject: #{
            id: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            type: "group",
            group: #{
                name: "Engineering Team",
                description: "Development and engineering team",
                user_count: 25
            }
        },
        roles: #[
            #{
                id: "550e8400-e29b-41d4-a716-446655440002",
                name: "Workspace Admin"
            }
        ],
        resource: #{
            id: "550e8400-e29b-41d4-a716-446655440001",
            type: "workspace",
            workspace: #{
                name: "Engineering Workspace",
                type: "default",
                description: "Main workspace for engineering team"
            }
        }
    })
    model RoleBindingBySubject {
        @doc("Timestamp of last modification")
        last_modified?: offsetDateTime;
        @doc("Subject of the role binding")
        subject?: Subject;
        @doc("Roles assigned to the subject")
        roles?: Role[];
        @doc("Resource the roles apply to")
        resource?: Resource;
    }

    model RoleBindingBySubjectListResponse {
        @doc("Pagination metadata")
        meta: CursorPaginationMeta;
        @doc("Pagination links")
        links: CursorPaginationLinks;
        @doc("List of role bindings grouped by subject")
        data: RoleBindingBySubject[];
    }

    @doc("List role bindings grouped by subject")
    @summary("List role bindings grouped by subject")
    @route("by-subject")
    @opExample(#{
        parameters: #{
            limit: 10,
            cursor: "cD0yMDI1LTA4LTE1KzE0JTNBMDQlM0E0MS42ODM3NTIlMkIwMCUzQTAw"
        },
        returnType: #{
            meta: #{
                limit: 10
            },
            links: #{
                next: "http://localhost:8000/api/rbac/v2/role-bindings/by-subject/?cursor=cD0yMDI1LTA4LTE1KzE0JTNBMDQlM0E0MS42ODM3NTIlMkIwMCUzQTAw",
                previous: null
            },
            data: #[
                #{
                    last_modified: offsetDateTime.fromISO("2024-08-04T12:00:00Z"),
                    subject: #{
                        id: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        type: "group",
                        group: #{
                            name: "Engineering Team",
                            description: "Development and engineering team",
                            user_count: 25
                        }
                    },
                    roles: #[
                        #{
                            id: "550e8400-e29b-41d4-a716-446655440002",
                            name: "Workspace Admin"
                        }
                    ],
                    resource: #{
                        id: "550e8400-e29b-41d4-a716-446655440001",
                        type: "workspace",
                        workspace: #{
                            name: "Engineering Workspace",
                            type: "default",
                            description: "Main workspace for engineering team"
                        }
                    }
                }
            ]
        }
    })
    @get op listBySubject(
        @query limit?: int64 = 10;

        @doc("Cursor for cursor-based pagination.")
        @query cursor?: string;

        @doc("Filter by resource type")
        @example("workspace")
        @query resource_type?: string;
        @doc("Filter by resource ID")
        @example("550e8400-e29b-41d4-a716-446655440001")
        @query resource_id?: string;
        @doc("Filter by subject type")
        @example("group")
        @query subject_type?: string;
        @doc("Filter by subject ID")
        @example("550e8400-e29b-41d4-a716-446655440004")
        @query subject_id?: string;

        @doc("""
        Control which fields are included in the response to optimize payload size and improve performance.

        **Default Behavior (no fields parameter):**
        Basic required fields are always included: subject.id, subject.type, role.id, resource.type

        **When fields parameter is provided:**
        Only explicitly specified fields are included in the response. Type fields (subject.type, resource.type) are always required and included even if not specified.

        **Syntax:**
        - Use parentheses to specify fields for nested objects: `object(field1,field2)`
        - Use comma to separate multiple field specifications: `subject(name),resource(name),last_modified`
        - Fields not in parentheses apply to the root level

        **Available Fields:**

        **subject object (polymorphic - available fields depend on type):**
        - id (UUID) - always included
        - type (string) - always included, cannot be excluded (determines which additional fields are available)

        *When type = "user":*
        - user.username (string) - username of the user

        *When type = "group":*
        - group.name (string) - name of the group
        - group.description (string) - description of the group
        - group.user_count (integer) - number of users in the group

        **role object:**
        - id (UUID) - always included
        - name (string) - role display name

        **resource object (polymorphic - available fields depend on type):**
        - id (UUID) - always included
        - type (string) - always included, cannot be excluded (determines which additional fields are available)

        *When type = "workspace":*
        - workspace.name (string) - name of the workspace
        - workspace.type (string) - type of workspace (e.g., "default", "standard")
        - workspace.description (string) - description of the workspace

        **root level:**
        - last_modified (datetime) - timestamp of last modification

        **Examples:**
        - `subject(group.name,group.user_count)` - Include group name and user count (only for group subjects)
        - `subject(user.username)` - Include username (only for user subjects)
        - `role(name)` - Include role name
        - `resource(workspace.name,workspace.description)` - Include workspace name and description (only for workspace resources)
        - `subject(group.name),role(name),resource(workspace.name)` - Combine multiple object field specifications
        - `subject(user.username),role(name),last_modified` - Include user details, role name, and modification timestamp
        - `last_modified` - Include only modification timestamp (plus required fields)
        - `subject(group.name,group.user_count),resource(workspace.type)` - Mix group and workspace specific fields
        """)
        @example("subject(group.name,group.user_count),role(name),last_modified")
        @query fields?: string;
        @doc("Sort by specified field(s), prefix with '-' for descending order")
        @example("subject_name,-subject_type")
        @query order_by?: string;

    ): RoleBindingBySubjectListResponse | Problems.CommonProblems;
}
