import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";
import "@typespec/versioning";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;

@service({title:"Role Based Access Control for Kessel Project"})

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
