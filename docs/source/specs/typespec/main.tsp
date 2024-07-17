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

model Link {
    @format("uri")
    first: string = "/api/v2/(resources)/?offset=0&limit=10";
    @format("uri")
    previous: string = "/api/v2/(resources)/?offset=20&limit=10";
    @format("uri")
    next: string = "/api/v2/(resources)/?offset=40&limit=10";
    @format("uri")
    last: string = "/api/v2/(resources)/?offset=90&limit=10";
}

model Meta {
    count: int64 = 30
}

model ListResponse<T> {
    data: T[];
    links: Link;
    meta: Meta;
}

model Timestamps {
    @doc("2019-01-21T17:32:28Z")
    created: offsetDateTime;
    @doc("2019-01-21T17:32:28Z")
    modified: offsetDateTime;
}

model ListQueryParams {
    @doc("Parameter for selecting the amount of data returned.")
    @maxValue(1000)
    @minValue(1)
    @query limit?: integer = 10,
    @query offset?: integer = 0,
    @doc("Parameter for ordering by value. For inverse ordering, supply '-' before the param value, such as: ?order_by=-name")
    @query order_by?: OrderByDefaultValues;
}

@format("uuid")
scalar UUID extends string;

enum OrderByDefaultValues {
    name,
    modified
}


model OkResponseForModel<T>{
    @statusCode
    statusCode: 200,
    ...T
}

namespace Problems {
    enum ProblemType {
        InsufficientPermission:"http://project-kessel.github.io",
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
        detail: "Not found"
    }
    
    alias Problem500 = ProblemDetails<Status = 500>;

    @error
    model Problem400 extends ProblemDetails<Status = 400>{
        detail: "JSON parse error - Expecting value: line 1 column 1 (char 0)",
    }

    alias Problem400AlreadyExists = ProblemDetails<Status = 400>;

    alias CommonProblems = Problem401 | Problem403 | Problem500;
}

@route("/workspaces")
@tag("Workspaces")
@doc("Operations about workspaces")
namespace Workspaces {
    model BasicWorkspace {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }

    model Workspace {
        @key uuid: UUID;
        parent?: UUID;
        ...BasicWorkspace;
        ...Timestamps;
    }

    alias CreateWorkspaceRequest = BasicWorkspace;

    model CreateWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 201;
    }

    model GetWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 200;
    }
    
    alias PutWorkspaceRequest = BasicWorkspace;

    model PutWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 200;
    }

    model DeleteWorkspaceResponse{
        @statusCode
        statusCode: 201,
    }
   
    @doc("Create workspace in tenant")
    @summary("Create workspace in tenant")
    @post op create(@body body: CreateWorkspaceRequest): CreateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400;

    model WorkspaceListResponse is ListResponse<Workspace>;
    @doc("By default, responses are sorted in ascending order by workspace name")
    @summary("List workspaces for tenant")
    @get op list(...ListQueryParams): WorkspaceListResponse | Problems.CommonProblems;

    @doc("Get a workspace in tenant")
    @summary("Get a workspace in tenant")
    @get op read(
        @doc("Unique identification")
        @path uuid: UUID;
    ): GetWorkspaceResponse | Problems.CommonProblems | Problems.Problem404;

    @doc("Edit a workspace")
    @summary("Edit the workspace name or description")
    @put op   update(
        @doc("Unique identification")
        @path uuid: UUID;
        @body body: PutWorkspaceRequest
    ): PutWorkspaceResponse | Problems.Problem400AlreadyExists | Problems.CommonProblems;

    @doc("Delete a workspace")
    @summary("Delete the workspace")
    @delete op delete(
        @doc("Unique identification")
        @path uuid: UUID;
    ): DeleteWorkspaceResponse | Problems.CommonProblems;
}
