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
        detail: "Not found"
    }
    
    alias Problem500 = ProblemDetails<Status = 500>;

    @error
    model Problem400 extends ProblemDetails<Status = 400>{
        detail: "JSON parse error - Expecting value: line 1 column 1 (char 0)",
    }

    alias Problem400AlreadyExists = ProblemDetails<Status = 400>;
    
    alias CommonProblems = Problem401 | Problem403 | Problem500;

    namespace Workspace {
        model Problem400WorkspaceNotEmpty extends Problems.ProblemDetails<Status = 400>{
            title: "Unable to delete due to workspace dependencies",
        }
    }
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
        @statusCode _: 204;
    }

    model GetWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 200;
    }

    model PutWorkspaceRequest {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description: string = "Description of Workspace A";
    }

    model PatchWorkspaceRequest {
        @doc("Workspace A")
        name?: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }

    model PutWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 201;
    }

    model PatchWorkspaceResponse extends BasicWorkspace{
        @statusCode _: 204;
    }

    model DeleteWorkspaceResponse{
        @statusCode
        statusCode: 201,
    }
   
    @doc("Create workspace in tenant")
    @summary("Create workspace in tenant")
    @post op create(@body body: CreateWorkspaceRequest): CreateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400;

    @doc("Get a workspace in tenant")
    @summary("Get a workspace in tenant")
    @get op read(
        @doc("Unique identification")
        @path uuid: UUID;
    ): GetWorkspaceResponse | Problems.CommonProblems | Problems.Problem404;

    @doc("Edit a workspace")
    @summary("Edit the workspace name or description")
    @put op update(
        @doc("Unique identification")
        @path uuid: UUID;
        @body body: PutWorkspaceRequest
    ): PutWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @patch op patch(
        @doc("Unique identification")
        @path uuid: UUID;
        @body body: PutWorkspaceRequest
    ): PatchWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @doc("Delete a workspace")
    @summary("Delete the workspace")
    @delete op delete(
        @doc("Unique identification")
        @path uuid: UUID;
    ): DeleteWorkspaceResponse | Problems.CommonProblems | Problems.Workspace.Problem400WorkspaceNotEmpty;
}
