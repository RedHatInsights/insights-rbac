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

    model CreateWorkspaceRequest extends BasicWorkspace{
        //if parent_id is not stated within the request for standard workspaces, it is automatically populated from default workspace.
        @doc("Parent ID of Workspace A")
        parent_id?: UUID = "Parent ID of Workspace A";
    }

    model CreateWorkspaceResponse extends Workspace{
        @statusCode _: 201;
    }

    model ReadWorkspaceResponse extends Workspace {
        @statusCode _: 200;
    }

    model ReadWorkspaceWithAncestryResponse extends ReadWorkspaceResponse {
        ancestry: WorkspaceAncestor[];
    }

    model UpdateWorkspaceRequest {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description: string = "Description of Workspace A";
        @doc("Must match current parent_id value. Not updatable directly on the workspace.")
        parent_id: UUID = "Parent ID of Workspace A";
    }

    model PatchWorkspaceRequest {
        @doc("Workspace A")
        name?: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }

    model UpdateWorkspaceResponse extends Workspace{
        @statusCode _: 200;
    }

    model PatchWorkspaceResponse extends Workspace{
        @statusCode _: 200;
    }

    model DeleteWorkspaceResponse{
        @statusCode
        statusCode: 204,
    }


    model MoveWorkspaceRequest {
      @doc("The UUID of the new parent workspace.")
      parent_id: UUID = "Parent ID of target workspace";
    }

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
        @example(1000)
        limit: int64 = 1000;

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

    model WorkspaceListResponse {
        ...Pagination;

        @doc("List of workspaces")
        data: Workspace[];
    }

    @doc("List workspaces in a tenant")
    @summary("List workspaces in a tenant")
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
    @post op create(@body body: CreateWorkspaceRequest): CreateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400;

    @doc("Get a workspace in tenant")
    @summary("Get a workspace in tenant")
    @route("{id}/")
    @get op read(
        @doc("Unique identification")
        @path id: UUID;

        @doc("When true, the response will include the ancestry of the workspace.")
        @query include_ancestry?: boolean;
    ): ReadWorkspaceResponse | ReadWorkspaceWithAncestryResponse | Problems.CommonProblems | Problems.Problem404;

    @doc("Edit a workspace")
    @summary("Edit the workspace name or description")
    @route("{id}/")
    @put op update(
        @doc("Unique identification")
        @path id: UUID;
        @body body: UpdateWorkspaceRequest
    ): UpdateWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @route("{id}/")
    @patch op patch(
        @doc("Unique identification")
        @path id: UUID;
        @body body: PatchWorkspaceRequest
    ): PatchWorkspaceResponse | Problems.CommonProblems | Problems.Problem400AlreadyExists ;

    @doc("Delete a workspace")
    @summary("Delete the workspace")
    @route("{id}/")
    @delete op delete(
        @doc("Unique identification")
        @path id: UUID;
    ): DeleteWorkspaceResponse | Problems.CommonProblems | Problems.Workspace.Problem400WorkspaceNotEmpty;

    @doc("Move a workspace to a new parent.")
    @summary("Move a workspace to a new parent.")
    @route("{id}/move/")
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
        @doc("Name of the subject")
        name?: string;
    }

    model UserSubject extends BaseSubject {
        @doc("Type of subject")
        type: "user";
    }

    model GroupSubject extends BaseSubject {
        @doc("Type of subject")
        type: "group";
        @doc("Number of users in the group")
        user_count?: int64;
    }

    alias Subject = UserSubject | GroupSubject;

    @discriminator("type")
    model BaseResource {
        @doc("Type of resource")
        @example("workspace")
        type: string;
        @doc("Name of the resource")
        @example("Workspace A")
        name?: string;
        @doc("Information about parent resource when inherited from parent (only when parent_role_bindings=true)")
        inherited_from?: {
            @doc("Parent resource type")
            @example("workspace")
            type: string;
            @doc("Parent resource name")
            @example("Workspace Z")
            name?: string;
        };
    }

    model WorkspaceResource extends BaseResource {
        @doc("Type of resource")
        type: "workspace";
    }

    alias Resource = WorkspaceResource;

    model Role {
        @doc("Role identifier")
        id?: UUID;
        @doc("Name of the role")
        name?: string;
    }

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
        meta: Workspaces.PaginationMeta;
        @doc("Pagination links")
        links: Workspaces.PaginationLinks;
        @doc("List of role bindings grouped by subject")
        data: RoleBindingBySubject[];
    }

    @doc("List role bindings grouped by subject")
    @summary("List role bindings grouped by subject")
    @route("by-subject")
    @get op listBySubject(
        @query limit?: int64 = 1000;
        @query offset?: int64 = 0;

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

        @doc("Specify which columns to include in response. Basic columns (subject.id, subject.type, role.id, resource.type) are included by default when no columns parameter is specified (type fields are always required, other fields are optional). When columns parameter is provided, only the specified columns are exposed. Use parentheses format: subject(field1,field2), resource(field1,field2). Available fields - subject: user_count, name; resource: name; role: name; other: last_modified")
        @example("subject(user_count,name),resource(name,type),last_modified")
        @query columns?: string;
        @doc("Sort by specified field(s), prefix with '-' for descending order")
        @example("subject_name,-subject_type")
        @query sort_by?: string;
        @doc("Include role bindings from parent resources")
        @query parent_role_bindings?: boolean;
    ): RoleBindingBySubjectListResponse | Problems.CommonProblems;
}
