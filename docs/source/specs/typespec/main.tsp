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


model CreatedResponseForModel<T>{
    @statusCode
    statusCode: 201,
    ...T
}

/**
 * Resource Deleted
 */
model NoContentResponseResourceDeleted{
    @statusCode
    statusCode: 201,
}

namespace Errors {
    @error
    model ErrorMessage400 {
        detail?: string = "JSON parse error - Expecting value: line 1 column 1 (char 0)",
        status?: string = "404",
        source?: string = "detail"
    }

    @error
    model ErrorMessage403 {
        detail?: string = "You do not have permission to perform this action.",
        status?: string = "403",
        source?: string = "detail"
    }

    @error
    model ErrorMessage404 {
        detail?: string = "Not found.",
        status?: string = "404",
    }

    @error
    model ErrorBasicResponse<STATUS>{
        @statusCode 
        statusCode: STATUS;
    }

    @error
    model ErrorResponse400{
        @statusCode
        statusCode: 400,
        errors: ErrorMessage400[]
    }

    @error
    model ErrorResponse400AlreadyExist<T>{
        @statusCode
        statusCode: 400,
        errors: T[]
    }

    @error
    model ErrorResponse403{
        @statusCode 
        statusCode: 403,
        errors: ErrorMessage403[]
    }

    @error
    model ErrorResponse404{
        @statusCode 
        statusCode: 404,
        errors: ErrorMessage404[]
    }

    @error
    model ErrorResponse401{
        @statusCode 
        statusCode: 401,
    }

    scalar ErrorCode extends string;
}

interface CreateResource<BodyType> {
    create<ModelType>(@body body: BodyType): CreatedResponseForModel<ModelType> | 
    Errors.ErrorResponse401 |
    Errors.ErrorResponse403 |
    Errors.ErrorResponse400 |
    Errors.ErrorBasicResponse<500>;
}

interface ListResource<T> {
    list(...ListQueryParams): T[] |
    Errors.ErrorResponse401 |
    Errors.ErrorResponse403 |
    Errors.ErrorBasicResponse<500>;
}

interface ReadResource<T> {
    read(
        @doc("Unique identification")
        @path uuid: UUID;
    ): T |
    Errors.ErrorResponse401 |
    Errors.ErrorResponse403 |
    Errors.ErrorResponse404 |
    Errors.ErrorBasicResponse<500>;
}

interface UpdateResource<B, R, E> {
    update(
        @doc("Unique identification")
        @path uuid: UUID;
        @body body: B
    ): OkResponseForModel<R> |
    Errors.ErrorResponse400AlreadyExist<E> |
    Errors.ErrorResponse401 |
    Errors.ErrorResponse403 |
    Errors.ErrorBasicResponse<500>;
}

interface DeleteResource {
    delete(
        @doc("Unique identification")
        @path uuid: UUID;
    ): NoContentResponseResourceDeleted |
    Errors.ErrorResponse401 |
    Errors.ErrorResponse403 |
    Errors.ErrorBasicResponse<500>;
}

@route("/workspaces")
@tag("Workspaces")
@doc("Operations about workspaces")
namespace Workspaces {
    model WorkspaceForRead {
        @doc("Workspace A")
        name: string = "Workspace A";
        @doc("Description of Workspace A")
        description?: string = "Description of Workspace A";
    }

    model Workspace {
        @key uuid: UUID;
        ...WorkspaceForRead;
        ...Timestamps;
    }

    @error
    model ErrorMessage400WorkspaceAlreadyExist {
        detail?: string = "Workspace already exist in tenant",
        status?: string = "400",
        source?: string = "workspace",
    }

    alias CreateResourceAlias = CreateResource<WorkspaceForRead>;
    @doc("Create workspace in tenant")
    @summary("Create workspace in tenant")
    @post op create is CreateResourceAlias.create<Workspace>;

    model WorkspaceListResponse is ListResponse<Workspace>;
    alias ListResourceAlias = ListResource<WorkspaceListResponse>;
    @doc("By default, responses are sorted in ascending order by workspace name")
    @summary("List workspaces for tenant")
    @get op list is ListResourceAlias.list;

    alias ReadResourceAlias = ReadResource<Workspace>;
    @doc("Get a workspace in tenant")
    @summary("Get a workspace in tenant")
    @get op read is ReadResourceAlias.read;

    alias UpdateResourceAlias = UpdateResource<WorkspaceForRead, Workspace, ErrorMessage400WorkspaceAlreadyExist>;
    @doc("Edit a workspace")
    @summary("Edit the workspace name or description")
    @put op update is UpdateResourceAlias.update;

    @doc("Delete a workspace")
    @summary("Delete the workspace")
    @delete op delete is DeleteResource.delete;
}
