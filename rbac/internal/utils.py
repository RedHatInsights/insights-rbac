#
# Copyright 2022 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""Utilities for Internal RBAC use."""
import json
import logging

import jsonschema
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.urls import resolve
from internal.schemas import INVENTORY_INPUT_SCHEMAS, RELATION_INPUT_SCHEMAS
from jsonschema import validate
from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.models import Principal, Workspace
from management.principal.proxy import PrincipalProxy
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler

from api.models import User


logger = logging.getLogger(__name__)
PROXY = PrincipalProxy()


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    valid_identity_types = ["Associate", "X509"]
    try:
        identity_type = json_rh_auth["identity"]["type"]
        if identity_type not in valid_identity_types:
            logger.debug(
                f"User identity type is not valid: '{identity_type}'. Valid types are: {valid_identity_types}"
            )
            return None
        user.username = json_rh_auth["identity"].get("associate", {}).get("email", "system")
        user.admin = True
        user.org_id = resolve(request.path).kwargs.get("org_id")
        return user
    except KeyError:
        logger.debug(
            f"Identity object is missing 'identity.type' attribute. Valid options are: {valid_identity_types}"
        )
        return None


def delete_bindings(bindings):
    """
    Delete the provided bindings and replicate the deletion event.

    Args:
        bindings (QuerySet): A Django QuerySet of binding objects to be deleted.

    Returns:
        dict: A dictionary containing information about the deleted bindings, including:
            - mappings (list): A list of mappings for each binding.
            - role_ids (list): A list of role IDs for each binding.
            - resource_ids (list): A list of resource IDs for each binding.
            - resource_types (list): A list of resource type names for each binding.
            - relations (list): A list of tuples representing the relations to be removed.
    """
    replicator = OutboxReplicator()
    info = {
        "mappings": [binding.mappings for binding in bindings],
        "role_ids": [binding.role_id for binding in bindings],
        "resource_ids": [binding.resource_id for binding in bindings],
        "resource_types": [binding.resource_type_name for binding in bindings],
    }
    if bindings:
        with transaction.atomic():
            relations_to_remove = []
            for binding in bindings:
                relations_to_remove.extend(binding.as_tuples())
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.DELETE_BINDING_MAPPINGS,
                    info=info,
                    partition_key=PartitionKey.byEnvironment(),
                    remove=relations_to_remove,
                ),
            )
            bindings.delete()
        info["relations"] = [stringify_spicedb_relationship(relation) for relation in relations_to_remove]
    return info


@transaction.atomic
def get_or_create_ungrouped_workspace(tenant: str) -> Workspace:
    """
    Retrieve the ungrouped workspace for the given tenant.

    Args:
        tenant (str): The tenant for which to retrieve the ungrouped workspace.
    Returns:
        Workspace: The ungrouped workspace object for the given tenant.
    """
    # fetch parent only once
    default_ws = Workspace.objects.get(tenant=tenant, type=Workspace.Types.DEFAULT)

    # single select_for_update + get_or_create
    workspace, created = Workspace.objects.select_for_update().get_or_create(
        tenant=tenant,
        type=Workspace.Types.UNGROUPED_HOSTS,
        defaults={"name": Workspace.SpecialNames.UNGROUPED_HOSTS, "parent": default_ws},
    )

    if created:
        RelationApiDualWriteWorkspaceHandler(
            workspace, ReplicationEventType.CREATE_WORKSPACE
        ).replicate_new_workspace()

    return workspace


def validate_relations_input(action, request_data) -> bool:
    """Check if request body provided to relations tool endpoints are valid."""
    validation_schema = RELATION_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def validate_inventory_input(action, request_data) -> bool:
    """Check if request body provided to inventory tool endpoints are valid."""
    validation_schema = INVENTORY_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def load_request_body(request) -> dict:
    """Decode request body from json into dict structure."""
    request_decoded = request.body.decode("utf-8")
    req_data = json.loads(request_decoded)
    return req_data


def is_resource_a_workspace(application: str, resource_type: str, attributeFilter: dict) -> bool:
    """Check if a given ResourceDefinition is a Workspace."""
    is_workspace_application = application == settings.WORKSPACE_APPLICATION_NAME
    is_workspace_resource_type = resource_type in settings.WORKSPACE_RESOURCE_TYPE
    is_workspace_group_filter = attributeFilter.get("key") == settings.WORKSPACE_ATTRIBUTE_FILTER
    return is_workspace_application and is_workspace_resource_type and is_workspace_group_filter


def get_workspace_ids_from_resource_definition(attributeFilter: dict) -> list[str]:
    """Get workspace id from a resource definition."""
    operation = attributeFilter.get("operation")
    if operation == "in":
        value = attributeFilter.get("value", [])
        return [str(val) for val in value if val is not None]
    elif operation == "equal":
        value = attributeFilter.get("value", "")
        return [str(value)]
    else:
        return []


def _query_bop_for_usernames(proxy, user_ids):
    """Query BOP for correct usernames for given user_ids.

    Args:
        proxy: PrincipalProxy instance to use for BOP queries
        user_ids (list): List of user IDs to query

    Returns:
        tuple: (user_id_to_username dict, error_response or None)
            - user_id_to_username: Mapping of user_id (str) -> username (str, lowercase)
            - error_response: JsonResponse object if error occurred, None otherwise
    """
    user_id_to_username = {}

    logger.info(f"Querying BOP for {len(user_ids)} user IDs to verify correct usernames")

    try:
        resp = proxy.request_filtered_principals(
            user_ids, org_id=None, options={"query_by": "user_id", "return_id": True}
        )

        if resp.get("status_code") != 200:
            error_msg = f"BOP query failed with status {resp.get('status_code')}: {resp.get('errors')}"
            logger.error(error_msg)
            error_response = JsonResponse(
                {
                    "error": "BOP query failed. Cannot proceed without verification.",
                    "details": error_msg,
                    "status_code": resp.get("status_code"),
                },
                status=500,
            )
            return None, error_response

        for item in resp.get("data", []):
            bop_user_id = str(item.get("user_id"))
            bop_username = item.get("username")
            if bop_user_id and bop_username:
                user_id_to_username[bop_user_id] = bop_username.lower()
        logger.info(f"Successfully fetched {len(user_id_to_username)} usernames from BOP")

        return user_id_to_username, None

    except Exception as e:
        error_msg = f"Failed to query BOP for usernames: {e}"
        logger.error(error_msg)
        error_response = JsonResponse(
            {"error": "BOP query failed. Cannot proceed without verification.", "details": error_msg}, status=500
        )
        return None, error_response


def _parse_user_ids(request):
    """Parse the comma-separated list of user_ids from the request."""
    user_ids_param = request.GET.get("user_ids")

    if not user_ids_param:
        return HttpResponse(
            'Missing required parameter "user_ids". Provide a comma-separated list of user IDs.', status=400
        )

    # Parse the comma-separated list of user_ids
    user_ids = [uid.strip() for uid in user_ids_param.split(",") if uid.strip()]

    if not user_ids:
        return HttpResponse('Invalid "user_ids" parameter. Provide at least one user ID.', status=400)

    return user_ids


def _fetch_bop_usernames(user_ids, fail_on_error, proxy):
    """Fetch BOP usernames with error handling.

    Args:
        user_ids (list): List of user IDs to query
        fail_on_error (bool): Whether to return error response on BOP failure
        proxy: PrincipalProxy instance

    Returns:
        tuple: (user_id_to_username dict, error_response or None)
    """
    names, err = _query_bop_for_usernames(proxy, user_ids)
    if err:
        if fail_on_error:
            return None, err
        logger.warning("BOP lookup failed, continuing without verification")
        return {}, None
    return names, None


def _get_duplicate_principals(request, user_ids):
    """GET method logic: Return information about duplicate principals.

    Args:
        request: HTTP request object
        user_ids (list): List of user IDs to check

    Returns:
        JsonResponse: Response with duplicate information
    """
    # Query BOP for correct usernames (don't fail on error for GET)
    user_id_to_username, _ = _fetch_bop_usernames(user_ids, fail_on_error=False, proxy=PROXY)

    # Return information about duplicates
    duplicates_info = []

    # Check each user_id individually
    for user_id in user_ids:
        # Get principals if duplicates exist
        principals = list(Principal.objects.filter(user_id=user_id, type=Principal.Types.USER))
        if len(principals) <= 1:
            continue

        correct_username = user_id_to_username.get(user_id)

        principal_details = []
        for p in principals:
            is_correct_username = p.username.lower() == correct_username if correct_username else None
            principal_details.append(
                {
                    "id": p.id,
                    "uuid": str(p.uuid),
                    "username": p.username,
                    "type": p.type,
                    "group_count": p.group.count(),
                    "groups": list(p.group.values_list("uuid", "name")),
                    "is_correct_username": is_correct_username,
                    "will_be_kept": is_correct_username if is_correct_username is not None else False,
                }
            )

        duplicates_info.append(
            {
                "user_id": user_id,
                "duplicate_count": len(principals),
                "bop_username": correct_username,
                "bop_verified": correct_username is not None,
                "principals": principal_details,
            }
        )

    response_data = {
        "total_duplicate_sets": len(duplicates_info),
        "duplicates": duplicates_info,
    }
    return JsonResponse(response_data, safe=False)


def _remove_duplicate_principals(request, user_ids):
    """POST method logic: Remove duplicate principals based on BOP verification.

    Args:
        request: HTTP request object
        user_ids (list): List of user IDs to process

    Returns:
        JsonResponse: Response with removal statistics
    """
    removed_principals = []
    kept_principals = []
    affected_groups = set()
    total_removed = 0
    user_ids_not_found_in_bop = []

    # Query BOP for correct usernames (fail on error for POST)
    user_id_to_username, error_response = _fetch_bop_usernames(user_ids, fail_on_error=True, proxy=PROXY)
    if error_response:
        return error_response

    # Check each user_id individually
    for user_id in user_ids:
        with transaction.atomic():
            # Lock the principals for update
            principals = list(Principal.objects.filter(user_id=user_id, type=Principal.Types.USER).select_for_update())

            # Only process if there are duplicates (count > 1)
            if len(principals) <= 1:
                continue

            # Check if user_id exists in BOP
            correct_username = user_id_to_username.get(user_id)

            if not correct_username:
                # User ID not found in BOP -> delete ALL principals
                logger.warning(f"User ID {user_id} not found in BOP. Deleting all {len(principals)} principal(s).")
                user_ids_not_found_in_bop.append(user_id)

            # First pass: identify principal to keep (if any)
            principal_to_keep = None
            principals_to_delete = []

            for principal in principals:
                if correct_username and principal.username.lower() == correct_username:
                    # Username matches BOP -> keep
                    principal_to_keep = principal
                    logger.info(
                        f"Principal username '{principal.username}' matches BOP. Keeping principal "
                        f"(user_id={user_id}, uuid={principal.uuid})"
                    )
                    kept_principals.append(
                        {
                            "uuid": str(principal.uuid),
                            "username": principal.username,
                            "user_id": principal.user_id,
                            "verified_with_bop": True,
                            "bop_username": correct_username,
                            "username_matches_bop": True,
                        }
                    )
                else:
                    # No BOP username OR username doesn't match -> delete
                    principals_to_delete.append(principal)
                    if correct_username:
                        logger.info(
                            f"Principal username '{principal.username}' does not match "
                            f"BOP username '{correct_username}'. "
                            f"Will delete principal (user_id={user_id}, uuid={principal.uuid})"
                        )

            # Second pass: migrate group memberships and delete incorrect principals
            for principal in principals_to_delete:
                # Get all groups this principal is in
                groups = list(principal.group.all().prefetch_related("principals"))

                for group in groups:
                    # If we have a correct principal, migrate the group membership
                    if principal_to_keep and principal_to_keep not in group.principals.all():
                        group.principals.add(principal_to_keep)
                        logger.info(
                            f"Migrated group membership: Added principal {principal_to_keep.username} "
                            f"(uuid={principal_to_keep.uuid}) to group {group.name} (uuid={group.uuid})"
                        )

                    # Remove the incorrect principal from the group
                    group.principals.remove(principal)
                    affected_groups.add(str(group.uuid))
                    logger.info(
                        f"Removed principal {principal.username} (uuid={principal.uuid}) "
                        f"from group {group.name} (uuid={group.uuid})"
                    )

                # Replicate the changes
                if groups:
                    for group in groups:
                        try:
                            # Replicate the removal
                            dual_write_handler = RelationApiDualWriteGroupHandler(
                                group, ReplicationEventType.REMOVE_PRINCIPALS_FROM_GROUP
                            )
                            dual_write_handler.replicate_removed_principals([principal])

                            # If we migrated to the keeper, replicate the addition
                            if principal_to_keep and principal_to_keep in group.principals.all():
                                dual_write_handler_add = RelationApiDualWriteGroupHandler(
                                    group, ReplicationEventType.ADD_PRINCIPALS_TO_GROUP
                                )
                                dual_write_handler_add.replicate_new_principals([principal_to_keep])
                                logger.info(f"Replicated addition of keeper principal to group {group.uuid}")

                            logger.info(f"Replicated removal of principal from group {group.uuid}")
                        except Exception as e:
                            logger.error(f"Failed to replicate for group {group.uuid}: {e}")

                # Delete the principal
                removed_principals.append(
                    {
                        "uuid": str(principal.uuid),
                        "username": principal.username,
                        "user_id": principal.user_id,
                        "had_groups": len(groups),
                    }
                )
                principal.delete()
                total_removed += 1
                logger.info(f"Deleted principal {principal.username} (uuid={principal.uuid})")

    response_data = {
        "total_removed": total_removed,
        "total_kept": len(kept_principals),
        "affected_groups_count": len(affected_groups),
        "user_ids_not_found_in_bop": user_ids_not_found_in_bop,
        "removed_principals": removed_principals,
        "kept_principals": kept_principals,
    }
    return JsonResponse(response_data, safe=False, status=200)
