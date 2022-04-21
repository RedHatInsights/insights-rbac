#
# Copyright 2019 Red Hat, Inc.
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

"""Notification handlers of object change."""
import logging

from django.conf import settings
from management.notifications.producer_util import NotificationProducer
from management.utils import account_id_for_tenant

from api.models import Tenant


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
producer = NotificationProducer()


def notify_all(event_type, payload):
    """Notify all tenants."""
    # To avoid memory overloaded, use iterator:
    # https://docs.djangoproject.com/en/4.0/ref/models/querysets/#django.db.models.query.QuerySet.iterator
    for tenant in Tenant.objects.exclude(tenant_name="public").iterator():
        # Tenant name pattern is acct12345
        account_id = account_id_for_tenant(tenant)
        producer.send_kafka_message(event_type, account_id, payload)


def handle_system_role_change_notification(role_obj, operation):
    """Signal handler for sending notification message when system Role object changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return

    payload = payload_builder("Red Hat", role_obj)
    # Role created
    if operation == "created":
        event_type = "rh-new-role-available"
    # Role updated (including access/resourceDefinition update)
    elif operation == "updated":
        if role_obj.platform_default:
            event_type = "rh-platform-default-role-updated"
        else:
            event_type = "rh-non-platform-default-role-updated"
    else:
        raise Exception("Not recorgnized operation for updating Red Hat managed group.")

    notify_all(event_type, payload)


def role_obj_change_notification_handler(role_obj, operation, user=None):
    """Signal handler for sending notification message when Role object changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return

    if role_obj.system:
        handle_system_role_change_notification(role_obj, operation)
        return

    account_id = user.account
    payload = payload_builder(user.username, role_obj)
    # Role created
    if operation == "created":
        event_type = "custom-role-created"
    # Role deleted
    elif operation == "deleted":
        event_type = "custom-role-deleted"
    # Role updated (including access/resourceDefinition update)
    elif operation == "updated":
        event_type = "custom-role-updated"

    producer.send_kafka_message(event_type, account_id, payload)


def group_obj_change_notification_handler(user, group_obj, operation):
    """Signal handler for sending notification message when Group object changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return
    account_id = user.account
    payload = payload_builder(user.username, group_obj)
    # Group created
    if operation == "created":
        if not group_obj.system:
            event_type = "group-created"
    # Group deleted
    elif operation == "deleted":
        if not group_obj.system:
            event_type = "group-deleted"
    # Group updated
    else:
        event_type = "group-updated"
    producer.send_kafka_message(event_type, account_id, payload)


def handle_platform_group_role_change_notification(group_obj, role_obj, operation):
    """Signal handler for sending notification message when roles of platform group changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return
    payload = payload_builder("Red Hat", group_obj, extra_info=("role", role_obj))

    if operation == "added":
        event_type = "rh-new-role-added-to-default-access"
    elif operation == "removed":
        event_type = "rh-role-removed-from-default-access"
    else:
        raise Exception("Not recorgnized operation for updating Red Hat managed platform default access group.")

    notify_all(event_type, payload)


def group_role_change_notification_handler(user, group_obj, role_obj, operation):
    """Signal handler for sending notification message when role of group changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return

    # Handle Red Hat managed platform group

    if (group_obj.platform_default or group_obj.admin_default) and group_obj.system:
        handle_platform_group_role_change_notification(group_obj, role_obj, operation)
        return

    # Handle custom group
    account_id = user.account
    payload = payload_builder(user.username, group_obj, operation, ("role", role_obj))

    if group_obj.platform_default:
        event_type = "custom-default-access-updated"
    else:
        event_type = "group-updated"

    producer.send_kafka_message(event_type, account_id, payload)


def group_principal_change_notification_handler(user, group_obj, principal, operation):
    """Signal handler for sending notification message when principal of group changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return

    account_id = user.account
    payload = payload_builder(user.username, group_obj, operation, ("principal", principal))

    event_type = "group-updated"
    producer.send_kafka_message(event_type, account_id, payload)


def group_flag_change_notification_handler(user, group_obj):
    """Signal handler for sending notification message when flag of group changes."""
    if not settings.NOTIFICATIONS_ENABLED:
        return
    account_id = user.account
    payload = payload_builder(user.username, group_obj)

    event_type = "platform-default-group-turned-into-custom"

    producer.send_kafka_message(event_type, account_id, payload)


def payload_builder(username, resource_obj, operation=None, extra_info=None):
    """Payload builder for notifications message."""
    payload = {"username": username, "name": resource_obj.name, "uuid": str(resource_obj.uuid)}
    if operation:
        payload["operation"] = operation

    if extra_info:
        if extra_info[0] == "role":
            payload["role"] = {"name": extra_info[1].name, "uuid": str(extra_info[1].uuid)}
        elif extra_info[0] == "principal":
            payload["principal"] = extra_info[1]
        else:
            raise Exception(f"Unknow extra_info {extra_info[0]}, valid ones are role/principal")

    return payload
