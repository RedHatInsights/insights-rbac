#
# Copyright 2026 Red Hat, Inc.
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
"""Shared domain exceptions for the management module."""

from typing import Any


class DomainError(Exception):
    """Base for all domain exceptions. Maps to Problem Details (RFC 7807)."""

    status_code: int = 500
    title: str = "An error occurred."

    def __init__(self, message: str, operation_context: str = ""):
        """Initialize with message and optional operation context."""
        self.operation_context = operation_context
        super().__init__(message)


class MissingRequiredFieldError(DomainError):
    """Raised when a required field is not provided."""

    status_code = 400
    title = "The request payload contains invalid syntax."

    def __init__(self, field: str, operation_context: str = ""):
        """Initialize with the missing field name."""
        self.field = field
        super().__init__(f"{field} is required", operation_context)


class InvalidFieldError(DomainError):
    """Raised when a field value fails validation."""

    status_code = 400
    title = "The request payload contains invalid syntax."

    def __init__(self, field: str, message: str, operation_context: str = "", rejected_value: Any = None):
        """Initialize with field name and validation message."""
        self.field = field
        self.rejected_value = rejected_value
        super().__init__(message, operation_context)


class NotFoundError(DomainError):
    """Raised when a resource cannot be found."""

    status_code = 404
    title = "Not found."

    def __init__(self, resource_type: str, resource_id: str, operation_context: str = ""):
        """Initialize with resource type and identifier."""
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(f"{resource_type} with id '{resource_id}' not found", operation_context)


class AlreadyExistsError(DomainError):
    """Raised when attempting to create a resource that already exists."""

    status_code = 409
    title = "Conflict."

    def __init__(self, resource_type: str, identifier: str, operation_context: str = ""):
        """Initialize with resource type and identifier."""
        self.resource_type = resource_type
        self.identifier = identifier
        super().__init__(f"A {resource_type} with name '{identifier}' already exists", operation_context)


class InUseError(DomainError):
    """Raised when attempting to delete a resource that is still referenced."""

    status_code = 409
    title = "Conflict."

    def __init__(self, resource_type: str, reference_count: int, operation_context: str = ""):
        """Initialize with resource type and reference count."""
        self.resource_type = resource_type
        self.reference_count = reference_count
        super().__init__(f"Cannot delete {resource_type}: {reference_count} references exist", operation_context)


class ImmutableError(DomainError):
    """Raised when attempting to modify an immutable resource."""

    status_code = 403
    title = "Forbidden."

    def __init__(self, resource_type: str, reason: str, operation_context: str = ""):
        """Initialize with resource type and reason."""
        self.resource_type = resource_type
        self.reason = reason
        super().__init__(f"Cannot modify {resource_type}: {reason}", operation_context)


class DatabaseError(DomainError):
    """Raised when an unexpected database error occurs."""

    status_code = 500
    title = "Internal server error."

    def __init__(self, operation_context: str = ""):
        """Initialize with optional operation context."""
        super().__init__("An unexpected error occurred. Please try again later.", operation_context)
