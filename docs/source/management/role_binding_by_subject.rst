====================================
V2 Role Binding ``by-subject`` API
====================================

Overview
========

The V2 Role Binding API exposes a read-only endpoint that returns role bindings
grouped by **subject** (group or user) for a given resource. It supports both:

* Direct bindings attached to the resource itself.
* Inherited bindings resolved via the Relations (SpiceDB/Kessel) API.

Endpoint
========

.. code-block:: text

   GET /api/rbac/v2/role-bindings/by-subject/

The endpoint is part of the ``v2_management`` namespace and is registered under
the ``RoleBindingViewSet``.

Query Parameters
================

Required
--------

* ``resource_type``: Type of the resource.

  * Short form defaults to the ``rbac`` namespace, e.g. ``workspace`` → ``rbac/workspace``.
  * Full form includes namespace, e.g. ``hbi/host``.

* ``resource_id``: Identifier of the resource (e.g. workspace UUID).

Optional
--------

* ``subject_type``: Filter by subject type.

  * ``group`` – return group subjects.
  * ``user`` – return user subjects.

* ``subject_id``: Filter by subject UUID (matches group or principal UUID depending on ``subject_type``).
* ``parent_role_bindings``: If ``true``, use the Relations API to include inherited bindings.
* ``fields``: Comma-separated subset of top-level fields to include in the response
  (e.g. ``fields=subject,roles,resource``).
* ``order_by``: Ordering for the results. Currently supports:

  * ``latest_modified``
  * ``-latest_modified`` (default)

* ``limit``: Page size for cursor pagination (default: ``10``, max: ``1000``).

Response Shape
==============

When used with the default cursor pagination class, the response has the
following shape:

.. code-block:: json

   {
     "next": null,
     "previous": null,
     "results": [
       {
         "last_modified": "2025-01-01T12:00:00Z",
         "subject": {
           "type": "group",
           "group": {
             "id": "5e1e9c4e-...",
             "name": "Engineering Team",
             "description": "Development group",
             "user_count": 25
           }
         },
         "roles": [
           {
             "id": "e13a50e4-...",
             "name": "Workspace Admin"
           }
         ],
         "resource": {
           "id": "2fd0e63c-...",
           "type": "workspace",
           "name": "Child Workspace"
         },
         "inherited_from": [
           {
             "id": "9a4c59f0-...",
             "type": "workspace",
             "name": "Parent Workspace"
           }
         ]
       }
     ]
   }

Inheritance Behaviour
=====================

Direct Bindings Only
--------------------

When ``parent_role_bindings`` is omitted or set to ``false``:

* The view filters bindings directly attached to ``resource_type/resource_id``.
* The ``inherited_from`` field is omitted from the payload.

Inherited Bindings via Relations
--------------------------------

When ``parent_role_bindings=true``:

1. The view calls the Relations API using ``LookupSubjects`` to resolve
   all effective role binding subjects for the resource, including parent
   resources in the hierarchy.
2. The returned binding UUIDs are used to filter role bindings in the
   local database.
3. The serializer populates the ``inherited_from`` field with any bindings
   whose ``resource_type/resource_id`` differ from the requested resource.

If the Relations API is unavailable or misconfigured, the view logs the error
and falls back to using direct bindings only (behaving as if
``parent_role_bindings`` is false).

Example Usage
=============

List group bindings on a workspace (direct only)
------------------------------------------------

.. code-block:: bash

   curl -H "x-rh-identity: $IDENTITY" \
     "https://console.redhat.com/api/rbac/v2/role-bindings/by-subject/?resource_type=workspace&resource_id=$WORKSPACE_ID&subject_type=group"

List bindings including inherited from parent workspaces
--------------------------------------------------------

.. code-block:: bash

   curl -H "x-rh-identity: $IDENTITY" \
     "https://console.redhat.com/api/rbac/v2/role-bindings/by-subject/?resource_type=workspace&resource_id=$WORKSPACE_ID&parent_role_bindings=true"


