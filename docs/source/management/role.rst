Managing Roles
###############
A Role defines a set of access control lists (ACLs). These ACLs define Permissions and contain Resource Definitions.

Permissions
********************
A Permission is a three part object: application, resource type, operation

Application specifies the service or domain for the resource, for example::

- catalog
- approval
- cost-management

Resource type defines the resource to be controlled, for example::

- aws.account
- openshift.cluster

Operation defines the application logic action, for example::

- read
- write
- order

Note that in any of the above stanzas, ``*`` is taked to mean "all".


Resource Definitions
********************
Resource Definitions are a somewhat trickier aspect of our implementation of RBAC currently only used by the cost-management service.

In general, ALL roles should be created with a resourceDefinitions stanza of ``[]``. This is taken to mean "no additional filtering" and will generally result in the expected behavior. 

In specific cases where the application logic has been written to handle them, however, resource access can be limited by specifing an attribute filter in the resourceDefinitions stanza as below.

Specifying a single resource with an attribute filter::

    "resourceDefinitions": [
        {
            "attributeFilter": {
                "key": "uuid",
                "operation": "equal",
                "value": "39c8cecd-e595-46fb-8908-13365d59d5e8"
            }
        }
    ]


While you can specify resources individually you can also specify a multiple resource with an attribute filter as follows::

    "resourceDefinitions": [
        {
            "attributeFilter": {
                "key": "uuid",
                "operation": "in",
                "value": "39c8cecd-e595-46fb-8908-13365d59d5e8,9928e33b-e28f-4e82-b996-12e222f08098"
            }
        }
    ]

Permissions for Role API access
********************************
Only an account administrator can view (read) roles or create/update (write) roles.
Non-administrator can view (read) roles within their scope with scope specified in the API call -``?scope=principal``.
