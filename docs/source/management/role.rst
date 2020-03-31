Managing Roles
###############
A role defines a set of access control lists (ACLs). These ACLs define permissions and resource definitions.

Permissions
********************
A permission is a three part object: application, resource type, operation

Application specifies the specific domain for the resource control, for example::

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


Resource Definitions
********************
If an empty array is supplied for resource definitions then this is implied to mean all access. However, resource access can be limited by specifing an attribute filter.

To specify a single resource with an attribute filter you would supply the following::

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
Only administrator can view (read) roles or create/update (write) roles.
Non-administrator can view (read) roles within their scope with scope specified in the API call -``?scope=principal``.