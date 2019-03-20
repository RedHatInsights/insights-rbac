Managing Groups
###############

A group is a collection of principals used to grant access to a resource. A principal can be a member of many groups. Groups are associated with roles with a policy. A group can be associated with multiple policies.

Permissions for Group API access
********************************
A user can be given access to view (read) groups or create/update (write) groups.
Below are the valid permissions for reading or writing groups. Write permissions implies read permission.

Read group -``rbac:group:read``

Write group - ``rbac:group:write``

