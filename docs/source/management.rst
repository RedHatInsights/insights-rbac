Managing Resources with Role Based Access Control
=================================================

Users can control access to resources utilizing the Role Based Access Control (RBAC) service.  By default only Account administrators can access resources without being granted access using the RBAC service. In order to give non-administrators for an account access they must be added to a group. The associated group must then be granted access by being bound to a role or set of roles through a policy. A role defines access to specific application resources with defined permissions.

.. include:: management/principal.rst
.. include:: management/group.rst
.. include:: management/role.rst
.. include:: management/policy.rst