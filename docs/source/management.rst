Managing Resources with Role Based Access Control
=================================================

Overview
--------

The Role Based Access Control (RBAC) service allows users to control access to Platform services and resources. Management of RBAC resources can only be performed by account/organization administrators. There are three primary resources RBAC uses to control access to services: Principals, Groups, and Roles. In order to give any Principal(user) access to an application resource, they must be added to a Group. The associated group must then be granted access by being bound to a Role or set of Roles. A Role defines access to specific application resources with a specific set of permissions.

.. include:: management/principal.rst
.. include:: management/group.rst
.. include:: management/role.rst
