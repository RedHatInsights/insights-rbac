Installation
============

Insights RBAC provides a web server for its API interaction.


This guide will focus on deploying Insighs RBAC into an existing `OpenShift <https://www.okd.io/>`_ cluster.

Deploying the RBAC API
----------------------

The RBAC application contains two components - a web service and database.

**OpenShift**

A basic deployment configuration is contained within the application's openshift template file ``openshift/rbac-template.yaml``. This template should be acceptable for most use cases. It provides parameterized values for most configuration options.

To deploy the RBAC API application using the provided templates, you can use
the provided ``Makefile``:

    ``make oc-create-all``

To deploy individual components, there are also ``make`` commands provided for your convenience:

    Deploy the API web application: ``make oc-create-rbac``
    Deploy the PostgreSQL database: ``make oc-create-db``

**Docker Compose**

The RBAC API can also be deployed with Docker Compose with the following steps.
Before these steps can complete, the postgresql-devel package for your distribution must be installed.

* Create a Docker bridge network named ``rbac-network``: ``docker network create rbac-network``
* Start RBAC server and database: ``make docker-up``

This command will run database migraitons and start the API server.  Once complete the API server will be running on port 8000 on your localhost.
