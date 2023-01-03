=========================================
Insights Role Based Access Control README
=========================================

|license| |Build Status| |codecov| |Updates| |Python 3| |Docs|

~~~~~
About
~~~~~

Insights RBAC's goal is to provide an open source solution for storing roles, permissions and groups.

Full documentation is available through readthedocs_.
More info is available through platformdocs_.


Getting Started
===============

This is a Python project developed using Python 3.8. Make sure you have at least this version installed.

Additionally, the development environment installation requires the postgresql-devel package installed for your distribution before running properly.

Development
===========

To get started developing against Insights-rbac first clone a local copy of the git repository. ::

    git clone https://github.com/RedHatInsights/insights-rbac.git

Developing inside a virtual environment is recommended. A Pipfile is provided. Pipenv is recommended for combining virtual environment (virtualenv) and dependency management (pip). To install pipenv, use pip ::

    pip3 install pipenv

Then project dependencies and a virtual environment can be created using ::

    pipenv install --dev

To activate the virtual environment run ::

    pipenv shell

Preferred Environment
---------------------

Please refer to `Working with Openshift`_.

Alternative Environment
-----------------------
If deploying with Openshift seems overly complex you can try an alternate local environment where you will need to install and setup some of the dependencies and configuration.

Configuration
^^^^^^^^^^^^^

This project is developed using the Django web framework. Many configuration settings can be read in from a `.env` file. An example file `.env.example` is provided in the repository. To use the defaults simply ::

    cp .env.example .env


Modify as you see fit.

Database
^^^^^^^^

PostgreSQL is used as the database backend for Insights-rbac. A docker-compose file is provided for creating a local database container. If modifications were made to the .env file the docker-compose file will need to be modified to ensure matching database credentials. Several commands are available for interacting with the database. ::

    # This will launch a Postgres container
    make start-db

    # This will run Django's migrations against the database
    make run-migrations

    # This will stop and remove a currently running database and run the above commands
    make reinitdb

Assuming the default .env file values are used, to access the database directly using psql run ::

    psql rbac -U rbacadmin -h localhost -p 15432

There is a known limitation with docker-compose and Linux environments with SELinux enabled. You may see the following error during the postgres container deployment::

    "mkdir: cannot create directory '/var/lib/pgsql/data/userdata': Permission denied" can be resolved by granting ./pg_data ownership permissions to uid:26 (postgres user in centos/postgresql-96-centos7)

If a docker container running Postgres is not feasible, it is possible to run Postgres locally as documented in the Postgres tutorial_. The default port for local Postgres installations is `5432`. Make sure to modify the `.env` file accordingly. To initialize the database run ::

    make run-migrations

You may also run migrations explicitly, and in parallel, by specifying `TENANT_PARALLEL_MIGRATION_MAX_PROCESSES` (the number of concurrent processes to run migrations) and/or `TENANT_PARALLEL_MIGRATION_CHUNKS` (the number of migrations for each process to run at a time). Both of these values default to 2. *Be mindful of the fact that bumping these values will consume more database connections:*

    TENANT_PARALLEL_MIGRATION_MAX_PROCESSES=4 TENANT_PARALLEL_MIGRATION_CHUNKS=2 ./rbac/manage.py migrate

Seeds
^^^^^

Default roles and groups are automatically seeded when the application starts by default unless either of the following environment variables are set to 'False' respectively: ::

  PERMISSION_SEEDING_ENABLED
  ROLE_SEEDING_ENABLED
  GROUP_SEEDING_ENABLED

Locally these are sourced from `/rbac/management/role/definitions/*.json`, while the config maps in deployed instances are source from our `RBAC config repo`_. **If any changes to default roles/groups are required, they should be make there.**

You can also execute the following Django command to run seeds manually. It's recommended that you disable db signals while running seeds with `ACCESS_CACHE_CONNECT_SIGNALS=False`. Caching will be busted after seeding for each tenant has processed. You may also specify the number of concurrent threads in which seeds should be run, by setting `MAX_SEED_THREADS` either in the process, or the app environment. The default value is 2. *Be mindful of the fact that bumping this value will consume more database connections:* ::

  ACCESS_CACHE_CONNECT_SIGNALS=False MAX_SEED_THREADS=2 ./rbac/manage.py seeds [--roles|--groups|--permissions]

Server
^^^^^^

To run a local dev Django server you can use ::

    make serve

To run the local dev Django on a specific port use::

    make PORT=8111 serve

Making Requests
---------------

You can make requests to RBAC locally to mimic traffic coming from the gateway, or locally within the same cluster from another internal service.

Basic/JWT Auth with an Identity Header
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, with the `DEVELOPMENT` variable set to `True`, the `dev_middleware.py` will be used.
This will ensure that a mock identity header will be set on all requests for you.
You can modify this header to add new users to your tenant by changing the `username`, create new tenants by changing the `account_number`, and toggling between admin/non-admins by flipping `is_org_admin` from `True` to `False`.

This will allow you to simulate a JWT or basic-auth request from the gateway.

Serivce to Service Requests
^^^^^^^^^^^^^^^^^^^^^^^^^^^

RBAC also allows for service-to-service requests. These requests require a PSK, and some additional headers in order to authorize the request as an "admin". To test this locally, do the following:

First disable the local setting of the identity header in `dev_middleware.py` by [commenting this line out](https://github.com/RedHatInsights/insights-rbac/blob/b207668440faf8f951dec75ffef8891343b4131b/rbac/rbac/dev_middleware.py#L72)

Next, start the server with: ::

  make serve SERVICE_PSKS='{"catalog": {"secret": "abc123"}}'

Verify that you cannot access any endpoints requiring auth: ::

  curl http://localhost:8000/api/rbac/v1/roles/ -v

Verify that if you pass in the correct headers/values, you _can_ access the endpoint: ::

  curl http://localhost:8000/api/rbac/v1/roles/ -v -H 'x-rh-rbac-psk: abc123' -H 'x-rh-rbac-account: 10001' -H 'x-rh-rbac-client-id: catalog'

Change the 'x-rh-rbac-client-id', 'x-rh-rbac-psk' and 'x-rh-rbac-account' header values to see that you should get back a 401 (or 400 with an account that doesn't exist).

You can also send a request _with_ the identity header explicitly in the curl command along with the service-to-service headers to verify that the identity header will take precedence.

API Documentation Generation
----------------------------

To generate and host the API documentation locally you need to `Install APIDoc`_.

Generate the project API documenttion by running the following command ::

  make gen-apidoc

In order to host the docs locally you need to collect the static files ::

  make collect-static

Now start the server with as described above and point your browser to **http://127.0.0.1:8000/apidoc/index.html**.

Testing and Linting
-------------------

Insights-rbac uses tox to standardize the environment used when running tests. Essentially, tox manages its own virtual environment and a copy of required dependencies to run tests. To ensure a clean tox environment run ::

    tox -r

This will rebuild the tox virtual env and then run all tests.

To run unit tests specifically::

    tox -e py38

To lint the code base ::

    tox -e lint

Caveats
-------

For all requests to the Insights RBAC API, it is assumed and required that principal
information for the request be sent in a header named: `x-rh-identity`. The information
in this header is used to determine the tenant, principal and other account-level
information for the request.

Consumers of this API through cloud.redhat.com should not be concerned with adding
this header, as it will be overwritten by the gateway. All traffic to the Insights
RBAC API comes through Akamai and the Insights 3scale Gateway. The gateway is responsible
for adding the `x-rh-identity` header to all authenticated requests.

Any internal, service-to-service requests which do **not** go through the gateway
will need to have this header added to each request.

This header requirement is not reflected in the openapi.json spec, as it would
cause spec-based API clients to require the header, which would be superfluously
added to all requests on cloud.redhat.com.

Contributing
=============

This repository uses [pre-commit](https://pre-commit.com) to check and enforce code style. It uses
[Black](https://github.com/psf/black) to reformat the Python code and [Flake8](http://flake8.pycqa.org) to check it
afterwards. Other formats and text files are linted as well.

Install pre-commit hooks to your local repository by running:

  $ pre-commit install

After that, all your commited files will be linted. If the checks don’t succeed, the commit will be rejected. Please
make sure all checks pass before submitting a pull request. Thanks!

Repositories of the roles to be seeded
--------------------------------------

Default roles can be found in the `RBAC config repo`_.

For additional information please refer to Contributing_.

.. _readthedocs: http://insights-rbac.readthedocs.io/en/latest/
.. _platformdocs: https://platform-docs.cloud.paas.psi.redhat.com/backend/rbac.html
.. _tutorial: https://www.postgresql.org/docs/10/static/tutorial-start.html
.. _`Install APIDoc`: http://apidocjs.com/#install
.. _`Working with Openshift`: https://insights-rbac.readthedocs.io/en/latest/openshift.html
.. _Contributing: https://insights-rbac.readthedocs.io/en/latest/CONTRIBUTING.html

.. |license| image:: https://img.shields.io/github/license/RedHatInsights/insights-rbac.svg
   :target: https://github.com/RedHatInsights/insights-rbac/blob/master/LICENSE
.. |Build Status| image:: https://travis-ci.org/RedHatInsights/insights-rbac.svg?branch=master
   :target: https://travis-ci.org/RedHatInsights/insights-rbac
.. |codecov| image:: https://codecov.io/gh/RedHatInsights/insights-rbac/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/RedHatInsights/insights-rbac
.. |Updates| image:: https://pyup.io/repos/github/RedHatInsights/insights-rbac/shield.svg?t=1524249231720
   :target: https://pyup.io/repos/github/RedHatInsights/insights-rbac/
.. |Python 3| image:: https://pyup.io/repos/github/RedHatInsights/insights-rbac/python-3-shield.svg?t=1524249231720
   :target: https://pyup.io/repos/github/RedHatInsights/insights-rbac/
.. |Docs| image:: https://readthedocs.org/projects/insights-rbac/badge/
   :target: https://insights-rbac.readthedocs.io/en/latest/
.. _`RBAC config repo`: https://github.com/RedHatInsights/rbac-config.git
