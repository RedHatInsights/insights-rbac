=========================================
Insights RBAC ephemeral testing
=========================================

~~~~~
About
~~~~~
This README outlines how to use the ephemeral make tasks


Prerequisites
===============
1. You must be logged into VPN
2. Install `bonfire <https://github.com/RedHatInsights/bonfire>`_ locally
3. Log into the ephemeral cluster (via the UI)
    a. Select your username drop down in the top right corner and select
    b. Copy login command
    c. Paste it into you terminal
5. Set the following ENV variables::

        export QUAY_USER=<your quay username>
        export EPHEMERAL_USER=<your ephemeral username>

Running makefile tasks
=======================

1. Reserve a namespace for 12 hours (HOURS defaults to 24h if not provided)::

    $ make ephemeral-reserve HOURS="12h"

2. Build RBAC image from local repo::

    $ make ephemeral-build

3. After the build step has completed make sure your quay repo is public accessible before proceeding.
    Repo will be: https://quay.io/repository/<user_name>/insights-rbac

4. Deploy app::

    $ make ephemeral-deploy

5. To view pods you can do either of the below commands::

    $ make ephemeral-pods (This will show you only the rbac pods)::
    or
    $ oc get pods (this will show all pods in your namespace

6. Release the Namespace (this will happen automatically at the end of the reserve time)::

    $ make ephemeral-release
