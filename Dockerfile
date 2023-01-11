FROM registry.access.redhat.com/ubi8/ubi-minimal:latest AS base

USER root

ENV PYTHON_VERSION=3.8 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    PIP_NO_CACHE_DIR=off \
    PIPENV_VENV_IN_PROJECT=1 \
    PIPENV_VERBOSITY=-1 \
    APP_ROOT=/opt/rbac \
    APP_CONFIG=/opt/rbac/rbac/gunicorn.py \
    APP_HOME=/opt/rbac/rbac \
    APP_MODULE=rbac.asgi \
    APP_NAMESPACE=rbac \
    PLATFORM="el8"


ENV SUMMARY="Insights RBAC is a role based access control web server" \
    DESCRIPTION="Insights RBAC is a role based access control web server"

LABEL summary="$SUMMARY" \
      description="$DESCRIPTION" \
      io.k8s.description="$DESCRIPTION" \
      io.k8s.display-name="insights-rbac" \
      io.openshift.expose-services="8080:http" \
      io.openshift.tags="python,python38,rh-python38" \
      com.redhat.component="python38-docker" \
      name="insights-rbac" \
      version="1" \
      maintainer="Red Hat Insights"


# Very minimal set of packages
# glibc-langpack-en is needed to set locale to en_US and disable warning about it
# gcc to compile some python packages (e.g. ciso8601)
# shadow-utils to make useradd available
RUN INSTALL_PKGS="python38 python38-devel glibc-langpack-en libpq-devel gcc shadow-utils" && \
    microdnf --nodocs -y upgrade && \
    microdnf -y --setopt=tsflags=nodocs --setopt=install_weak_deps=0 install $INSTALL_PKGS && \
    rpm -V $INSTALL_PKGS && \
    microdnf -y clean all --enablerepo='*'

# PIPENV_DEV is set to true in the docker-compose allowing
# local builds to install the dev dependencies
ARG PIPENV_DEV=False
ARG USER_ID=1001

# Create a Python virtual environment for use by any application to avoid
# potential conflicts with Python packages preinstalled in the main Python
# installation.
RUN python3.8 -m venv /pipenv-venv
ENV PATH="/pipenv-venv/bin:$PATH"
# Install pipenv into the virtual env
RUN \
    pip install --upgrade pip && \
    pip install pipenv

WORKDIR ${APP_ROOT}

# install dependencies
ENV PIP_DEFAULT_TIMEOUT=100
COPY Pipfile .
COPY Pipfile.lock .
RUN \
    pip install --upgrade pip && \
    pip install pipenv && \
    pip install pipenv-to-requirements && \
    pipenv run pipenv_to_requirements -f && \
    pipenv install -r requirements.txt


# Runtime env variables:
ENV VIRTUAL_ENV=${APP_ROOT}/.venv
ENV \
    # Add the rbac virtual env bin to the front of PATH.
    # This activates the virtual env for all subsequent python calls.
    PATH="$VIRTUAL_ENV/bin:$PATH" \
    PROMETHEUS_MULTIPROC_DIR=/tmp

# copy the src files into the workdir
COPY . .

RUN touch ${APP_HOME}/app.log; chmod 777 ${APP_HOME}/app.log

# test
RUN chown -R 1001:0 ${APP_ROOT}

# create the rbac user
RUN \
    adduser rbac -u ${USER_ID} -g 0 && \
    chmod ug+rw ${APP_ROOT} ${APP_HOME} ${APP_HOME}/staticfiles /tmp
USER rbac


# create the static files
RUN \
    python rbac/manage.py collectstatic --noinput && \
    # This `app.log` file is created during the `collectstatic` step. We need to
    # remove it else the random OCP user will not be able to access it. This file
    # will be recreated by the Pod when the application starts.
    rm ${APP_HOME}/app.log

EXPOSE 8000

ENTRYPOINT ["./scripts/entrypoint.sh"]
