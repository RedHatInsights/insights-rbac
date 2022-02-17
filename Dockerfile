FROM registry.access.redhat.com/ubi8/python-36

EXPOSE 8080

ENV NODEJS_VERSION=14 \
    NODEJS_SCL=rh-nodejs14 \
    NPM_RUN=start \
    NODEJS_SCL=rh-nodejs14 \
    NPM_CONFIG_PREFIX=$HOME/.npm-global \
    PATH=$HOME/.local/bin/:$HOME/node_modules/.bin/:$HOME/.npm-global/bin/:$PATH \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    PIP_NO_CACHE_DIR=off \
    UPGRADE_PIP_TO_LATEST=true \
    PIP_INDEX_URL="" \
    PIPENV_PYPI_MIRROR="" \
    ENABLE_PIPENV=true \
    APP_CONFIG=/opt/app-root/src/rbac/gunicorn.py \
    APP_HOME=/opt/app-root/src/rbac \
    APP_MODULE=rbac.wsgi \
    APP_NAMESPACE=rbac


ENV SUMMARY="Insights RBAC is a role based access control web server" \
    DESCRIPTION="Insights RBAC is a role based access control web server"

LABEL summary="$SUMMARY" \
      description="$DESCRIPTION" \
      io.k8s.description="$DESCRIPTION" \
      io.k8s.display-name="insights-rbac" \
      io.openshift.expose-services="8080:http" \
      io.openshift.tags="python,python36,rh-python36" \
      com.redhat.component="python36-docker" \
      name="insights-rbac" \
      version="1" \
      maintainer="Red Hat Insights"

USER root

RUN yum module reset nodejs -y
RUN yum install @nodejs:14 -y
RUN yum install screen -y

# Copy the S2I scripts from the specific language image to $STI_SCRIPTS_PATH.
COPY openshift/s2i/bin $STI_SCRIPTS_PATH

# Copy extra files to the image.
COPY openshift/root /

# Copy application files to the image.
COPY . ${APP_ROOT}/src

# - Create a Python virtual environment for use by any application to avoid
#   potential conflicts with Python packages preinstalled in the main Python
#   installation.
# - In order to drop the root user, we have to make some directories world
#   writable as OpenShift default security model is to run the container
#   under random UID.
RUN virtualenv ${APP_ROOT} && \
    chown -R 1001:0 ${APP_ROOT} && \
    fix-permissions ${APP_ROOT} -P && \
    rpm-file-permissions && \
    $STI_SCRIPTS_PATH/assemble || true

RUN curl -L -o /usr/bin/haberdasher \
https://github.com/RedHatInsights/haberdasher/releases/latest/download/haberdasher_linux_amd64 && \
chmod 755 /usr/bin/haberdasher

RUN touch /opt/app-root/src/rbac/app.log; chmod 777 /opt/app-root/src/rbac/app.log
USER 1001

ENTRYPOINT ["/usr/bin/haberdasher"]

# Set the default CMD to print the usage of the language image.
CMD $STI_SCRIPTS_PATH/run
