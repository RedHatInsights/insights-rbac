#!/bin/bash

TAG=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 7 | head -n 1`
IMAGE="127.0.0.1:5000/rbac"

podman build -t $IMAGE:$TAG -f Dockerfile

podman push $IMAGE:$TAG `minikube ip`:5000/rbac:$TAG --tls-verify=false

bonfire deploy --get-dependencies --namespace metaverse -p rbac/rbac/$IMAGE_TAG=$TAG rbac -i $IMAGE=$TAG

echo $TAG
