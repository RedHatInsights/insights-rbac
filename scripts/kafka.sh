#!/bin/bash

# Function to display usage
usage() {
  echo "Usage: $0 -n <NAMESPACE> | --namespace <NAMESPACE>"
  exit 1
}

# Check if no arguments are provided
if [ $# -eq 0 ]; then
  usage
fi

# Parse command-line arguments
while [[ "$1" =~ ^- ]]; do
  case "$1" in
    -n|--namespace)
      shift
      if [[ -n "$1" ]]; then
        NAMESPACE="$1"
      else
        echo "Error: Argument for $1 is missing."
        usage
      fi
      shift
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

# Check if the NAMESPACE variable is set
if [ -z "$NAMESPACE" ]; then
  echo "Error: NAMESPACE is required."
  usage
fi

# Example operation using the NAMESPACE
echo "The provided namespace is: $NAMESPACE"
oc process -f ../deploy/kafka-connect.yml --namespace=$NAMESPACE | oc apply --namespace=$NAMESPACE -f -
oc process -f ../deploy/debezium-connector.yml --param-file=connector-params.env --namespace=$NAMESPACE | oc apply --namespace=$NAMESPACE -f -
