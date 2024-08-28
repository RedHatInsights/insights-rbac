# Local Debezium Testing
In the main insights-rbac directory there is now a docker-compose-kafka.yml file that has added a local Kafka cluster and KafkaConnect instance to the standard RBAC setup to allow for testing of Debezium setups for Kessel/Relations.

In this directory are a series of scripts for setting up and testing the results of the debezium connector's use with the RBAC database.

# Setup
Stand up the testing environment with `docker-compose -f docker-compose-kafka.yml up` to get things up and running. This will require an active login to the cloudservices quay.io repository to pull our KafkaConnect image with the necessary connector plugins already installed.

Once the testing environment is up and running, run the the `setup_local.py` python script in this directory to add the necessary `outbox` table and wal_level configurations to the RBAC postgres DB and create the `debezium-test` connector on the local KafkaConnect instance.

# Testing
With the above complete, any INSERT into the `outbox` table will result in a corresponding message to the `debezium-testing.public.outbox` topic on Kafka. The messages in this topic can be checked with the `check_events.sh` script, also in this directory.

Eventually, we'll have an output process or Kafka Connector that will grab events from the outbox events topic and replicate them to the relations API or directly into the appropriate DB tables. For now, please use this setup to see how KafkaConnect/Debezium and the RBAC DB work together and what the format of the messages will be. 
