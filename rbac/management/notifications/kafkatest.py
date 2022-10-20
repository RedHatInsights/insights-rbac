from kafka import KafkaConsumer

conf = {
    "bootstrap_servers": "consoledot-c-th-hq-ph--rr-ujfmg.bf2.kafka.rhcloud.com:443",
    "sasl_plain_username": "srvc-acct-6cf26dd4-91a9-4236-b4b2-90b02463ed69",
    "sasl_plain_password": "763074b1-4b63-421e-af47-4bf0e01527f3",
    "sasl_mechanism": "PLAIN",
    "security_protocol": "SASL_SSL",
    "auto_offset_reset": "earliest",
}

c = KafkaConsumer(**conf)

c.subscribe(topics="platform-mq-stage.platform.upload.advisor")

while True:
    msgs = c.poll()
    if msgs:
        print(msgs)
