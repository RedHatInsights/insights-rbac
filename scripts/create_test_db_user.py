#!/usr/bin/env python3

from os import environ as e

import psycopg2

config = "dbname='%s' user='%s' host='%s' port='%s' password='%s'"

name, user, host, port, pw = e["DATABASE_NAME"], e["DATABASE_USER"], e["DATABASE_HOST"], e["DATABASE_PORT"], e["PGPASSWORD"]

conn = psycopg2.connect(config % (name, "postgres", host, port, pw))
conn.set_isolation_level(0)
cur = conn.cursor()
cur.execute("DROP DATABASE IF EXISTS test_%s" % name)
cur.execute("DROP USER %s" % user)
cur.execute("CREATE USER %s WITH SUPERUSER LOGIN PASSWORD '%s'" % (user, pw))
