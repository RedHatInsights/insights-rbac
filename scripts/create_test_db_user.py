#!/usr/bin/env python3

import psycopg2
from os import environ as e

config = "dbname='%s' user='%s' host='%s' password='%s'"

name, user, host, pw = e["DATABASE_NAME"], e["DATABASE_USER"], "%s:%s" % (e["DATABASE_HOST"], e["DATABASE_PORT"]), e["DATABASE_PASSWORD"]

conn = psycopg2.connect(config % (name, user, host, pw))
cur = conn.cursor()
cur.execute("DROP DATABASE IF EXISTS test_%s" % name)
cur.execute("DROP USER %s" % user)
cur.execute("CREATE USER %s WITH SUPERUSER LOGIN PASSWORD '%s'" % (user, pw))
