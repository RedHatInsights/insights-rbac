import psycopg2
import requests


def setup_needs():
    setup_db_for_debezium()
    setup_connector()


def setup_connector():
    with open("./connector.json") as cj:
        d = cj.read()

    print(d)
    headers = {"Content-type": "application/json"}
    res = requests.put(
        url="http://localhost:8083/connectors/debezium-test/config",
        data=d,
        headers=headers,
    )
    res.raise_for_status()


def setup_db_for_debezium():
    try:
        conn = psycopg2.connect(
            "host=localhost port=15432 dbname=postgres user=postgres password=postgres"
        )
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("ALTER SYSTEM SET wal_level = logical;")
        conn.commit()
        cur.execute("CREATE TABLE outbox (name varchar(80), test int);")
        conn.commit()
    except psycopg2.errors.DuplicateTable as e:
        print(e)


if __name__ == "__main__":
    setup_needs()
