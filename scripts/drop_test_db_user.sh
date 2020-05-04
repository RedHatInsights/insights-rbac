DB_USER=$1

psql ${DATABASE_NAME} -p ${DATABASE_PORT} -h ${DATABASE_HOST} -U postgres -c "DROP USER ${DB_USER};" || true
