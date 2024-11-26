import time
from django.db import connections, OperationalError
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    """Custom command to wait for the database to be available"""

    def handle(self, *args, **kwargs):
        self.stdout.write('Waiting for the database connection...')
        retries = 5  # Number of retries
        wait_time = 2
        while retries > 0:
            try:
                connections['default'].ensure_connection()
                self.stdout.write(self.style.SUCCESS('Database connection established.'))
                return
            except OperationalError as e:
                self.stdout.write(f"Database not available: {e}. Retrying in 1 second...")
                retries -= 1
                time.sleep(wait_time)
                wait_time *= 2  # Exponential backoff

        self.stderr.write(self.style.ERROR('Database connection failed after retries.'))
        raise OperationalError("Unable to connect to the database.")
