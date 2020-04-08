import json
import logging

from django.conf import settings
from redis import BlockingConnectionPool, exceptions
from redis.client import Redis

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
_connection_pool = BlockingConnectionPool(
    max_connections=10,  # should match gunicorn.threads
    **settings.REDIS_CACHE_CONNECTION_PARAMS)


class AccessCache:
    def __init__(self, tenant):
        self.tenant = tenant
        self._connection = None
    
    @property
    def connection(self):
        if not self._connection:
            self._connection = Redis(connection_pool=_connection_pool)
            try:
                self._connection.ping()
            except exceptions.RedisError:
                self._connection = None
                raise
        return self._connection        

    def key_for(self, uuid):
        return f'rbac::policy::tenant={self.tenant}::user={uuid}'

    def get_policy(self, uuid, application):
        if not settings.ACCESS_CACHE_ENABLED:
            return None
        try:
            policy_string = self.connection.hget(
                self.key_for(uuid),
                application
            )
            if policy_string:
                return json.loads(policy_string)
        except exceptions.RedisError:
            logger.exception('Error querying policy for uuid %s', uuid)
        return None
    
    def delete_policy(self, uuid):
        if not settings.ACCESS_CACHE_ENABLED:
            return
        try:
            logger.info('Deleting policy cache for uuid %s', uuid)
            self.connection.delete(self.key_for(uuid))
        except exceptions.RedisError:
            logger.exception('Error deleting policy for uuid %s', uuid)
    
    def save_policy(self, uuid, application, policy):
        if not settings.ACCESS_CACHE_ENABLED:
            return
        try:
            logger.info('Caching policy for uuid %s', uuid)
            with self.connection.pipeline() as pipe:
                pipe.hset(
                    self.key_for(uuid),
                    application,
                    json.dumps(policy)
                )
                pipe.expire(self.key_for(uuid), settings.ACCESS_CACHE_LIFETIME)
                pipe.execute()
        except exceptions.RedisError:
            logger.exception('Error writing policy for uuid %s', uuid)
        finally:
            try:
                pipe.reset()
            except:
                pass

