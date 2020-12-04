"""Redis-based caching of per-Principal per-app access policy."""

import contextlib
import json
import logging
import pickle

from django.conf import settings
from redis import BlockingConnectionPool, exceptions
from redis.client import Redis

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
_connection_pool = BlockingConnectionPool(
    max_connections=10, **settings.REDIS_CACHE_CONNECTION_PARAMS  # should match gunicorn.threads
)


class BasicCache:
    """Basic cache class to be inherited."""

    def __init__(self):
        """Init the class."""
        self._connection = None

    @property
    def connection(self):
        """Get Redis connection from the pool."""
        if not self._connection:
            self._connection = Redis(connection_pool=_connection_pool)
            try:
                self._connection.ping()
            except exceptions.RedisError:
                self._connection = None
                raise
        return self._connection

    @contextlib.contextmanager
    def delete_handler(self, err_msg):
        """Handle delete events."""
        try:
            yield
        except exceptions.RedisError:
            logger.exception(err_msg)

    def get_from_redis(self, key):
        """Get object from redis based on key."""
        raise Exception("Please override the get_from_redis method.")

    def get_cached(self, key, error_message):
        """Get cached object from redis, throw error if there is any."""
        try:
            return self.get_from_redis(key)
        except exceptions.RedisError:
            logger.exception(error_message)
        return None

    def delete_cached(self, key, obj_name):
        """Delete cache from redis."""
        err_msg = f"Error deleting {obj_name} for {key}"
        with self.delete_handler(err_msg):
            logger.info(f"Deleting {obj_name} cache for {key}")
            self.connection.delete(self.key_for(key))

    def set_cache(self, pipe, key, item):
        """Set cache to redis."""
        raise Exception("Please override the set_cache method.")

    def save(self, key, item, obj_name):
        """Save cache including exception handler."""
        try:
            logger.info(f"Caching {obj_name} for {key}")
            with self.connection.pipeline() as pipe:
                self.set_cache(pipe, key, item)
        except exceptions.RedisError:
            logger.exception(f"Error writing {obj_name} for {key}")
        finally:
            try:
                pipe.reset()
            except:  # noqa: E722
                pass


class TenantCache(BasicCache):
    """Redis-based caching of tenant."""

    def key_for(self, schema_name):
        """Redis key for a given tenant."""
        return f"rbac::tenant::schema={schema_name}"

    def get_from_redis(self, key):
        """Override the method to get tenant based on key."""
        obj = self.connection.get(self.key_for(key))
        if obj:
            return pickle.loads(obj)

    def get_tenant(self, schema_name):
        """Get the tenant by schema_name."""
        return super().get_cached(schema_name, f"Error querying tenant {schema_name}")

    def set_cache(self, pipe, key, item):
        """Override the method to set tenant to cache."""
        pipe.set(self.key_for(key), pickle.dumps(item))
        pipe.expire(self.key_for(key), settings.ACCESS_CACHE_LIFETIME)
        pipe.execute()

    def save_tenant(self, tenant):
        """Write the tenant for a request to Redis."""
        super().save(tenant.schema_name, tenant, "tenant")

    def delete_tenant(self, schema_name):
        """Purge the given tenant from the cache."""
        super().delete_cached(schema_name, "tenant")


class AccessCache(BasicCache):
    """Redis-based caching of per-Principal per-app access policy."""  # noqa: D204

    def __init__(self, tenant):
        """tenant: The name of the database schema for this tenant."""
        self.tenant = tenant
        super().__init__()

    def key_for(self, uuid):
        """Redis key for a given user policy."""
        return f"rbac::policy::tenant={self.tenant}::user={uuid}"

    def set_cache(self, pipe, args, item):
        """Set cache to redis."""
        pipe.hset(self.key_for(args[0]), args[1], json.dumps(item))
        pipe.expire(self.key_for(args[0]), settings.ACCESS_CACHE_LIFETIME)
        pipe.execute()

    def get_from_redis(self, args):
        """Get object from redis based on args."""
        obj = self.connection.hget(*(self.key_for(args[0]), args[1]))
        if obj:
            return json.loads(obj)

    def get_policy(self, uuid, application):
        """Get the given user's policy for the given application."""
        if not settings.ACCESS_CACHE_ENABLED:
            return None
        return super().get_cached((uuid, application), f"Error querying policy for uuid {uuid}")

    def delete_policy(self, uuid):
        """Purge the given user's policy from the cache."""
        super().delete_cached(uuid, "policy")

    def delete_all_policies_for_tenant(self):
        """Purge users' policies for a given tenant from the cache."""
        if not settings.ACCESS_CACHE_ENABLED:
            return
        err_msg = f"Error deleting all policies for tenant {self.tenant}"
        with self.delete_handler(err_msg):
            logger.info("Deleting entire policy cache for tenant %s", self.tenant)
            keys = self.connection.keys(self.key_for("*"))
            if keys:
                self.connection.delete(*keys)

    def save_policy(self, uuid, application, policy):
        """Write the policy for a given user for a given app to Redis."""
        if not settings.ACCESS_CACHE_ENABLED:
            return
        super().save((uuid, application), policy, "policy")
