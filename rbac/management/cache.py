"""Redis-based caching of per-Principal per-app access policy."""

import contextlib
import json
import logging
import pickle

from django.conf import settings
from prometheus_client import Counter
from redis import BlockingConnectionPool, exceptions
from redis.client import Redis

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
_connection_pool = BlockingConnectionPool(**settings.REDIS_CACHE_CONNECTION_PARAMS)  # should match gunicorn.threads

redis_enable_cache_get_total = Counter("redis_enable_cache_get_total", "Total amount of use_caching is true")
redis_disable_cache_get_total = Counter(
    "redis_disable_cache_get_total", "Total amount of times cache has been disabled"
)

BATCH_DELETE_SIZE = 1000


class BasicCache:
    """Basic cache class to be inherited."""

    def __init__(self):
        """Init the class."""
        self._connection = None
        self.use_caching = True

    @property
    def connection(self):
        """Get Redis connection from the pool."""
        if not self._connection:
            self._connection = Redis(connection_pool=_connection_pool, ssl=settings.REDIS_SSL)
            try:
                self._connection.ping()
            except exceptions.RedisError:
                self._connection = None
                raise
        return self._connection

    def enable_caching(self):
        """Enable caching and increment prometheus metric that redis caching is enabled."""
        self.use_caching = True
        logger.info("Redis Cache Enabled")
        redis_enable_cache_get_total.inc()
        return self.use_caching

    def disable_caching(self):
        """Disable caching and increment prometheus metric that redis caching is disabled."""
        self.use_caching = False
        logger.info("Redis Cache Disabled")
        redis_disable_cache_get_total.inc()
        return self.use_caching

    def redis_health_check(self):
        """Check whether redis cache is reachable. If it is not reachable, then disable caching."""
        self._connection = Redis(connection_pool=_connection_pool, ssl=settings.REDIS_SSL)
        try:
            response = self._connection.ping()
            if response:
                logger.info("Redis cache is reachable.")
                self.enable_caching()
                return True
            else:
                logger.info("Redis cache is not reachable.")
                self.disable_caching()
                return False
        except Exception as e:
            logger.exception(f"Error: {e}")

    @contextlib.contextmanager
    def delete_handler(self, err_msg):
        """Handle delete events."""
        try:
            yield
        except exceptions.RedisError:
            logger.exception(err_msg)

    def get_from_redis(self, key):
        """Get object from redis based on key."""
        raise NotImplementedError("Please override the get_from_redis method.")

    def get_cached(self, key, error_message):
        """Get cached object from redis, throw error if there is any."""
        try:
            if self.redis_health_check() is True:
                if self.use_caching:
                    return self.get_from_redis(key)
            else:
                # Retrieve data directly
                logger.info("Not Retrieving Data from Redis Cache")
                self.disable_caching()
                pass
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
        raise NotImplementedError("Please override the set_cache method.")

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

    def key_for(self, key):
        """Redis key for a given tenant."""
        return f"rbac::tenant::tenant={key}"

    def get_from_redis(self, key):
        """Override the method to get tenant based on key."""
        obj = self.connection.get(self.key_for(key))
        if obj:
            return pickle.loads(obj)

    def get_tenant(self, key):
        """Get the tenant by tenant_name."""
        return super().get_cached(key, f"Error querying tenant {key}")

    def set_cache(self, pipe, key, item):
        """Override the method to set tenant to cache."""
        pipe.set(self.key_for(key), pickle.dumps(item))
        pipe.expire(self.key_for(key), settings.ACCESS_CACHE_LIFETIME)
        pipe.execute()

    def save_tenant(self, tenant):
        """Write the tenant for a request to Redis."""
        super().save(tenant.org_id, tenant, "tenant")

    def delete_tenant(self, key):
        """Purge the given tenant from the cache."""
        super().delete_cached(key, "tenant")


class AccessCache(BasicCache):
    """Redis-based caching of per-Principal per-app access policy."""  # noqa: D204

    def __init__(self, tenant: str):
        """
        tenant: The name of the database schema for this tenant.

        if tenant is *, then it is for all tenants.
        """
        if not tenant:
            raise ValueError("tenant must be provided")
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

    def get_policy(self, uuid, sub_key):
        """Get the given user's policy for the given sub_key (application_offset_limit)."""
        if not settings.ACCESS_CACHE_ENABLED:
            return None
        return super().get_cached((uuid, sub_key), f"Error querying policy for uuid {uuid}")

    def delete_policy(self, uuid):
        """Purge the given user's policy from the cache."""
        super().delete_cached(uuid, "policy")

    def delete_all_policies_for_tenant(self):
        """Purge users' policies for a given tenant from the cache."""
        if not settings.ACCESS_CACHE_ENABLED:
            return
        err_msg = f"Error deleting all policies for tenant {self.tenant}"
        with self.delete_handler(err_msg):
            logger.info(f"Deleting entire policy cache for tenant {self.tenant}")
            # Following piece is taken from https://github.com/jazzband/django-redis/pull/617
            count = 0
            pipeline = self.connection.pipeline()
            for key in self.connection.scan_iter(match=self.key_for("*"), count=BATCH_DELETE_SIZE):
                pipeline.delete(key)
                count += 1
            pipeline.execute()
            logger.info(f"Deleted {count} policies for tenant {self.tenant}")

    def save_policy(self, uuid, sub_key, policy):
        """Write the policy for a given user for a given sub_key (application_offset_limit) to Redis."""
        if not settings.ACCESS_CACHE_ENABLED:
            return
        super().save((uuid, sub_key), policy, "policy")


class JWKSCache(BasicCache):
    """Redis-based caching for the storage of JKWS certificates."""

    JWKS_CACHE_KEY = "rbac::jwks:response"

    def key_for(self):
        """Redis key for the JWKS certificate response."""
        return "rbac::jwks::response"

    def set_cache(self, pipe, key, item):
        """Set cache to redis."""
        pipe.hset(key=key, value=json.dumps(item), name="hi")
        pipe.expire(name=key, time=settings.IT_TOKEN_JKWS_CACHE_LIFETIME)
        pipe.execute()

    def get_from_redis(self, args):
        """Get object from redis based on args."""
        obj = self.connection.hget(*(self.JWKS_CACHE_KEY, args[1]))
        if obj:
            return json.loads(obj)

    def get_jwks_response(self):
        """Get the JWKS certificates' response from Redis."""
        return super().get_cached(self.JWKS_CACHE_KEY, "Unable to fetch the JWKS response from Redis")

    def set_jwks_response(self, response):
        """Save the JWKS certificates' response in Redis."""
        super().save(self.JWKS_CACHE_KEY, response, "JWKS response")


def skip_purging_cache_for_public_tenant(tenant):
    """Skip purging cache for public tenant."""
    # Cache is by tenant org_id and user_id, we don't have to purge cache for public tenant
    if tenant.tenant_name == "public":
        return True
