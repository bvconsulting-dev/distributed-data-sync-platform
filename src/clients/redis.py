import os
import ssl
import logging
from typing import Dict, Any, Optional
from datetime import datetime

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError as e:
    REDIS_AVAILABLE = False
    REDIS_IMPORT_ERROR = str(e)

from ..config.settings import RedisConfig, VaultConfigLoader
from ..exceptions.base import ConfigurationError


class RedisClient:

    def __init__(self, config: RedisConfig):
        self.host = config.host
        self.port = config.port
        self.password = config.password
        self.db = config.db
        self.ssl_enabled = config.ssl
        self.ssl_cert_reqs = getattr(config, 'ssl_cert_reqs', 'None')
        self.correlation_id = f"redis_client_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

        self.redis_pool = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        check_roles = os.getenv("SYNC_ENGINE_CHECK_ROLES_EXIST_IN_TARGET_SYSTEM", "true").lower() == "true"
        if not check_roles:
            self.logger.info("Redis connection skipped (SYNC_ENGINE_CHECK_ROLES_EXIST_IN_TARGET_SYSTEM=false)")
            return
        if not REDIS_AVAILABLE:
            self.logger.error(f"Redis library not available: {REDIS_IMPORT_ERROR}")
            raise ConfigurationError(f"Redis library not available: {REDIS_IMPORT_ERROR}")

        try:
            scheme = "rediss" if self.ssl_enabled else "redis"
            if self.password:
                url = f"{scheme}://:{self.password}@{self.host}:{self.port}/{self.db}"
            else:
                url = f"{scheme}://{self.host}:{self.port}/{self.db}"

            pool_params = {
                'decode_responses': True,
                'max_connections': 20
            }

            self.redis_pool = aioredis.ConnectionPool.from_url(url, **pool_params)

            redis = aioredis.Redis(connection_pool=self.redis_pool)
            await redis.ping()
            self.logger.info(f"Connected to Redis at {self.host}:{self.port}")

        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            raise ConfigurationError(f"Redis connection failed: {e}")

    async def disconnect(self):
        if self.redis_pool:
            await self.redis_pool.disconnect()
            self.logger.info("Disconnected from Redis")

    async def get_redis_connection(self):
        if not REDIS_AVAILABLE:
            raise ConfigurationError(f"Redis library not available: {REDIS_IMPORT_ERROR}")
        if not self.redis_pool:
            raise ConfigurationError("Redis connection not established")
        return aioredis.Redis(connection_pool=self.redis_pool)

    async def set_value(self, key: str, value: str, expire: int = None) -> bool:
        try:
            redis = await self.get_redis_connection()
            result = await redis.set(key, value, ex=expire)
            return result
        except Exception as e:
            self.logger.error(f"Failed to set Redis key {key}: {e}")
            return False

    async def get_value(self, key: str) -> Optional[str]:
        try:
            redis = await self.get_redis_connection()
            return await redis.get(key)
        except Exception as e:
            self.logger.error(f"Failed to get Redis key {key}: {e}")
            return None

    async def delete_key(self, key: str) -> bool:
        try:
            redis = await self.get_redis_connection()
            result = await redis.delete(key)
            return result > 0
        except Exception as e:
            self.logger.error(f"Failed to delete Redis key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        try:
            redis = await self.get_redis_connection()
            return await redis.exists(key) > 0
        except Exception as e:
            self.logger.error(f"Failed to check Redis key {key}: {e}")
            return False

    async def ping(self) -> bool:
        try:
            redis = await self.get_redis_connection()
            await redis.ping()
            return True
        except Exception:
            return False


class RedisService:

    def __init__(self, config: RedisConfig):
        self.config = config

    async def set_synchronizer_data(self, key: str, data: str, expire: int = 3600) -> bool:
        async with RedisClient(self.config) as client:
            return await client.set_value(key, data, expire)

    async def get_synchronizer_data(self, key: str) -> Optional[str]:
        async with RedisClient(self.config) as client:
            return await client.get_value(key)

    async def delete_synchronizer_data(self, key: str) -> bool:
        async with RedisClient(self.config) as client:
            return await client.delete_key(key)

    async def check_synchronizer_status(self, key: str) -> bool:
        async with RedisClient(self.config) as client:
            return await client.exists(key)

    async def test_connection(self) -> bool:
        async with RedisClient(self.config) as client:
            return await client.ping()


class DynamicRedisService:

    def __init__(self, base_config: RedisConfig, vault_loader: VaultConfigLoader = None, 
                 bundle_region_map: Dict[str, str] = None, check_roles_exist_in_TargetSystem: bool = False,
                 correlation_id: str = None):
        self.base_config = base_config
        self.vault_loader = vault_loader
        self.bundle_region_map = bundle_region_map or {}
        self.check_roles_exist_in_TargetSystem = check_roles_exist_in_TargetSystem
        self.correlation_id = correlation_id or f"redis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self._config_cache = {}
        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

    @property
    def config(self) -> RedisConfig:
        return self.base_config

    def _should_use_redis(self) -> bool:
        return self.check_roles_exist_in_TargetSystem

    async def _get_dynamic_config(self, bundle: str, env: str) -> RedisConfig:
        cache_key = f"{bundle}_{env}"
        if cache_key in self._config_cache:
            return self._config_cache[cache_key]

        try:
            use_vault = os.getenv("USE_VAULT", "false").lower() == "true"
            redis_use_dynamic = os.getenv("REDIS_USE_DYNAMIC_CONFIG", "false").lower() == "true"
            TargetSystem_use_dynamic = os.getenv("TargetSystem_USE_DYNAMIC_API", "false").lower() == "true"
            deployment_destination = os.getenv("DEPLOYMENT_TARGET", "OCI")

            if redis_use_dynamic and TargetSystem_use_dynamic and deployment_destination == "OCI":
                if use_vault:

                    if not self.vault_loader:
                        self.logger.warning("Vault loader not available for OCI dynamic Redis configuration, using base config")
                        return self.base_config

                    self.logger.info(f"Loading Redis config from OCI vault path for bundle={bundle}, env={env}")
                    vault_config = await self.vault_loader.load_oci_redis_config(bundle, env)
                else:

                    self.logger.info(f"Loading Redis config from environment variables for bundle={bundle}, env={env}")
                    from ..config.settings import VaultConfigLoader
                    vault_config = VaultConfigLoader.load_env_redis_config(bundle, env, self.bundle_region_map)
            elif redis_use_dynamic and not TargetSystem_use_dynamic and deployment_destination == "OCI":
                if use_vault:
                    if not self.vault_loader:
                        self.logger.warning("Vault loader not available for OCI dynamic Redis configuration, using base config")
                        return self.base_config
                    
                    self.logger.info(f"Loading Redis config from OCI vault path for bundle={bundle}, env={env}")
                    vault_config = await self.vault_loader.load_oci_redis_config(bundle, env)
                else:
                    self.logger.info(f"Loading Redis config from environment variables for bundle={bundle}, env={env}")
                    from ..config.settings import VaultConfigLoader
                    vault_config = VaultConfigLoader.load_env_redis_config(bundle, env, self.bundle_region_map)
            else:
                if not self.vault_loader:
                    self.logger.warning("Vault loader not available for dynamic Redis configuration, using base config")
                    return self.base_config
                
                self.logger.info(f"Loading Redis config from original vault path for bundle={bundle}, env={env}")
                vault_config = await self.vault_loader.load_redis_config(bundle, env, self.bundle_region_map)

            dynamic_config = RedisConfig(
                host=vault_config.get('host', self.base_config.host),
                port=vault_config.get('port', self.base_config.port),
                password=vault_config.get('password', self.base_config.password),
                db=vault_config.get('db', self.base_config.db),
                ssl=vault_config.get('ssl', self.base_config.ssl),
                ssl_cert_reqs=vault_config.get('ssl_cert_reqs', self.base_config.ssl_cert_reqs),
                use_dynamic_config=self.base_config.use_dynamic_config
            )

            self._config_cache[cache_key] = dynamic_config
            return dynamic_config

        except Exception as e:
            self.logger.warning(f"Failed to load dynamic Redis configuration for {bundle}/{env}: {e}, using base config")
            return self.base_config

    async def _get_config_for_request(self, bundle: str, env: str) -> RedisConfig:
        if not self._should_use_redis():
            self.logger.info("Redis disabled (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return self.base_config

        if self.base_config.use_dynamic_config:
            return await self._get_dynamic_config(bundle, env)
        else:
            return self.base_config

    async def set_synchronizer_data(self, key: str, data: str, bundle: str = "defFailed to load dynamicault", env: str = "dev", expire: int = 3600) -> bool:
        if not self._should_use_redis():
            self.logger.info("Redis operation skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return True

        config = await self._get_config_for_request(bundle, env)
        async with RedisClient(config) as client:
            return await client.set_value(key, data, expire)

    async def get_synchronizer_data(self, key: str, bundle: str = "default", env: str = "dev") -> Optional[str]:
        if not self._should_use_redis():
            self.logger.info("Redis operation skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return None

        config = await self._get_config_for_request(bundle, env)
        async with RedisClient(config) as client:
            return await client.get_value(key)

    async def delete_synchronizer_data(self, key: str, bundle: str = "default", env: str = "dev") -> bool:
        if not self._should_use_redis():
            self.logger.info("Redis operation skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return True

        config = await self._get_config_for_request(bundle, env)
        async with RedisClient(config) as client:
            return await client.delete_key(key)

    async def check_synchronizer_status(self, key: str, bundle: str = "default", env: str = "dev") -> bool:
        if not self._should_use_redis():
            self.logger.info("Redis operation skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return False

        config = await self._get_config_for_request(bundle, env)
        async with RedisClient(config) as client:
            return await client.exists(key)

    async def test_connection(self, bundle: str = "default", env: str = "dev") -> bool:
        if not self._should_use_redis():
            self.logger.info("Redis connection test skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")
            return True

        config = await self._get_config_for_request(bundle, env)
        async with RedisClient(config) as client:
            return await client.ping()
