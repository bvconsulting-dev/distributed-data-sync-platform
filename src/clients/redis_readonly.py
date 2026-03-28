
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from .redis import DynamicRedisService
from ..config.settings import RedisConfig, VaultConfigLoader
from ..exceptions.base import ConfigurationError

class ReadOnlyRedisService:

    def __init__(self, base_config: RedisConfig, vault_loader: VaultConfigLoader = None, 
                 bundle_region_map: Dict[str, str] = None, check_roles_exist_in_TargetSystem: bool = False,
                 correlation_id: str = None):

        self.correlation_id = correlation_id or f"readonly_redis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

        self._redis_service = DynamicRedisService(
            base_config=base_config,
            vault_loader=vault_loader,
            bundle_region_map=bundle_region_map,
            check_roles_exist_in_TargetSystem=check_roles_exist_in_TargetSystem,
            correlation_id=correlation_id
        )
        
        self.logger.info("Read-only Redis service initialized - write operations are disabled")

    @property
    def config(self) -> RedisConfig:

        return self._redis_service.config

    async def get_synchronizer_data(self, key: str, bundle: str = "default", env: str = "dev") -> Optional[str]:

        self.logger.debug(f"Read-only Redis: Getting data for key '{key}' in {bundle}/{env}")
        return await self._redis_service.get_synchronizer_data(key, bundle, env)

    async def check_synchronizer_status(self, key: str, bundle: str = "default", env: str = "dev") -> bool:

        self.logger.debug(f"Read-only Redis: Checking status for key '{key}' in {bundle}/{env}")
        return await self._redis_service.check_synchronizer_status(key, bundle, env)

    async def test_connection(self, bundle: str = "default", env: str = "dev") -> bool:

        self.logger.debug(f"Read-only Redis: Testing connection for {bundle}/{env}")
        return await self._redis_service.test_connection(bundle, env)

    async def set_synchronizer_data(self, key: str, data: str, bundle: str = "default", env: str = "dev", expire: int = 3600) -> bool:

        self.logger.warning(f"Read-only Redis: BLOCKED write operation - set_synchronizer_data for key '{key}' in {bundle}/{env}")
        self.logger.info("Redis is configured for read-only access from engine")
        return False

    async def delete_synchronizer_data(self, key: str, bundle: str = "default", env: str = "dev") -> bool:

        self.logger.warning(f"Read-only Redis: BLOCKED write operation - delete_synchronizer_data for key '{key}' in {bundle}/{env}")
        self.logger.info("Redis is configured for read-only access from engine")
        return False

    def is_read_only(self) -> bool:

        return True

    def get_allowed_operations(self) -> list:

        return [
            "get_synchronizer_data",
            "check_synchronizer_status", 
            "test_connection"
        ]

    def get_blocked_operations(self) -> list:

        return [
            "set_synchronizer_data",
            "delete_synchronizer_data"
        ]

class ReadOnlyRedisServiceFactory:

    @staticmethod
    def create_read_only_service(base_config: RedisConfig, vault_loader: VaultConfigLoader = None,
                                bundle_region_map: Dict[str, str] = None, check_roles_exist_in_TargetSystem: bool = False,
                                correlation_id: str = None) -> ReadOnlyRedisService:

        return ReadOnlyRedisService(
            base_config=base_config,
            vault_loader=vault_loader,
            bundle_region_map=bundle_region_map,
            check_roles_exist_in_TargetSystem=check_roles_exist_in_TargetSystem,
            correlation_id=correlation_id
        )