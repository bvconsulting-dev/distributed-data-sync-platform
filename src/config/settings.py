import os
import ssl
import aiohttp
from pydantic import Field, validator
from pydantic_settings import BaseSettings
from typing import Dict, List, Optional, Union
from datetime import datetime

from ..exceptions.base import ConfigurationError, VaultConnectionError


class DatabaseConfig(BaseSettings):
	connection_string: str = Field(default="", env="DB_CONNECTION_STRING")
	enable: bool = Field(default=False, env="DB_ENABLE")
	reconnect_count: int = Field(default=3, env="DB_RECONNECT_COUNT")
	reconnect_sleep_time: int = Field(default=3, env="DB_RECONNECT_SLEEP_TIME")
	db_schema: str = Field(default="sync_dev", env="DB_SCHEMA")
	type: str = Field(default="Postgre", env="DB_TYPE")
	json_file_db_path: str = Field(default="data", env="JSON_FILE_DB_PATH")
	store_IDENTITY_MANAGER_data_enable: bool = Field(default=False, env="STORE_IDENTITY_MANAGER_DATA_ENABLE")
	store_TargetSystem_data_enable: bool = Field(default=False, env="STORE_TargetSystem_DATA_ENABLE")

	@validator('reconnect_count', pre=True)
	def validate_reconnect_count(cls, v):
		if v == '' or v is None:
			return 3
		return int(v) if isinstance(v, str) else v

	@validator('reconnect_sleep_time', pre=True)
	def validate_reconnect_sleep_time(cls, v):
		if v == '' or v is None:
			return 3
		return int(v) if isinstance(v, str) else v

	class Config:
		env_prefix = "DB_"
		env_file = ".env"
		extra = "ignore"


class IdentityManagerConfig(BaseSettings):
	file_name_path: str = Field(default="data/", env="source_FILE_NAME_PATH")
	request_rest_api_authorization: str = Field(default="", env="source_REQUEST_RESTAPI_AUTHORIZATION")
	request_rest_api_url: str = Field(default="", env="source_REQUEST_RESTAPI_URL")
	request_rest_api_timeout: int = Field(default=600, env="source_REQUEST_RESTAPI_TIMEOUT")
	verify_ssl: bool = Field(default=True, env="source_VERIFY_SSL")

	@validator('request_rest_api_timeout', pre=True)
	def validate_request_rest_api_timeout(cls, v):
		if v == '' or v is None:
			return 600
		return int(v) if isinstance(v, str) else v

	class Config:
		env_prefix = "source_"
		env_file = ".env"
		extra = "ignore"

	def __init__(self, **kwargs):
		import os
		if not kwargs:
			source_timeout = os.getenv('source_REQUEST_RESTAPI_TIMEOUT', '600')
			kwargs = {
				'file_name_path': os.getenv('source_FILE_NAME_PATH', 'data/'),
				'request_rest_api_authorization': os.getenv('source_REQUEST_RESTAPI_AUTHORIZATION', ''),
				'request_rest_api_url': os.getenv('source_REQUEST_RESTAPI_URL', ''),
				'request_rest_api_timeout': int(source_timeout) if source_timeout != '' else 600,
				'verify_ssl': os.getenv('source_VERIFY_SSL', 'true').lower() == 'true',
			}
		super().__init__(**kwargs)


class TargetSystemConfig(BaseSettings):
	request_rest_api_header_value: str = Field(default='{"Content-Type":"application/json"}',
											   env="TargetSystem_REQUEST_RESTAPI_HEADER_VALUE")
	request_rest_api_timeout: int = Field(default=180, env="TargetSystem_REQUEST_RESTAPI_TIMEOUT")
	request_rest_api_url: str = Field(default="", env="TargetSystem_REQUEST_RESTAPI_URL")
	verify_ssl: bool = Field(default=True, env="TargetSystem_VERIFY_SSL")
	dry_run_mode: bool = Field(default=False, env="TargetSystem_DRY_RUN_MODE")
	use_dynamic_api: bool = Field(default=False, env="TargetSystem_USE_DYNAMIC_API")

	@validator('request_rest_api_timeout', pre=True)
	def validate_request_rest_api_timeout(cls, v):
		if v == '' or v is None:
			return 180
		return int(v) if isinstance(v, str) else v

	class Config:
		env_prefix = "TargetSystem_"
		env_file = ".env"
		extra = "ignore"

	def __init__(self, **kwargs):
		import os
		if not kwargs:
			TargetSystem_timeout = os.getenv('TargetSystem_REQUEST_RESTAPI_TIMEOUT', '180')
			kwargs = {
				'request_rest_api_header_value': os.getenv('TargetSystem_REQUEST_RESTAPI_HEADER_VALUE',
														   '{"Content-Type":"application/json"}'),
				'request_rest_api_timeout': int(TargetSystem_timeout) if TargetSystem_timeout != '' else 180,
				'request_rest_api_url': os.getenv('TargetSystem_REQUEST_RESTAPI_URL', ''),
				'verify_ssl': os.getenv('TargetSystem_VERIFY_SSL', 'true').lower() == 'true',
				'dry_run_mode': os.getenv('TargetSystem_DRY_RUN_MODE', 'false').lower() == 'true',
				'use_dynamic_api': os.getenv('TargetSystem_USE_DYNAMIC_API', 'false').lower() == 'true',
			}
		super().__init__(**kwargs)


class TimeConfig(BaseSettings):
	date_time_format: str = Field(default="%Y-%m-%dT%H:%M:%SZ", env="DATE_TIME_FORMAT")
	default_last_time_check: str = Field(default="2025-02-14T13:10:20Z", env="DEFAULT_LAST_TIME_CHECK")
	IDENTITY_MANAGER_timezone: str = Field(default="UTC", env="IDENTITY_MANAGER_TIMEZONE")
	start_time_check: str = Field(default="", env="START_TIME_CHECK")

	class Config:
		env_prefix = ""
		env_file = ".env"
		extra = "ignore"


class LoggingConfig(BaseSettings):
	is_debug: bool = Field(default=False, env="IS_DEBUG")
	log_level: str = Field(default="INFO", env="LOG_LEVEL")
	log_format: str = Field(default="json", env="LOG_FORMAT")

	class Config:
		env_prefix = "LOG_"
		env_file = ".env"
		extra = "ignore"

	def __init__(self, **kwargs):
		import os
		if not kwargs:
			kwargs = {
				'is_debug': os.getenv('IS_DEBUG', 'false').lower() == 'true',
				'log_level': os.getenv('LOG_LEVEL', 'INFO'),
				'log_format': os.getenv('LOG_FORMAT', 'json'),
			}
		super().__init__(**kwargs)


class EngineConfig(BaseSettings):
	check_roles_exist_in_TargetSystem: bool = Field(default=True, env="CHECK_ROLES_EXIST_IN_TargetSystem")
	execute_without_IDENTITY_MANAGER_read: bool = Field(default=False, env="EXECUTE_WITHOUT_IDENTITY_MANAGER_READ")
	reprocess_count: int = Field(default=3, env="REPROCESS_COUNT")
	max_error_reprocess_count: int = Field(default=3, env="MAX_ERROR_REPROCESS_COUNT")
	max_in_progress_reprocess_count: int = Field(default=3, env="MAX_IN_PROGRESS_REPROCESS_COUNT")
	enable_error_reprocessing: bool = Field(default=True, env="ENABLE_ERROR_REPROCESSING")
	enable_in_progress_reprocessing: bool = Field(default=True, env="ENABLE_IN_PROGRESS_REPROCESSING")
	enable_json_error_reprocessing: bool = Field(default=True, env="ENABLE_JSON_ERROR_REPROCESSING")
	roles_check_file_name: str = Field(default="_missing_roles", env="ROLES_CHECK_FILE_NAME")
	roles_check_file_path: str = Field(default="data/", env="ROLES_CHECK_FILE_PATH")
	max_concurrent_files: int = Field(default=10, env="MAX_CONCURRENT_FILES")
	max_api_calls: int = Field(default=50, env="MAX_API_CALLS")
	previous_days_check: int = Field(default=20, env="PREVIOUS_DAYS_CHECK")
	domain_check_enabled: bool = Field(default=False, env="DOMAIN_CHECK_ENABLED")
	max_domains_per_user: int = Field(default=1, env="MAX_DOMAINS_PER_USER")
	role_domain_logging_enabled: bool = Field(default=False, env="ROLE_DOMAIN_LOGGING_ENABLED")

	@validator('reprocess_count', pre=True)
	def validate_reprocess_count(cls, v):
		if v == '' or v is None:
			return 3
		return int(v) if isinstance(v, str) else v

	@validator('max_error_reprocess_count', pre=True)
	def validate_max_error_reprocess_count(cls, v):
		if v == '' or v is None:
			return 3
		return int(v) if isinstance(v, str) else v

	@validator('max_in_progress_reprocess_count', pre=True)
	def validate_max_in_progress_reprocess_count(cls, v):
		if v == '' or v is None:
			return 3
		return int(v) if isinstance(v, str) else v

	@validator('max_concurrent_files', pre=True)
	def validate_max_concurrent_files(cls, v):
		if v == '' or v is None:
			return 10
		return int(v) if isinstance(v, str) else v

	@validator('max_api_calls', pre=True)
	def validate_max_api_calls(cls, v):
		if v == '' or v is None:
			return 50
		return int(v) if isinstance(v, str) else v

	@validator('previous_days_check', pre=True)
	def validate_previous_days_check(cls, v):
		if v == '' or v is None:
			return 20
		return int(v) if isinstance(v, str) else v

	@validator('max_domains_per_user', pre=True)
	def validate_max_domains_per_user(cls, v):
		if v == '' or v is None:
			return 1
		return int(v) if isinstance(v, str) else v

	class Config:
		env_prefix = ""
		env_file = ".env"
		extra = "ignore"


class RedisConfig(BaseSettings):
	host: str = Field(default="localhost", env="REDIS_HOST")
	port: int = Field(default=6379, env="REDIS_PORT")
	password: str = Field(default="", env="REDIS_PASSWORD")
	db: int = Field(default=0, env="REDIS_DB")
	ssl: bool = Field(default=False, env="REDIS_SSL")
	ssl_cert_reqs: str = Field(default="None", env="REDIS_SSL_CERT_REQS")
	use_dynamic_config: bool = Field(default=False, env="REDIS_USE_DYNAMIC_CONFIG")

	@validator('port', pre=True)
	def validate_port(cls, v):
		if v == '' or v is None:
			return 6379
		return int(v) if isinstance(v, str) else v

	@validator('db', pre=True)
	def validate_db(cls, v):
		if v == '' or v is None:
			return 0
		return int(v) if isinstance(v, str) else v

	class Config:
		env_prefix = "REDIS_"
		env_file = ".env"
		extra = "ignore"

	def __init__(self, **kwargs):
		import os
		if not kwargs:
			redis_port = os.getenv('REDIS_PORT', '6379')
			redis_db = os.getenv('REDIS_DB', '0')
			kwargs = {
				'host': os.getenv('REDIS_HOST', 'localhost'),
				'port': int(redis_port) if redis_port != '' else 6379,
				'password': os.getenv('REDIS_PASSWORD', ''),
				'db': int(redis_db) if redis_db != '' else 0,
				'ssl': os.getenv('REDIS_SSL', 'false').lower() == 'true',
				'ssl_cert_reqs': os.getenv('REDIS_SSL_CERT_REQS', 'None'),
				'use_dynamic_config': os.getenv('REDIS_USE_DYNAMIC_CONFIG', 'false').lower() == 'true',
			}
		super().__init__(**kwargs)


class SyncConfig(BaseSettings):
	database: DatabaseConfig = Field(default_factory=DatabaseConfig)
	IDENTITY_MANAGER: IdentityManagerConfig = Field(default_factory=IdentityManagerConfig)
	TargetSystem: TargetSystemConfig = Field(default_factory=TargetSystemConfig)
	time: TimeConfig = Field(default_factory=TimeConfig)
	logging: LoggingConfig = Field(default_factory=LoggingConfig)
	engine: EngineConfig = Field(default_factory=EngineConfig)
	redis: RedisConfig = Field(default_factory=RedisConfig)

	environment_list: str = Field(default="", env="ENVIRONMENT_LIST")
	bundle_region_map: Union[str, Dict[str, str]] = Field(default_factory=dict, env="BUNDLE_REGION_MAP")

	use_IDENTITY_MANAGER_bundle_env: bool = Field(default=True, env="USE_IDENTITY_MANAGER_BUNDLE_ENV")
	default_test_bundle: str = Field(default="eu01", env="DEFAULT_TEST_BUNDLE")
	default_test_environment: str = Field(default="dev", env="DEFAULT_TEST_ENVIRONMENT")

	vault_url: Optional[str] = Field(env="VAULT_URL")
	vault_token: Optional[str] = Field(env="VAULT_TOKEN")
	vault_secret_path: str = Field(default="sync_runtime_config_dev", env="VAULT_SECRET_PATH")

	correlation_id: Optional[str] = Field(default=None)

	class Config:
		env_file = ".env"
		case_sensitive = False
		extra = "ignore"

	@validator('environment_list')
	def parse_environment_list(cls, v):
		if isinstance(v, str):
			return [env.strip() for env in v.split(',') if env.strip()]
		return v

	@validator('bundle_region_map', pre=True)
	def parse_bundle_region_map(cls, v):
		if isinstance(v, str):
			try:
				import json
				return json.loads(v)
			except json.JSONDecodeError:
				result = {}
				for pair in v.split(','):
					if '=' in pair:
						key, value = pair.split('=', 1)
						result[key.strip()] = value.strip()
				return result
		return v or {}


class VaultConfigLoader:

	def __init__(self, vault_url: str, vault_token: str, verify_ssl: bool = True):
		self.vault_url = vault_url.rstrip('/')
		self.vault_token = vault_token
		self.verify_ssl = verify_ssl
		self.correlation_id = f"vault_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

	async def load_config(self, secret_path: str) -> Dict:
		try:
			ssl_context = None
			if not self.verify_ssl:
				ssl_context = ssl.create_default_context()
				ssl_context.check_hostname = False
				ssl_context.verify_mode = ssl.CERT_NONE

			connector = aiohttp.TCPConnector(ssl=ssl_context)

			async with aiohttp.ClientSession(connector=connector) as session:
				async with session.get(
						f"{self.vault_url}/v1/{secret_path}",
						headers={"X-Vault-Token": self.vault_token}
				) as response:
					if response.status == 200:
						data = await response.json()
						return data.get('data', {})
					elif response.status == 403:
						raise VaultConnectionError("Vault authentication failed")
					else:
						raise VaultConnectionError(f"Vault request failed with status {response.status}")
		except aiohttp.ClientError as e:
			raise VaultConnectionError(f"Failed to connect to Vault: {e}")

	async def load_engine_config(self, secret_path: Optional[str] = None) -> Dict:
		if secret_path is None:
			secret_path = os.getenv("VAULT_SECRET_PATH", "sync_runtime_config_dev")

		try:
			return await self.load_config(secret_path)
		except VaultConnectionError as e:
			if "status 404" in str(e):
				import logging
				logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
				logger.warning(f"Vault secret '{secret_path}' not found (404). Falling back to environment variables.")
				raise VaultConnectionError(f"Vault secret '{secret_path}' not found (404)")
			elif "authentication failed" in str(e).lower() or "status 403" in str(e):
				raise VaultConnectionError(f"Vault authentication failed. Please check VAULT_TOKEN: {e}")
			else:
				raise VaultConnectionError(f"Failed to connect to Vault: {e}")

	async def load_api_config(self, environment: str) -> Dict:
		return await self.load_config(f"sync_cicd_config/api_{environment}")

	async def load_synchronizer_config(self, environment: str) -> Dict:
		return await self.load_config(f"sync_cicd_config/synchronizer_{environment}")

	async def load_TargetSystem_api_config(self, bundle: str, environment: str, bundle_region_map: Dict[str, str]) -> Dict:
		region = None
		for region_key, bundle_list in bundle_region_map.items():
			if isinstance(bundle_list, str):
				bundles = [b.strip() for b in bundle_list.split(',')]
			else:
				bundles = bundle_list

			bundle_base = bundle.split('_')[0] if '_' in bundle else bundle
			if bundle_base in bundles:
				region = region_key
				break

		if not region:
			raise VaultConnectionError(f"No region found for bundle '{bundle}' in BUNDLE_REGION_MAP")

		config_path = f"sync_cicd_config/data/api_{region}_{environment}"
		return await self.load_config(config_path)

	async def load_redis_config(self, bundle: str, environment: str, bundle_region_map: Dict[str, str]) -> Dict:
		region = None
		for region_key, bundle_list in bundle_region_map.items():
			if isinstance(bundle_list, str):
				bundles = [b.strip() for b in bundle_list.split(',')]
			else:
				bundles = bundle_list

			bundle_base = bundle.split('_')[0] if '_' in bundle else bundle
			if bundle_base in bundles:
				region = region_key
				break

		if not region:
			raise VaultConnectionError(f"No region found for bundle '{bundle}' in BUNDLE_REGION_MAP")

		config_path = f"sync_cicd_config/data/synchronizer_{region}_{environment}"
		return await self.load_config(config_path)

	async def load_oci_synchronizer_config(self, bundle: str, environment: str) -> Dict:
		config_path = f"oci_{bundle}_{environment}/data/synchronizer_config"
		return await self.load_config(config_path)

	async def load_oci_redis_config(self, bundle: str, environment: str) -> Dict:
		full_config = await self.load_oci_synchronizer_config(bundle, environment)
		if "redis" not in full_config['data']:
			raise VaultConnectionError(
				f"Redis configuration not found in oci_{bundle}_{environment}/data/synchronizer_config")
		return full_config['data'].get("redis")

	async def load_oci_api_config(self, bundle: str, environment: str) -> Dict:
		full_config = await self.load_oci_synchronizer_config(bundle, environment)
		if "sync_api" not in full_config['data']:
			raise VaultConnectionError(f"API configuration not found in oci_{bundle}_{environment}/api_handler_config")
		return full_config["data"].get('sync_api')

	@staticmethod
	def load_env_redis_config(bundle: str, environment: str, bundle_region_map: Dict[str, str]) -> Dict:
		region = None

		bundle_base = bundle.split('_')[0] if '_' in bundle else bundle

		if bundle_base in bundle_region_map:
			region = bundle_base
		elif bundle in bundle_region_map:
			region = bundle
		else:
			for region_key, bundle_value in bundle_region_map.items():
				if bundle_value == bundle_base or bundle_value == bundle:
					region = region_key
					break

		if not region:
			if bundle == "default":
				redis_config = {
					"host": os.getenv("REDIS_HOST"),
					"port": int(os.getenv("REDIS_PORT", "6379")),
					"password": os.getenv("REDIS_PASSWORD", "").strip("'\""),
					"db": int(os.getenv("REDIS_DB", "0")),
					"ssl": os.getenv("REDIS_SSL", "false").lower() == "true",
					"ssl_cert_reqs": os.getenv("REDIS_SSL_CERT_REQS", "None")
				}

				if not redis_config["host"]:
					raise ConfigurationError(
						f"Redis host not configured for default bundle. Expected env var: REDIS_HOST")

				return redis_config
			else:
				raise ConfigurationError(
					f"No region found for bundle '{bundle}' in BUNDLE_REGION_MAP. Available bundles: {list(bundle_region_map.keys())}")

		region_upper = region.upper()
		redis_config = {
			"host": os.getenv(f"REDIS_{region_upper}_HOST"),
			"port": int(os.getenv(f"REDIS_{region_upper}_PORT", "6379")),
			"password": os.getenv(f"REDIS_{region_upper}_PASSWORD", "").strip("'\""),
			"db": int(os.getenv(f"REDIS_{region_upper}_DB", "0")),
			"ssl": os.getenv(f"REDIS_{region_upper}_SSL", "false").lower() == "true",
			"ssl_cert_reqs": os.getenv(f"REDIS_{region_upper}_SSL_CERT_REQS", "None")
		}

		if not redis_config["host"]:
			raise ConfigurationError(
				f"Redis host not configured for region {region}. Expected env var: REDIS_{region_upper}_HOST")

		return redis_config

	@staticmethod
	def load_env_api_config(bundle: str, environment: str, bundle_region_map: Dict[str, str]) -> Dict:
		region = None

		bundle_base = bundle.split('_')[0] if '_' in bundle else bundle

		if bundle_base in bundle_region_map:
			region = bundle_base
		elif bundle in bundle_region_map:
			region = bundle
		else:
			for region_key, bundle_value in bundle_region_map.items():
				if bundle_value == bundle_base or bundle_value == bundle:
					region = region_key
					break

		if not region:
			if bundle == "cloud":
				api_config = {
					"url": os.getenv("TargetSystem_REQUEST_RESTAPI_URL"),
					"token": os.getenv("API_ACCESS_TOKEN"),
					"timeout": int(os.getenv("TargetSystem_REQUEST_RESTAPI_TIMEOUT", "180"))
				}

				if not api_config["url"]:
					raise ConfigurationError(
						f"API URL not configured for cloud bundle. Expected env var: TargetSystem_REQUEST_RESTAPI_URL")
				if not api_config["token"]:
					raise ConfigurationError(
						f"API token not configured for cloud bundle. Expected env var: API_ACCESS_TOKEN")

				return api_config
			else:
				raise ConfigurationError(
					f"No region found for bundle '{bundle}' in BUNDLE_REGION_MAP. Available bundles: {list(bundle_region_map.keys())}")

		region_upper = region.upper()
		api_config = {
			"url": os.getenv(f"API_{region_upper}_URL"),
			"token": os.getenv(f"API_{region_upper}_TOKEN"),
			"timeout": int(os.getenv(f"API_{region_upper}_TIMEOUT", "5"))
		}

		if not api_config["url"]:
			raise ConfigurationError(
				f"API URL not configured for region {region}. Expected env var: API_{region_upper}_URL")
		if not api_config["token"]:
			raise ConfigurationError(
				f"API token not configured for region {region}. Expected env var: API_{region_upper}_TOKEN")

		return api_config


async def load_configuration(use_vault: bool = True) -> SyncConfig:
	if use_vault:
		vault_url = os.getenv("VAULT_URL")
		vault_token = os.getenv("VAULT_TOKEN")
		vault_secret_path = os.getenv("VAULT_SECRET_PATH", "sync_runtime_config_dev")
		vault_verify_ssl = os.getenv("VAULT_VERIFY_SSL", "true").lower() == "true"

		if not vault_url or not vault_token:
			raise ConfigurationError("Vault URL and token must be provided for Vault configuration")

		_clear_non_vault_env_vars()

		vault_loader = VaultConfigLoader(vault_url, vault_token, verify_ssl=vault_verify_ssl)

		try:
			vault_config = await vault_loader.load_config(vault_secret_path)

			env_vars = _convert_vault_to_env(vault_config)

			for key, value in env_vars.items():
				os.environ[key] = str(value)

		except VaultConnectionError as e:
			if "status 404" in str(e):
				import logging
				config_correlation_id = f"config_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
				logger = logging.getLogger(f"{__name__}-{config_correlation_id}")
				logger.warning(
					f"Vault secret '{vault_secret_path}' not found (404). Falling back to environment variables.")
			elif "authentication failed" in str(e).lower() or "status 403" in str(e):
				raise ConfigurationError(f"Vault authentication failed. Please check VAULT_TOKEN: {e}")
			else:
				raise ConfigurationError(f"Failed to connect to Vault: {e}")
		except Exception as e:
			raise ConfigurationError(f"Failed to load configuration from Vault: {e}")

	try:
		if use_vault:
			return SyncConfig(vault_url=vault_url, vault_token=vault_token)
		else:
			return SyncConfig()
	except Exception as e:
		raise ConfigurationError(f"Failed to validate configuration: {e}")


def _clear_non_vault_env_vars():
	vault_vars = {'USE_VAULT', 'VAULT_URL', 'VAULT_TOKEN', 'VAULT_SECRET_PATH', 'VAULT_VERIFY_SSL'}

	config_prefixes = [
		'DB_', 'source_', 'TargetSystem_', 'REDIS_', 'TIME_', 'LOG_', 'SYNC_ENGINE_',
		'DATE_TIME_', 'DEFAULT_LAST_', 'START_TIME_', 'IS_DEBUG', 'LOG_LEVEL', 'LOG_FORMAT',
		'CHECK_ROLES_', 'EXECUTE_WITHOUT_', 'REPROCESS_COUNT', 'MAX_ERROR_', 'MAX_IN_PROGRESS_',
		'ENABLE_ERROR_', 'ENABLE_IN_PROGRESS_', 'ENABLE_JSON_ERROR_', 'ROLES_CHECK_',
		'MAX_CONCURRENT_', 'MAX_API_', 'DOMAIN_CHECK_', 'MAX_DOMAINS_', 'ROLE_DOMAIN_',
		'API_', 'HANDLER_', 'DEPLOYMENT_', 'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED'
	]

	individual_vars = [
		'ENVIRONMENT_LIST', 'BUNDLE_REGION_MAP', 'USE_IDENTITY_MANAGER_BUNDLE_ENV',
		'DEFAULT_TEST_BUNDLE', 'DEFAULT_TEST_ENVIRONMENT', 'PREVIOUS_DAYS_CHECK',
		'STORE_IDENTITY_MANAGER_DATA_ENABLE', 'STORE_TargetSystem_DATA_ENABLE', 'JSON_FILE_DB_PATH'
	]

	for env_var in list(os.environ.keys()):
		if env_var in vault_vars:
			continue

		should_clear = any(env_var.startswith(prefix) for prefix in config_prefixes)

		if env_var in individual_vars:
			should_clear = True

		if should_clear:
			del os.environ[env_var]


def _convert_vault_to_env(vault_config: Dict) -> Dict[str, str]:
	env_vars = {}

	if 'data' in vault_config and isinstance(vault_config['data'], dict):
		config_data = vault_config['data']
	else:
		config_data = vault_config

	section_mappings = {
		'disp_db_properties': 'DB_',
		'disp_IDENTITY_MANAGER_properties': 'source_',
		'disp_TargetSystem_properties': 'TargetSystem_',
		'disp_redis_properties': 'REDIS_',
		'disp_time_properties': '',
		'disp_logging_properties': 'LOG_',
		'engine_properties': 'SYNC_ENGINE_',
		'disp_environment': 'ENV_',
		'disp_api_properties': 'API_',
		'disp_deployment_properties': 'DEPLOYMENT_',
		'disp_dev_properties': 'DEV_',
		'disp_regional_api_properties': 'REGIONAL_API_',
		'disp_regional_redis_properties': 'REGIONAL_REDIS_',
	}

	key_mappings = {
		'disp_db_properties': {
			'connection_string': 'DB_CONNECTION_STRING',
			'enable': 'DB_ENABLE',
			'reconnect_count': 'DB_RECONNECT_COUNT',
			'reconnect_sleep_time': 'DB_RECONNECT_SLEEP_TIME',
			'schema': 'DB_SCHEMA',
			'type': 'DB_TYPE',
			'json_file_db_path': 'JSON_FILE_DB_PATH',
			'store_IDENTITY_MANAGER_data_enable': 'STORE_IDENTITY_MANAGER_DATA_ENABLE',
			'store_TargetSystem_data_enable': 'STORE_TargetSystem_DATA_ENABLE',
		},
		'disp_IDENTITY_MANAGER_properties': {
			'file_name_path': 'source_FILE_NAME_PATH',
			'authorization': 'source_REQUEST_RESTAPI_AUTHORIZATION',
			'url': 'source_REQUEST_RESTAPI_URL',
			'username': 'source_REQUEST_RESTAPI_USERNAME',
			'password': 'source_REQUEST_RESTAPI_PASSWORD',
			'timeout': 'source_REQUEST_RESTAPI_TIMEOUT',
			'verify_ssl': 'source_VERIFY_SSL',
			'timezone': 'IDENTITY_MANAGER_TIMEZONE',
		},
		'disp_TargetSystem_properties': {
			'header_value': 'TargetSystem_REQUEST_RESTAPI_HEADER_VALUE',
			'timeout': 'TargetSystem_REQUEST_RESTAPI_TIMEOUT',
			'url': 'TargetSystem_REQUEST_RESTAPI_URL',
			'base_url': 'TargetSystem_REQUEST_RESTAPI_URL',
			'username': 'TargetSystem_REQUEST_RESTAPI_USERNAME',
			'password': 'TargetSystem_REQUEST_RESTAPI_PASSWORD',
			'verify_ssl': 'TargetSystem_VERIFY_SSL',
			'dry_run_mode': 'TargetSystem_DRY_RUN_MODE',
			'use_dynamic_api': 'TargetSystem_USE_DYNAMIC_API',
		},
		'disp_time_properties': {
			'format': 'DATE_TIME_FORMAT',
			'date_time_format': 'DATE_TIME_FORMAT',
			'default_last_time_check': 'DEFAULT_LAST_TIME_CHECK',
			'default_last_check': 'DEFAULT_LAST_TIME_CHECK',
			'start_time_check': 'START_TIME_CHECK',
			'start_time': 'START_TIME_CHECK',
			'IDENTITY_MANAGER_timezone': 'IDENTITY_MANAGER_TIMEZONE',
		},
		'disp_logging_properties': {
			'is_debug': 'IS_DEBUG',
			'level': 'LOG_LEVEL',
			'log_level': 'LOG_LEVEL',
			'format': 'LOG_FORMAT',
			'log_format': 'LOG_FORMAT',
		},
		'disp_engine_properties': {
			'check_roles_exist_in_TargetSystem': 'CHECK_ROLES_EXIST_IN_TargetSystem',
			'execute_without_IDENTITY_MANAGER_read': 'EXECUTE_WITHOUT_IDENTITY_MANAGER_READ',
			'reprocess_count': 'REPROCESS_COUNT',
			'max_error_reprocess_count': 'MAX_ERROR_REPROCESS_COUNT',
			'max_in_progress_reprocess_count': 'MAX_IN_PROGRESS_REPROCESS_COUNT',
			'enable_error_reprocessing': 'ENABLE_ERROR_REPROCESSING',
			'enable_in_progress_reprocessing': 'ENABLE_IN_PROGRESS_REPROCESSING',
			'enable_json_error_reprocessing': 'ENABLE_JSON_ERROR_REPROCESSING',
			'roles_check_file_name': 'ROLES_CHECK_FILE_NAME',
			'roles_check_file_path': 'ROLES_CHECK_FILE_PATH',
			'max_concurrent_files': 'MAX_CONCURRENT_FILES',
			'max_api_calls': 'MAX_API_CALLS',
			'previous_days_check': 'PREVIOUS_DAYS_CHECK',
			'domain_check_enabled': 'DOMAIN_CHECK_ENABLED',
			'max_domains_per_user': 'MAX_DOMAINS_PER_USER',
			'role_domain_logging_enabled': 'ROLE_DOMAIN_LOGGING_ENABLED',
		},
		'disp_environment': {
			'list': 'ENVIRONMENT_LIST',
			'bundle_region_map': 'BUNDLE_REGION_MAP',
			'use_IDENTITY_MANAGER_bundle_env': 'USE_IDENTITY_MANAGER_BUNDLE_ENV',
			'default_test_bundle': 'DEFAULT_TEST_BUNDLE',
			'default_test_environment': 'DEFAULT_TEST_ENVIRONMENT',
		},
		'disp_redis_properties': {
			'host': 'REDIS_HOST',
			'port': 'REDIS_PORT',
			'password': 'REDIS_PASSWORD',
			'db': 'REDIS_DB',
			'ssl': 'REDIS_SSL',
			'use_dynamic_config': 'REDIS_USE_DYNAMIC_CONFIG',
		},
		'disp_api_properties': {
			'access_token': 'API_ACCESS_TOKEN',
			'secret_key': 'API_SECRET_KEY',
			'handler_port': 'HANDLER_API_PORT',
			'handler_deploy_name': 'HANDLER_DEPLOY_NAME',
			'handler_external_url': 'HANDLER_EXTERNAL_URL',
			'handler_ingress_name': 'HANDLER_INGRESS_NAME',
		},
		'disp_deployment_properties': {
			'destination': 'DEPLOYMENT_TARGET',
		},
		'disp_dev_properties': {
			'pythondontwritebytecode': 'PYTHONDONTWRITEBYTECODE',
			'pythonpath': 'PYTHONPATH',
			'pythonunbuffered': 'PYTHONUNBUFFERED',
		},
		'disp_regional_api_properties': {
			'apac_timeout': 'REGIONAL_API_APAC_TIMEOUT',
			'apac_token': 'REGIONAL_API_APAC_TOKEN',
			'apac_url': 'REGIONAL_API_APAC_URL',
			'emea_uk_timeout': 'REGIONAL_API_EMEA_UK_TIMEOUT',
			'emea_uk_token': 'REGIONAL_API_EMEA_UK_TOKEN',
			'emea_uk_url': 'REGIONAL_API_EMEA_UK_URL',
		},
		'disp_regional_redis_properties': {
			'apac_db': 'REGIONAL_REDIS_APAC_DB',
			'apac_host': 'REGIONAL_REDIS_APAC_HOST',
			'apac_password': 'REGIONAL_REDIS_APAC_PASSWORD',
			'apac_port': 'REGIONAL_REDIS_APAC_PORT',
			'apac_ssl': 'REGIONAL_REDIS_APAC_SSL',
			'emea_uk_db': 'REGIONAL_REDIS_EMEA_UK_DB',
			'emea_uk_host': 'REGIONAL_REDIS_EMEA_UK_HOST',
			'emea_uk_password': 'REGIONAL_REDIS_EMEA_UK_PASSWORD',
			'emea_uk_port': 'REGIONAL_REDIS_EMEA_UK_PORT',
			'emea_uk_ssl': 'REGIONAL_REDIS_EMEA_UK_SSL',
		},
	}

	for vault_section, env_prefix in section_mappings.items():
		if vault_section in config_data:
			section_data = config_data[vault_section]
			section_key_mapping = key_mappings.get(vault_section, {})

			for key, value in section_data.items():
				if key in section_key_mapping:
					env_key = section_key_mapping[key]
				else:
					env_key = f"{env_prefix}{key.upper()}"

				env_vars[env_key] = str(value)

	if 'disp_environment' in config_data:
		env_vars['ENVIRONMENT_LIST'] = config_data['disp_environment'].get('list', '')

	if 'disp_bundle_region_map' in config_data:
		import json
		env_vars['BUNDLE_REGION_MAP'] = json.dumps(config_data['disp_bundle_region_map'])

	return env_vars


config: Optional[SyncConfig] = None


async def get_config(reload: bool = False) -> SyncConfig:
	global config

	if config is None or reload:
		from dotenv import load_dotenv
		load_dotenv()

		use_vault = os.getenv("USE_VAULT", "true").lower() == "true"
		config = await load_configuration(use_vault=use_vault)

	return config
