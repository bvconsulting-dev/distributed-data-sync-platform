import asyncio
from typing import Optional, Dict, Any
from functools import wraps


class AccessSyncEngineException(Exception):

	def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
		self.message = message
		self.details = details or {}
		super().__init__(self.message)


class IdentityManagerConnectionError(AccessSyncEngineException):
	pass


class IdentityManagerAuthenticationError(AccessSyncEngineException):
	pass


class IdentityManagerGraphQLError(AccessSyncEngineException):
	pass


class TargetSystemApiError(AccessSyncEngineException):
	pass


class TargetSystemConnectionError(AccessSyncEngineException):
	pass


class TargetSystemAuthenticationError(AccessSyncEngineException):
	pass


class DataValidationError(AccessSyncEngineException):
	pass


class FileProcessingError(AccessSyncEngineException):
	pass


class SyncFileNotFoundError(AccessSyncEngineException):
	pass


class FilePermissionError(AccessSyncEngineException):
	pass


class ComparisonError(AccessSyncEngineException):
	pass


class ConfigurationError(AccessSyncEngineException):
	pass


class VaultConnectionError(AccessSyncEngineException):
	pass


class DatabaseError(AccessSyncEngineException):
	pass


class ReprocessingError(AccessSyncEngineException):
	pass


class TemplateError(AccessSyncEngineException):
	pass


class EngineError(AccessSyncEngineException):
	pass


def handle_api_errors(max_retries: int = 3, backoff_factor: float = 2.0):
	def decorator(func):
		@wraps(func)
		async def wrapper(*args, **kwargs):
			retry_count = 0

			while retry_count < max_retries:
				try:
					return await func(*args, **kwargs)
				except (IdentityManagerConnectionError, TargetSystemConnectionError) as e:
					retry_count += 1
					if retry_count >= max_retries:
						raise e

					wait_time = backoff_factor ** retry_count
					await asyncio.sleep(wait_time)
				except (IdentityManagerAuthenticationError, TargetSystemAuthenticationError) as e:

					raise e
				except asyncio.CancelledError as e:

					raise IdentityManagerConnectionError("Request was cancelled (timeout or external cancellation)")

		return wrapper

	return decorator


def handle_file_errors(func):
	@wraps(func)
	async def wrapper(*args, **kwargs):
		try:
			return await func(*args, **kwargs)
		except FileNotFoundError as e:
			raise SyncFileNotFoundError(f"File not found: {e}")
		except PermissionError as e:
			raise FilePermissionError(f"Permission denied: {e}")
		except OSError as e:
			raise FileProcessingError(f"File operation failed: {e}")

	return wrapper
