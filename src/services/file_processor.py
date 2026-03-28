
import aiofiles
import asyncio
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from ..models.processing import (
	FileStatus,
	FileStatusRecord,
	FileStatusData,
	ReprocessFile,
	ReprocessData,
	MissingRolesData,
	ProcessingResult,
	ParsedData,
	UserDisableInfo
)
from ..models.IDENTITY_MANAGER import IdentityUser
from ..exceptions.base import (
	FileProcessingError,
	SyncFileNotFoundError,
	FilePermissionError,
	handle_file_errors
)
from ..config.settings import DatabaseConfig


def _generate_filename(timestamp: Optional[datetime] = None) -> str:

	if timestamp is None:
		timestamp = datetime.utcnow()

	formatted = timestamp.strftime("%Y%m%dT%H%M%SZ")
	return f"{formatted}.json"


class AsyncFileProcessor:

	def __init__(self, config: DatabaseConfig):
		self.data_path = Path(config.json_file_db_path)
		self.roles_check_file_path = Path(config.json_file_db_path)
		self.ensure_directories()

	def ensure_directories(self):

		self.data_path.mkdir(parents=True, exist_ok=True)
		self.roles_check_file_path.mkdir(parents=True, exist_ok=True)

	def _get_daily_folder(self, timestamp: Optional[datetime] = None) -> Path:

		if timestamp is None:
			timestamp = datetime.utcnow()

		folder_name = timestamp.strftime("%Y-%m-%d")
		return self.data_path / folder_name

	def _get_status_file_path(self, timestamp: Optional[datetime] = None) -> Path:

		if timestamp is None:
			timestamp = datetime.utcnow()

		filename = f"{timestamp.strftime('%Y-%m-%d')}.json"
		daily_folder = self._get_daily_folder(timestamp)
		return daily_folder / filename

	@handle_file_errors
	async def save_user_data(self, users: List[IdentityUser], timestamp: Optional[datetime] = None) -> str:

		if timestamp is None:
			timestamp = datetime.utcnow()

		filename = _generate_filename(timestamp)
		daily_folder = self._get_daily_folder(timestamp)
		file_path = daily_folder / filename

		daily_folder.mkdir(parents=True, exist_ok=True)

		data = [user.dict() for user in users]

		async with aiofiles.open(file_path, 'w') as f:
			await f.write(json.dumps(data, indent=2, default=str))

		return str(file_path)

	@handle_file_errors
	async def save_IDENTITY_MANAGER_response(self, response_data, timestamp: Optional[datetime] = None) -> str:

		if timestamp is None:
			timestamp = datetime.utcnow()

		filename = _generate_filename(timestamp)
		daily_folder = self._get_daily_folder(timestamp)
		file_path = daily_folder / filename

		daily_folder.mkdir(parents=True, exist_ok=True)

		formatted_data = self._format_IDENTITY_MANAGER_data_for_reference(response_data)

		async with aiofiles.open(file_path, 'w') as f:
			await f.write(json.dumps(formatted_data, indent=4, ensure_ascii=False, sort_keys=True, default=str))

		return str(file_path)

	def _format_IDENTITY_MANAGER_data_for_reference(self, response_data) -> Dict[str, Any]:

		if isinstance(response_data, list):
			users_data = response_data
			total_count = len(response_data)

		elif hasattr(response_data, 'users') and hasattr(response_data, 'total'):
			users_data = response_data.users
			total_count = response_data.total
		else:

			if isinstance(response_data, dict) and 'data' in response_data:
				return response_data
			users_data = response_data if isinstance(response_data, list) else [response_data]
			total_count = len(users_data)

		formatted_users = []
		for user in users_data:

			if hasattr(user, 'dict'):
				user_dict = user.dict()
			else:
				user_dict = user

			formatted_user = self._convert_to_camel_case_format(user_dict)
			formatted_users.append(formatted_user)

		return {
			"data": {
				"modifiedUsers": {
					"users": formatted_users,
					"total": total_count
				}
			}
		}

	def _convert_to_camel_case_format(self, data) -> Any:

		if isinstance(data, dict):
			converted = {}
			for key, value in data.items():

				camel_key = self._snake_to_camel_case(key)
				converted[camel_key] = self._convert_to_camel_case_format(value)
			return converted
		elif isinstance(data, list):
			return [self._convert_to_camel_case_format(item) for item in data]
		else:
			return data

	def _snake_to_camel_case(self, snake_str: str) -> str:

		field_mappings = {
			'user_detail': 'userDetail',
			'first_name': 'firstName',
			'last_name': 'lastName',
			'application_instance': 'applicationInstance',
			'application_hierarchies': 'applicationHierarchies',
			'application_hierarchy': 'applicationHierarchy',
			'attribute_values': 'attributeValues',
			'value_name': 'valueName',
			'parent_id': 'parentId'
		}

		if snake_str in field_mappings:
			return field_mappings[snake_str]

		components = snake_str.split('_')
		return components[0] + ''.join(word.capitalize() for word in components[1:])

	@handle_file_errors
	async def load_json_file(self, file_path: str) -> Dict[str, Any]:

		path = Path(file_path)
		if not path.exists():
			raise SyncFileNotFoundError(f"File not found: {file_path}")

		async with aiofiles.open(path, 'r') as f:
			content = await f.read()
			return json.loads(content)

	@handle_file_errors
	async def save_json_file(self, file_path: str, data: Dict[str, Any]) -> None:

		path = Path(file_path)
		path.parent.mkdir(parents=True, exist_ok=True)

		async with aiofiles.open(path, 'w') as f:
			await f.write(json.dumps(data, indent=2, default=str))

	async def check_file_empty_response(self, file_path: str) -> bool:

		try:
			data = await self.load_json_file(file_path)

			if (data.get("data", {}).get("modifiedUsers", {}).get("users") == [] and
					data.get("data", {}).get("modifiedUsers", {}).get("total") == 0):
				return True

			return False
		except Exception:
			return False

	async def check_user_for_disable(self, user_data: Dict[str, Any]) -> bool:

		return user_data.get("authorizations", []) == []

class FileStatusManager:

	def __init__(self, file_processor: AsyncFileProcessor):
		self.file_processor = file_processor

	async def load_status_file(self, timestamp: Optional[datetime] = None) -> FileStatusData:

		status_file_path = self.file_processor._get_status_file_path(timestamp)

		try:
			data = await self.file_processor.load_json_file(str(status_file_path))
			status_data = FileStatusData()

			for record_id, record_data in data.items():
				if record_id != "records":
					record = FileStatusRecord(
						json_file_path=record_data["json_file_path"],
						status=FileStatus(record_data["status"]),
 					start_time=datetime.fromisoformat(record_data["start_time"].replace('Z', '+00:00')).replace(tzinfo=None),
 					end_time=datetime.fromisoformat(
 						record_data["end_time"].replace('Z', '+00:00')).replace(tzinfo=None) if record_data.get("end_time") else None,
						error_message=record_data.get("error_message"),
						reprocess_count=record_data.get("reprocess_count", 0)
					)
					status_data.add_record(record_id, record)

			return status_data
		except (FileNotFoundError, SyncFileNotFoundError):

			return FileStatusData()

	async def save_status_file(self, status_data: FileStatusData, timestamp: Optional[datetime] = None) -> None:

		status_file_path = self.file_processor._get_status_file_path(timestamp)

		data = {}
		for record_id, record in status_data.records.items():
			data[record_id] = {
				"json_file_path": record.json_file_path,
				"status": record.status.value,
				"start_time": record.start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
				"end_time": record.end_time.strftime("%Y-%m-%dT%H:%M:%SZ") if record.end_time else None,
				"error_message": record.error_message,
				"reprocess_count": record.reprocess_count
			}

		await self.file_processor.save_json_file(str(status_file_path), data)

	async def add_new_file_record(self, file_path: str, timestamp: Optional[datetime] = None) -> str:

		if timestamp is None:
			timestamp = datetime.utcnow()

		status_data = await self.load_status_file(timestamp)

		record_id = str(len(status_data.records) + 1)

		record = FileStatusRecord(
			json_file_path=file_path,
			status=FileStatus.NEW,
			start_time=timestamp
		)

		status_data.add_record(record_id, record)
		await self.save_status_file(status_data, timestamp)

		return record_id

	async def find_record_across_status_files(self, file_path: str, days_to_check: int = 30) -> tuple[Optional[str], Optional[datetime]]:

		current_date = datetime.utcnow()

		try:
			status_data = await self.load_status_file(current_date)
			for record_id, record in status_data.records.items():
				if record.json_file_path == file_path:
					return record_id, current_date
		except Exception:
			pass

		for days_back in range(1, days_to_check + 1):
			try:
				check_date = current_date - timedelta(days=days_back)
				status_data = await self.load_status_file(check_date)
				for record_id, record in status_data.records.items():
					if record.json_file_path == file_path:
						return record_id, check_date
			except Exception:
				continue

		return None, None

	async def update_file_status(self, record_id: str, status: FileStatus,
								 error_message: Optional[str] = None,
								 timestamp: Optional[datetime] = None,
								 increment_reprocess_count: bool = False) -> None:

		if timestamp is None:
			timestamp = datetime.utcnow()

		status_data = await self.load_status_file(timestamp)
		status_data.update_status(record_id, status, error_message, increment_reprocess_count)
		await self.save_status_file(status_data, timestamp)

	async def update_file_status_in_original_file(self, file_path: str, status: FileStatus,
												  error_message: Optional[str] = None,
												  days_to_check: int = 30) -> bool:

		updated_any = False
		current_date = datetime.utcnow()

		try:
			status_data = await self.load_status_file(current_date)
			for record_id, record in status_data.records.items():
				if record.json_file_path == file_path:
					await self.update_file_status(record_id, status, error_message, current_date)
					updated_any = True
		except Exception:
			pass

		for days_back in range(1, days_to_check + 1):
			try:
				check_date = current_date - timedelta(days=days_back)
				status_data = await self.load_status_file(check_date)
				for record_id, record in status_data.records.items():
					if record.json_file_path == file_path:
						await self.update_file_status(record_id, status, error_message, check_date)
						updated_any = True
			except Exception:
				continue

		return updated_any

class ReprocessFileManager:

	def __init__(self, file_processor: AsyncFileProcessor):
		self.file_processor = file_processor

	def _get_reprocess_file_path(self, original_file_path: str) -> str:

		return f"{original_file_path}_error"

	async def load_reprocess_file(self, original_file_path: str, increment_counter: bool = True, max_reprocess_count: int = 3) -> ReprocessFile:

		reprocess_path = self._get_reprocess_file_path(original_file_path)

		try:
			data = await self.file_processor.load_json_file(reprocess_path)
			reprocess_file = ReprocessFile()

			is_new_format = False
			for key, value in data.items():
				if key != "reprocess_count" and isinstance(value, dict):
					for sub_key, sub_value in value.items():
						if sub_key != "request_type" and isinstance(sub_value, dict):

							if "user_id" in sub_value and "first_name" in sub_value:
								is_new_format = True
								break

			if is_new_format:
				for bundle_env, bundle_data in data.items():
					if bundle_env != "reprocess_count":
						bundle_level_request_type = bundle_data.get("request_type", "unknown")
						for user_id, user_data in bundle_data.items():
							if user_id != "request_type":
								user_request_type = user_data.get("request_type", bundle_level_request_type)
								reprocess_obj = ReprocessData(
									user_id=user_data.get("user_id", user_id),
									bundle=user_data.get("bundle", ""),
									env=user_data.get("env", ""),
									region=user_data.get("region", ""),
									json_data=user_data.get("json_data", {}),
									request_type=user_request_type,
									first_name=user_data.get("first_name", ""),
									last_name=user_data.get("last_name", "")
								)
								reprocess_file.add_user_data_without_counter(user_id, bundle_env, reprocess_obj)
			else:
				for user_id, user_data in data.items():
					if user_id != "reprocess_count":
						for bundle_env, reprocess_data in user_data.items():
							json_data = reprocess_data.get("json_data", {})
							request_type = reprocess_data.get("request_type", "unknown")
							reprocess_obj = ReprocessData(
								user_id=json_data.get("user_id", user_id),
								bundle=json_data.get("bundle", ""),
								env=json_data.get("env", ""),
								region=reprocess_data.get("region", ""),
								json_data=json_data,
								request_type=request_type,
								first_name=json_data.get("first_name", ""),
								last_name=json_data.get("last_name", "")
							)
							reprocess_file.add_user_data_without_counter(user_id, bundle_env, reprocess_obj)

			current_count = int(data.get("reprocess_count", 0))

			if increment_counter and current_count < max_reprocess_count:
				reprocess_file.reprocess_count = current_count + 1

				await self.save_reprocess_file(reprocess_file, original_file_path)
			else:
				reprocess_file.reprocess_count = current_count

			return reprocess_file

		except (FileNotFoundError, SyncFileNotFoundError):
			return ReprocessFile()

	async def save_reprocess_file(self, reprocess_file: ReprocessFile, original_file_path: str) -> None:

		reprocess_path = self._get_reprocess_file_path(original_file_path)

		data = {}
		for bundle_env, users_data in reprocess_file.data.items():
			data[bundle_env] = {}

			for user_id, reprocess_data in users_data.items():
				user_data = {
					"user_id": reprocess_data.user_id,
					"first_name": reprocess_data.first_name,
					"last_name": reprocess_data.last_name,
					"bundle": reprocess_data.bundle,
					"env": reprocess_data.env,
					"region": reprocess_data.region,
					"json_data": reprocess_data.json_data,
					"request_type": reprocess_data.request_type
				}
				data[bundle_env][user_id] = user_data

		data["reprocess_count"] = reprocess_file.reprocess_count

		if not reprocess_file.data:

			reprocess_path_obj = Path(reprocess_path)
			if reprocess_path_obj.exists():
				reprocess_path_obj.unlink()
			return

		await self.file_processor.save_json_file(reprocess_path, data)

	async def add_reprocess_data(self, original_file_path: str, user_id: str,
								 bundle_env: str, reprocess_data: ReprocessData) -> None:

		reprocess_file = await self.load_reprocess_file(original_file_path)
		reprocess_file.add_user_data(user_id, bundle_env, reprocess_data)
		await self.save_reprocess_file(reprocess_file, original_file_path)

	async def remove_reprocess_data(self, original_file_path: str, user_id: str,
									bundle_env: Optional[str] = None) -> None:

		reprocess_file = await self.load_reprocess_file(original_file_path)
		reprocess_file.remove_user_data(user_id, bundle_env)
		await self.save_reprocess_file(reprocess_file, original_file_path)

class MissingRolesManager:

	def __init__(self, file_processor: AsyncFileProcessor, roles_check_file_name: str = "_missing_roles"):
		self.file_processor = file_processor
		self.roles_check_file_name = roles_check_file_name

	def _get_missing_roles_file_path(self, region: str) -> str:

		filename = f"{region}{self.roles_check_file_name}.json"
		return str(self.file_processor.roles_check_file_path / filename)

	async def load_missing_roles_file(self, region: str) -> MissingRolesData:

		file_path = self._get_missing_roles_file_path(region)

		try:
			data = await self.file_processor.load_json_file(file_path)
			missing_roles = MissingRolesData()
			missing_roles.regions = data
			return missing_roles
		except FileNotFoundError:
			return MissingRolesData()

	async def save_missing_roles_file(self, missing_roles: MissingRolesData, region: str) -> None:

		file_path = self._get_missing_roles_file_path(region)

		if not missing_roles.regions:

			file_path_obj = Path(file_path)
			if file_path_obj.exists():
				file_path_obj.unlink()
			return

		await self.file_processor.save_json_file(file_path, missing_roles.regions)

	async def add_missing_roles(self, region: str, bundle: str, env: str,
								domain: str, roles: List[str]) -> None:

		missing_roles = await self.load_missing_roles_file(region)
		missing_roles.add_missing_roles(region, bundle, env, domain, roles)
		await self.save_missing_roles_file(missing_roles, region)

	async def remove_missing_roles(self, region: str, bundle: str, env: str,
								   domain: str, roles: List[str]) -> None:

		missing_roles = await self.load_missing_roles_file(region)
		missing_roles.remove_roles(region, bundle, env, domain, roles)
		await self.save_missing_roles_file(missing_roles, region)

class AsyncFileService:

	def __init__(self, config: DatabaseConfig, roles_check_file_name: str = "_missing_roles"):
		self.file_processor = AsyncFileProcessor(config)
		self.status_manager = FileStatusManager(self.file_processor)
		self.reprocess_manager = ReprocessFileManager(self.file_processor)
		self.missing_roles_manager = MissingRolesManager(self.file_processor, roles_check_file_name)

	async def process_files_batch(self, file_paths: List[str]) -> List[ProcessingResult]:

		tasks = [self.process_single_file(path) for path in file_paths]
		return await asyncio.gather(*tasks, return_exceptions=True)

	async def process_single_file(self, file_path: str) -> ProcessingResult:

		try:

			record_id = await self.status_manager.add_new_file_record(file_path)

			await self.status_manager.update_file_status(record_id, FileStatus.IN_PROGRESS)

			if await self.file_processor.check_file_empty_response(file_path):
				await self.status_manager.update_file_status(record_id, FileStatus.EMPTY)
				return ProcessingResult(
					success=True,
					message="File contains empty response",
					data={"status": "empty"}
				)

			data = await self.file_processor.load_json_file(file_path)

			await self.status_manager.update_file_status(record_id, FileStatus.DONE)

			return ProcessingResult(
				success=True,
				message="File processed successfully",
				data={"record_id": record_id}
			)

		except Exception as e:

			if 'record_id' in locals():
				await self.status_manager.update_file_status(
					record_id, FileStatus.ERROR, str(e)
				)

			return ProcessingResult(
				success=False,
				message="File processing failed",
				error=str(e)
			)
