import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.services.comparison import ComparisonOrchestrator, DataParser
from src.services.file_processor import AsyncFileService, FileStatusManager
from src.clients.source_manager import IdentityManagerService
from src.clients.destination_system import TargetSystemService, DynamicTargetSystemService
from src.clients.redis import DynamicRedisService
from src.clients.redis_readonly import ReadOnlyRedisService
from src.config.settings import SyncConfig, VaultConfigLoader
from src.exceptions.base import EngineError, FileProcessingError, TargetSystemApiError
from src.models.processing import (
    ProcessingResult, ComparisonResult, ParsedData, ParsedUser, FileStatus,
    UserDisableInfo, FileStatusRecord
)
from src.models.TargetSystem import TargetSystemUser, TargetSystemUserRequest, TargetSystemAssignmentRequest, TargetSystemDefaultRoleRequest, TargetSystemUserAssignments
from src.utils.bundle_env_extractor import BundleEnvironmentExtractor


class RoleValidator:

    def __init__(self, redis_service: ReadOnlyRedisService, config=None, correlation_id: str = None):
        self.redis_service = redis_service
        self.config = config
        self.correlation_id = correlation_id
        self.logger = logging.getLogger(f"{__name__}.RoleValidator")

    async def validate_roles_for_domain(self, roles: List[str], domain: str, bundle: str, env: str, region_name: str) -> \
            Dict[str, List[str]]:
        correlation_context = f" (correlation_id: {self.correlation_id})" if self.correlation_id else ""
        self.logger.info(
            f"Validating roles {roles} for domain {domain} in {bundle}/{env} with region {region_name}{correlation_context}")

        try:
            cache_key = f"{region_name}_{bundle}_{env}"
            cached_data = await self.redis_service.get_synchronizer_data(cache_key, bundle, env)

            if cached_data:
                try:
                    domains_roles = json.loads(cached_data)
                    domain_roles = domains_roles.get('domains').get(domain, [])

                    valid_roles = []
                    invalid_roles = []

                    for role in roles:
                        if role in domain_roles:
                            valid_roles.append(role)
                        else:
                            invalid_roles.append(role)

                    self.logger.info(
                        f"Validation result - Valid: {valid_roles}, Invalid: {invalid_roles}{correlation_context}")
                    return {
                        'valid_roles': valid_roles,
                        'invalid_roles': invalid_roles
                    }

                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse cached domain roles data: {e}{correlation_context}")

            else:
                self.logger.warning(f"No cached domain roles found for {bundle}/{env}{correlation_context}")

        except Exception as e:
            self.logger.error(f"Error validating roles: {e}{correlation_context}")

        return {
            'valid_roles': [],
            'invalid_roles': roles
        }

    async def validate_role_domain_prefix(self, roles: List[str], selected_domain: str) -> Dict[str, List[str]]:
        if not self.config or not self.config.engine.role_domain_logging_enabled:
            return {'domain_mismatch_roles': [], 'public_roles': []}

        correlation_context = f" (correlation_id: {self.correlation_id})" if self.correlation_id else ""
        domain_mismatch_roles = []
        public_roles = []

        for role in roles:
            if "." in role:
                role_domain = role.split(".")[0]

                if role_domain != selected_domain:
                    domain_mismatch_roles.append(role)
                    self.logger.info(
                        f"Role '{role}' domain '{role_domain}' does not match selected domain '{selected_domain}'{correlation_context}")
            else:
                public_roles.append(role)
                self.logger.info(f"Role '{role}' has no domain prefix - logging as public role{correlation_context}")

        return {
            'domain_mismatch_roles': domain_mismatch_roles,
            'public_roles': public_roles
        }

    def log_role_domain_validation_results(self, user_login: str, validation_results: Dict[str, List[str]],
                                           selected_domain: str):
        if not self.config or not self.config.engine.role_domain_logging_enabled:
            return

        correlation_context = f" (correlation_id: {self.correlation_id})" if self.correlation_id else ""
        domain_mismatch_roles = validation_results.get('domain_mismatch_roles', [])
        public_roles = validation_results.get('public_roles', [])

        if domain_mismatch_roles or public_roles:
            self.logger.warning(
                f"Role domain validation results for user '{user_login}' with selected domain '{selected_domain}'{correlation_context}:")

            if domain_mismatch_roles:
                self.logger.warning(
                    f"  Roles not matching selected domain: {domain_mismatch_roles}{correlation_context}")

            if public_roles:
                self.logger.warning(f"  Public roles (no domain prefix): {public_roles}{correlation_context}")

    async def store_invalid_roles(self, invalid_roles_by_domain: Dict[str, List[str]], region: str, file_path: str):
        if not invalid_roles_by_domain:
            return

        sanitized_region = region.replace('/', '_').replace('\\', '_')

        missing_roles_filename = f"{sanitized_region}_missing_roles.json"
        missing_roles_path = Path("data") / missing_roles_filename

        existing_data = {}
        if missing_roles_path.exists():
            try:
                with open(missing_roles_path, 'r') as f:
                    existing_data = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load existing missing roles file: {e}")

        for domain, roles in invalid_roles_by_domain.items():
            if domain not in existing_data:
                existing_data[domain] = []

            for role in roles:
                if role not in existing_data[domain]:
                    existing_data[domain].append(role)

        try:
            missing_roles_path.parent.mkdir(parents=True, exist_ok=True)
            with open(missing_roles_path, 'w') as f:
                json.dump(existing_data, f, indent=2)

            self.logger.info(f"Stored invalid roles in {missing_roles_path}: {invalid_roles_by_domain}")

        except Exception as e:
            self.logger.error(f"Failed to store invalid roles: {e}")


class AccessSyncEngine:

    def __init__(self, config: SyncConfig):
        self.config = config
        self.correlation_id = config.correlation_id or f"sync_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
        self._shutdown_event = asyncio.Event()
        self._processing_semaphore = asyncio.Semaphore(config.engine.max_concurrent_files or 10)

        self.IDENTITY_MANAGER_service = IdentityManagerService(config.IDENTITY_MANAGER)

        vault_loader = None
        if config.vault_url and config.vault_token:
            vault_verify_ssl = os.getenv("VAULT_VERIFY_SSL", "true").lower() == "true"
            vault_loader = VaultConfigLoader(config.vault_url, config.vault_token, verify_ssl=vault_verify_ssl)

        self.TargetSystem_service = DynamicTargetSystemService(
            base_config=config.TargetSystem,
            vault_loader=vault_loader,
            bundle_region_map=config.bundle_region_map
        )

        self.dynamic_TargetSystem_service = self.TargetSystem_service

        self.redis_service = ReadOnlyRedisService(
            base_config=config.redis,
            vault_loader=vault_loader,
            bundle_region_map=config.bundle_region_map,
            check_roles_exist_in_TargetSystem=config.engine.check_roles_exist_in_TargetSystem,
            correlation_id=self.correlation_id
        )

        self.role_validator = RoleValidator(self.redis_service, config, self.correlation_id)

        self.file_service = AsyncFileService(config.database)
        self.comparison_orchestrator = ComparisonOrchestrator(self.correlation_id, config)
        self.data_parser = DataParser(self.correlation_id, config)

        self.bundle_env_extractor = BundleEnvironmentExtractor()

        self.status_manager = FileStatusManager(self.file_service.file_processor)

        self.processing_results = {
            "successful_files": [],
            "failed_files": [],
            "users_processed": 0,
            "users_disabled": [],
            "errors": []
        }

        if config.engine.check_roles_exist_in_TargetSystem:
            self.logger.info("Role validation is ENABLED - roles will be validated against TargetSystem before operations")
        else:
            self.logger.info("Role validation is DISABLED - all roles will be processed without validation")

    async def execute_sync_engine(self,
                                      correlation_id: str = None,
                                      read_from_IDENTITY_MANAGER: bool = None,
                                      last_check: str = None) -> Dict[str, Any]:
        self.correlation_id = correlation_id or f"sync_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        read_from_IDENTITY_MANAGER = self.config.engine.execute_without_IDENTITY_MANAGER_read

        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
        self.logger.info("Starting Access Sync Engine.")
        self.logger.info(
            f"EXECUTE WITH source UM READ configuration: {self.config.engine.execute_without_IDENTITY_MANAGER_read}")
        self.logger.info(f"IdentityManager operations will be: {'ENABLED' if read_from_IDENTITY_MANAGER else 'DISABLED'}")
        self.logger.debug(
            f"Engine execution parameters: correlation_id={self.correlation_id}, read_from_IDENTITY_MANAGER={read_from_IDENTITY_MANAGER}, last_check={last_check}")

        try:
            self.logger.debug("Step 1: Read IdentityManager data and store file with status new")
            await self._initialize()
            files_to_process = []
            if read_from_IDENTITY_MANAGER:
                self.logger.debug("Step 1: Attempting to retrieve data from IdentityManager")
                try:
                    files_to_process = await self._get_data_from_IDENTITY_MANAGER(last_check)
                    self.logger.debug(
                        f"Step 1: Successfully retrieved {len(files_to_process)} files from IdentityManager and stored with NEW status")
                except Exception as e:
                    self.logger.error(f"IdentityManager is not accessible or has issues: {e}")
                    self.logger.debug(f"Step 1: IdentityManager error details: {str(e)}")
                    self.processing_results["errors"].append(f"IdentityManager error: {e}")
                    self.logger.info("Continuing with existing files in database/file system")
                    files_to_process = []
            self.logger.debug("Step 1: IdentityManager data retrieval and storage completed")

            self.logger.debug("Step 2: Check files status - error")
            await self._check_error_status_files()
            self.logger.debug("Step 2: Error status check completed")

            self.logger.debug("Step 3: Check file status - in_progress")
            await self._check_in_progress_status_files()
            self.logger.debug("Step 3: In-progress status check completed")

            self.logger.debug("Step 4: Process all files with status new")

            all_new_files = await self._get_files_with_new_status()

            all_files_to_process = files_to_process + [f for f in all_new_files if f not in files_to_process]

            self.logger.info(f"Total files to process with NEW status: {len(all_files_to_process)}")

            self.logger.debug("Step 4a: Reprocessing failed steps (json_error files)")
            await self._reprocess_failed_steps()
            self.logger.debug("Step 4a: Failed steps reprocessing completed")

            self.logger.debug("Step 4b: Processing all files with status NEW")
            await self._process_files_with_timeout(all_files_to_process)
            self.logger.debug("Step 4b: NEW files processing completed")

            self.logger.debug("Step 4: All NEW files processing completed")

            self.logger.debug("Generating execution summary")
            summary = self._generate_execution_summary()
            self.logger.debug(f"Execution summary generated: {summary}")
            self.logger.info("Access Sync Engine execution completed successfully")
            return summary

        except asyncio.CancelledError:
            self.logger.info("Access Sync Engine execution was cancelled")
            self.logger.debug("Engine execution cancelled by user or timeout")
            raise
        except Exception as e:
            self.logger.error(f"Access Sync Engine execution failed: {e}")
            self.logger.debug(f"Engine execution error details: {str(e)}", exc_info=True)
            raise EngineError(f"Engine execution failed: {e}")

    async def _process_files_with_timeout(self, files_to_process: List[str], timeout: int = 3600):
        self.logger.debug(f"Starting file processing with timeout: {timeout} seconds")
        self.logger.debug(f"Files to process: {files_to_process}")

        if not files_to_process:
            self.logger.debug("No files to process, skipping file processing phase")
            return

        try:
            self.logger.debug(f"Setting up timeout context for {timeout} seconds")
            async with asyncio.timeout(timeout):
                self.logger.info(f"Processing {len(files_to_process)} files sequentially in chronological order")
                self.logger.debug("Starting sequential file processing loop")

                start_time = datetime.utcnow()
                for i, file_path in enumerate(files_to_process, 1):
                    file_start_time = datetime.utcnow()
                    self.logger.info(f"Processing file {i}/{len(files_to_process)}: {file_path}")
                    self.logger.debug(f"File {i}: Starting processing at {file_start_time}")

                    await self._process_single_file_safe(file_path)

                    file_end_time = datetime.utcnow()
                    file_duration = (file_end_time - file_start_time).total_seconds()
                    self.logger.debug(f"File {i}: Completed processing in {file_duration:.2f} seconds")

                total_duration = (datetime.utcnow() - start_time).total_seconds()
                self.logger.debug(f"All files processed successfully in {total_duration:.2f} seconds")

        except asyncio.TimeoutError:
            self.logger.error(f"File processing timed out after {timeout} seconds")
            self.logger.debug(
                f"Timeout occurred during file processing. Processed files: {len(self.processing_results['successful_files'])}, Failed files: {len(self.processing_results['failed_files'])}")
            self.processing_results["errors"].append(f"Processing timed out after {timeout} seconds")
        except Exception as e:
            self.logger.error(f"Error in file processing: {e}")
            self.logger.debug(f"File processing error details: {str(e)}", exc_info=True)
            self.processing_results["errors"].append(str(e))

    async def _process_single_file_safe(self, file_path: str):
        self.logger.debug(f"Acquiring semaphore for file processing: {file_path}")
        async with self._processing_semaphore:
            self.logger.debug(f"Semaphore acquired, starting safe processing of: {file_path}")
            try:
                await self.process_file(file_path)
                self.processing_results["successful_files"].append(file_path)
                self.logger.debug(f"File processed successfully and added to successful_files: {file_path}")
            except Exception as e:
                self.logger.error(f"Failed to process file {file_path}: {e}")
                self.logger.debug(f"File processing error details for {file_path}: {str(e)}", exc_info=True)
                self.processing_results["failed_files"].append(file_path)
                self.processing_results["errors"].append(str(e))
                self.logger.debug(f"File added to failed_files list: {file_path}")
        self.logger.debug(f"Semaphore released for file: {file_path}")

    async def process_file(self, file_path: str, timeout: int = 1800) -> ProcessingResult:
        self.logger.info(f"Processing file: {file_path}")
        self.logger.debug(f"File processing parameters: timeout={timeout}s")
        record_id = None
        is_old_file = False
        original_timestamp = None

        self._current_file_path = file_path
        self.logger.debug(f"Set current file path for reprocess data storage: {file_path}")

        try:
            self.logger.debug(f"Setting up timeout context for file processing: {timeout}s")
            async with asyncio.timeout(timeout):
                self.logger.debug("Step 1: Starting file information extraction and record management")
                file_name = Path(file_path).name
                self.logger.debug(f"Extracted file name: {file_name}")

                self.logger.debug(
                    f"Searching for existing record across status files (checking {self.config.engine.previous_days_check} days)")
                record_id, original_timestamp = await self.status_manager.find_record_across_status_files(
                    file_path, days_to_check=self.config.engine.previous_days_check
                )
                self.logger.debug(
                    f"Record search result: record_id={record_id}, original_timestamp={original_timestamp}")

                if record_id and original_timestamp:
                    self.logger.info(
                        f"Found existing file record with ID: {record_id} in status file from {original_timestamp.strftime('%Y-%m-%d')}")
                    is_old_file = original_timestamp.date() != datetime.utcnow().date()
                    self.logger.debug(
                        f"File classification: is_old_file={is_old_file} (original_date={original_timestamp.date()}, current_date={datetime.utcnow().date()})")
                else:
                    self.logger.debug("No existing record found, creating new record")
                    self.logger.debug("Attempting to extract date from filename")
                    file_date = self._extract_date_from_filename(file_path)
                    self.logger.debug(f"Date extraction result: {file_date}")

                    if file_date:
                        record_date = file_date
                        is_old_file = file_date.date() != datetime.utcnow().date()
                        self.logger.info(
                            f"Extracted date {file_date.strftime('%Y-%m-%d')} from filename, using corresponding status file")
                        self.logger.debug(f"Using extracted date: record_date={record_date}, is_old_file={is_old_file}")
                    else:
                        record_date = datetime.utcnow()
                        is_old_file = False
                        self.logger.info(f"Using current date for status file")
                        self.logger.debug(f"Using current date: record_date={record_date}, is_old_file={is_old_file}")

                    self.logger.debug(f"Creating new file record with date: {record_date}")
                    record_id = await self.status_manager.add_new_file_record(file_path, record_date)
                    original_timestamp = record_date
                    self.logger.info(
                        f"Created new file record with ID: {record_id} in {record_date.strftime('%Y-%m-%d')} status file")
                    self.logger.debug(
                        f"New record created: record_id={record_id}, original_timestamp={original_timestamp}")

                self.logger.debug("Step 2: Updating file status to IN_PROGRESS")
                self.logger.info(f"Changing file status to IN_PROGRESS for: {file_path}")
                self.logger.debug(f"Status update method: {'original_file' if is_old_file else 'current_record'}")

                if is_old_file:
                    self.logger.debug("Updating status in original file (old file)")
                    await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.IN_PROGRESS)
                else:
                    self.logger.debug(f"Updating status for record ID: {record_id}")
                    await self.status_manager.update_file_status(record_id, FileStatus.IN_PROGRESS)

                self.logger.debug("File status updated to IN_PROGRESS successfully")

                self.logger.debug("Step 3: Checking if file is empty")
                is_empty = await self.file_service.file_processor.check_file_empty_response(file_path)
                self.logger.debug(f"File empty check result: {is_empty}")

                if is_empty:
                    self.logger.debug("File is empty, updating status to EMPTY and skipping processing")
                    if is_old_file:
                        self.logger.debug("Updating EMPTY status in original file")
                        await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.EMPTY)
                    else:
                        self.logger.debug(f"Updating EMPTY status for record ID: {record_id}")
                        await self.status_manager.update_file_status(record_id, FileStatus.EMPTY)

                    self.logger.debug("Returning success result for empty file")
                    return ProcessingResult(
                        success=True,
                        message="File is empty, skipping processing",
                        data={"file_path": file_path, "status": "empty"}
                    )

                self.logger.debug("Step 4: Starting file parsing")
                try:
                    self.logger.debug("Loading JSON file data")
                    file_data = await self.file_service.file_processor.load_json_file(file_path)
                    self.logger.debug(
                        f"JSON file loaded successfully, data keys: {list(file_data.keys()) if isinstance(file_data, dict) else 'non-dict data'}")

                    self.logger.debug("Parsing file data into structured format")
                    parsed_data, original_source_users = self._parse_file_data(file_data)
                    self.logger.debug(
                        f"File parsed successfully: {len(parsed_data.users)} users found, {len(original_source_users)} original IdentityManagerUser objects")
                    self.logger.debug(
                        f"Parsed data summary: bundle={parsed_data.bundle}, env={parsed_data.env}, users_count={len(parsed_data.users)}")

                except Exception as e:
                    self.logger.debug(f"File parsing failed with error: {str(e)}")
                    self.logger.debug("Updating file status to ERROR due to parsing failure")

                    if is_old_file:
                        self.logger.debug("Updating ERROR status in original file")
                        await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.ERROR,
                                                                                      str(e))
                    else:
                        self.logger.debug(f"Updating ERROR status for record ID: {record_id}")
                        await self.status_manager.update_file_status(record_id, FileStatus.ERROR, str(e))

                    self.logger.debug("Raising FileProcessingError for parsing failure")
                    raise FileProcessingError(f"Failed to parse file {file_path}: {e}")

                self.logger.debug("Step 5: Checking if parsed data storage is enabled")
                if self.config.database.store_IDENTITY_MANAGER_data_enable:
                    self.logger.debug("Parsed data storage is enabled, storing data")
                    await self._store_parsed_data(parsed_data, file_path)
                    self.logger.debug("Parsed data stored successfully")
                else:
                    self.logger.debug("Parsed data storage is disabled, skipping storage")

                self.logger.debug("Step 6: Starting parsed data processing")
                self.logger.debug(f"Processing {len(parsed_data.users)} users from parsed data")
                processing_result = await self._process_parsed_data(parsed_data, original_source_users)
                self.logger.debug(f"Parsed data processing completed: {processing_result}")

                self.logger.debug("Step 7: Updating file status to DONE")
                if is_old_file:
                    self.logger.debug("Updating DONE status in original file")
                    await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.DONE)
                else:
                    self.logger.debug(f"Updating DONE status for record ID: {record_id}")
                    await self.status_manager.update_file_status(record_id, FileStatus.DONE)

                self.logger.debug("File status updated to DONE successfully")

                final_result = ProcessingResult(
                    success=True,
                    message=f"Successfully processed file {file_path}",
                    data={
                        "file_path": file_path,
                        "users_processed": len(parsed_data.users),
                        "processing_details": processing_result
                    }
                )
                self.logger.debug(f"File processing completed successfully: {final_result.message}")
                return final_result

        except asyncio.TimeoutError:
            error_msg = f"File processing timed out after {timeout} seconds"
            self.logger.error(f"Timeout processing file {file_path}: {error_msg}")
            self.logger.debug(f"Timeout error details: record_id={record_id}, is_old_file={is_old_file}")

            if record_id:
                self.logger.debug("Updating file status to ERROR due to timeout")
                if is_old_file:
                    self.logger.debug("Updating ERROR status in original file (timeout)")
                    await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.ERROR,
                                                                                  error_msg)
                else:
                    self.logger.debug(f"Updating ERROR status for record ID: {record_id} (timeout)")
                    await self.status_manager.update_file_status(record_id, FileStatus.ERROR, error_msg)
                self.logger.debug("File status updated to ERROR due to timeout")
            else:
                self.logger.debug("No record_id available, skipping status update for timeout")

            timeout_result = ProcessingResult(
                success=False,
                message=f"Timeout processing file {file_path}",
                error=error_msg
            )
            self.logger.debug(f"Returning timeout result: {timeout_result.message}")
            return timeout_result

        except Exception as e:
            self.logger.debug(f"Exception caught during file processing: {str(e)}", exc_info=True)
            self.logger.debug(f"Exception error details: record_id={record_id}, is_old_file={is_old_file}")

            if record_id:
                self.logger.debug("Updating file status to ERROR due to exception")
                if is_old_file:
                    self.logger.debug("Updating ERROR status in original file (exception)")
                    await self.status_manager.update_file_status_in_original_file(file_path, FileStatus.ERROR, str(e))
                else:
                    self.logger.debug(f"Updating ERROR status for record ID: {record_id} (exception)")
                    await self.status_manager.update_file_status(record_id, FileStatus.ERROR, str(e))
                self.logger.debug("File status updated to ERROR due to exception")
            else:
                self.logger.debug("No record_id available, skipping status update for exception")

            self.logger.error(f"Error processing file {file_path}: {e}")
            error_result = ProcessingResult(
                success=False,
                message=f"Failed to process file {file_path}",
                error=str(e)
            )
            self.logger.debug(f"Returning error result: {error_result.message}")
            return error_result

    async def _process_parsed_data(self, parsed_data: ParsedData, original_source_users: List = None) -> Dict[str, Any]:

        self.logger.debug("Starting parsed data processing")
        self.logger.debug(
            f"Parsed data details: bundle={parsed_data.bundle}, env={parsed_data.env}, users_count={len(parsed_data.users)}")
        if original_source_users:
            self.logger.debug(
                f"Original source users provided but not used in this flow (count={len(original_source_users)}). ParsedUser is the source of truth.")

        try:
            existing_map = getattr(self, 'user_regions_map', {}) or {}
            if not isinstance(existing_map, dict):
                existing_map = {}
            for u in (parsed_data.users or []):
                regions_set = existing_map.setdefault(u.login, set())
                if not isinstance(regions_set, set):
                    regions_set = set(regions_set) if regions_set else set()
                    existing_map[u.login] = regions_set
                if getattr(u, 'region', None):
                    regions_set.add(u.region)
            self.user_regions_map = existing_map
            self.logger.debug(
                f"Updated user_regions_map (users={len(existing_map)}) with regions from current group based on ParsedUser")

            envs_map = getattr(self, 'user_envs_map', {}) or {}
            if not isinstance(envs_map, dict):
                envs_map = {}
            for u in (parsed_data.users or []):
                pair_set = envs_map.setdefault(u.login, set())
                if not isinstance(pair_set, set):
                    pair_set = set(pair_set) if pair_set else set()
                    envs_map[u.login] = pair_set
                b = (getattr(u, 'bundle', '') or '').strip()
                e = (getattr(u, 'env', '') or '').strip()
                if b and e:
                    b_base = b.split('_', 1)[0].lower()
                    pair_set.add((b_base, e.lower()))
            self.user_envs_map = envs_map
            self.logger.debug(f"Updated user_envs_map (users={len(envs_map)}) with bundle/env pairs from current group")
        except Exception as e:
            self.logger.warning(f"Failed updating user_regions_map from ParsedUser (will use existing map if any): {e}")

        results = {
            "users_processed": 0,
            "users_created": 0,
            "users_updated": 0,
            "users_disabled": 0,
            "errors": []
        }
        self.logger.debug(f"Initialized processing results: {results}")

        if not parsed_data.users:
            self.logger.debug("No users to process, returning empty results")
            return results

        semaphore_limit = 5
        semaphore = asyncio.Semaphore(semaphore_limit)
        self.logger.debug(f"Created semaphore with limit: {semaphore_limit}")

        async def process_user_safe(parsed_user: ParsedUser):
            self.logger.debug(f"Acquiring semaphore for user: {parsed_user.login}")
            async with semaphore:
                self.logger.debug(f"Semaphore acquired, processing user: {parsed_user.login}")
                try:
                    await self._process_single_user(parsed_user, results)
                    self.logger.debug(f"User processed successfully: {parsed_user.login}")
                except Exception as e:
                    error_msg = f"Error processing user {parsed_user.login}: {e}"
                    self.logger.error(error_msg)
                    self.logger.debug(f"User processing error details for {parsed_user.login}: {str(e)}", exc_info=True)
                    results["errors"].append(error_msg)
                    self.processing_results["errors"].append(error_msg)
                finally:
                    self.logger.debug(f"Semaphore released for user: {parsed_user.login}")

        self.logger.debug(f"Creating tasks for {len(parsed_data.users)} users")
        tasks = [process_user_safe(user) for user in parsed_data.users]
        self.logger.debug(f"Created {len(tasks)} user processing tasks")

        if tasks:
            self.logger.debug("Starting concurrent user processing")
            start_time = datetime.utcnow()

            await asyncio.gather(*tasks, return_exceptions=True)

            end_time = datetime.utcnow()
            processing_duration = (end_time - start_time).total_seconds()
            self.logger.debug(f"All user processing completed in {processing_duration:.2f} seconds")
        else:
            self.logger.debug("No tasks to process")

        self.logger.debug(f"Final processing results: {results}")
        self.logger.debug("Parsed data processing completed")
        return results

    async def _process_single_user(self, parsed_user: ParsedUser, results: Dict[str, Any]):
        user_correlation_id = str(uuid.uuid4())

        self.logger.info(f"Starting user processing: {parsed_user.login} (correlation_id: {user_correlation_id})")
        self.logger.info(
            f"User details: login={parsed_user.login}, first_name={parsed_user.first_name}, last_name={parsed_user.last_name}")
        self.logger.info(f"User domain: '{parsed_user.domain}'")
        self.logger.info(f"User roles: {parsed_user.roles} (count: {len(parsed_user.roles)})")
        self.logger.info(f"User associations: {parsed_user.associations} (count: {len(parsed_user.associations)})")
        self.logger.info(f"User default role: '{parsed_user.default_role}'")

        if self.config.engine.check_roles_exist_in_TargetSystem:
            self.logger.info(f"Role validation enabled - validating user roles against TargetSystem")

            try:
                if parsed_user.roles:
                    self.logger.info(f"Validating {len(parsed_user.roles)} roles for user {parsed_user.login}")
                    valid_roles = await self.TargetSystem_service.validate_roles_exist(
                        roles=parsed_user.roles,
                        domain=parsed_user.domain,
                        bundle=parsed_user.bundle,
                        env=parsed_user.env,
                        correlation_id=user_correlation_id
                    )

                    if len(valid_roles) != len(parsed_user.roles):
                        invalid_roles = [role for role in parsed_user.roles if role not in valid_roles]
                        self.logger.warning(f"Role validation filtered out invalid roles: {invalid_roles}")
                        self.logger.info(f"Proceeding with valid roles only: {valid_roles}")
                        parsed_user.roles = valid_roles
                    else:
                        self.logger.info(f"All user roles are valid: {valid_roles}")

                if parsed_user.default_role:
                    self.logger.info(
                        f"Validating default role '{parsed_user.default_role}' for user {parsed_user.login}")
                    valid_default_roles = await self.TargetSystem_service.validate_roles_exist(
                        roles=[parsed_user.default_role],
                        domain=parsed_user.domain,
                        bundle=parsed_user.bundle,
                        env=parsed_user.env,
                        correlation_id=user_correlation_id
                    )

                    if valid_default_roles:
                        self.logger.info(f"Default role '{parsed_user.default_role}' is valid")
                    else:
                        self.logger.warning(f"Default role '{parsed_user.default_role}' is invalid and will be cleared")
                        parsed_user.default_role = None

            except Exception as e:
                self.logger.error(f"Role validation failed for user {parsed_user.login}: {e}")
                self.logger.warning(f"Proceeding with original roles due to validation failure (fail-safe mode)")
        else:
            self.logger.debug(f"Role validation disabled - proceeding with all roles without validation")
        self.logger.info(
            f"Processing context: bundle='{parsed_user.bundle}', environment='{parsed_user.env}', region='{parsed_user.region}'")

        try:
            timeout_seconds = 300
            self.logger.debug(
                f"Setting up user processing timeout: {timeout_seconds} seconds for user {parsed_user.login}")
            async with asyncio.timeout(timeout_seconds):
                self.logger.debug(f"Step 1: Checking if user should be disabled: {parsed_user.login}")
                should_disable_comprehensive = await self._should_disable_user_comprehensive(parsed_user)
                self.logger.debug(
                    f"User comprehensive disable check result for {parsed_user.login}: {should_disable_comprehensive}")

                if should_disable_comprehensive:
                    self.logger.debug(
                        f"User {parsed_user.login} should be disabled comprehensively, proceeding with comprehensive disabling")
                    await self._disable_user_comprehensive(parsed_user)
                    results["users_disabled"] += 1
                    self.logger.debug(
                        f"User {parsed_user.login} disabled comprehensively, updated results: users_disabled={results['users_disabled']}")
                else:
                    self.logger.debug(f"Step 2: Checking TargetSystem status for {parsed_user.bundle}/{parsed_user.env}")
                    TargetSystem_status = await self._check_TargetSystem_status(parsed_user.bundle, parsed_user.env)
                    self.logger.debug(
                        f"TargetSystem status check result for {parsed_user.bundle}/{parsed_user.env}: {TargetSystem_status}")

                    if not TargetSystem_status:
                        self.logger.debug(
                            f"TargetSystem is not available for {parsed_user.bundle}/{parsed_user.env}, storing reprocess data")
                        await self._store_reprocess_data_for_user(
                            parsed_user, "TargetSystem_down")
                        self.logger.debug(
                            f"Reprocess data stored for user {parsed_user.login} due to TargetSystem unavailability")
                        raise TargetSystemApiError("TargetSystem API is not available")

                    TargetSystem_assignments = None

                    TargetSystem_user = await self._get_user_data_from_TargetSystem(
                        parsed_user.login,
                        parsed_user.bundle,
                        parsed_user.env,
                        user_correlation_id
                    )

                    if TargetSystem_user is None:
                        self.logger.warning(
                            f"No user with that name in the domain {parsed_user.domain} User will be created"
                        )
                        try:
                            await self._create_user_in_TargetSystem(parsed_user, parsed_user.bundle, parsed_user.env,
                                               user_correlation_id)
                            results["users_created"] += 1
                        except Exception as e:
                            await self._store_reprocess_data_for_user(
                                parsed_user, "create_user_failed",
                            )
                            raise
                        comparison_result = ComparisonResult()
                    else:
                        TargetSystem_assignments = await self.TargetSystem_service.get_user_roles_and_associations(
                            parsed_user.login, parsed_user.bundle, parsed_user.env, user_correlation_id
                        )
                    comparison_result = self._build_comparison_from_parsed(parsed_user, TargetSystem_user, TargetSystem_assignments)

                    regions_set = set()
                    try:
                        if hasattr(self, 'user_regions_map') and self.user_regions_map is not None:
                            regions_set = self.user_regions_map.get(parsed_user.login, set()) or set()
                    except Exception:
                        regions_set = set()
                    if len(regions_set) > 1:
                        self.logger.info(
                            f"Regional gating applied for multi-region user {parsed_user.login} in {parsed_user.region}/{parsed_user.bundle}/{parsed_user.env}: "
                            f"regions={sorted(regions_set) if regions_set else 'unknown'}, domain changes allowed (1 domain per region enforced), default role updates allowed"
                        )

                    if comparison_result and self._has_changes(comparison_result):
                        try:
                            await self._set_user_roles(parsed_user, comparison_result, user_correlation_id, TargetSystem_user)
                            results["users_updated"] += 1
                        except Exception as e:
                            await self._store_reprocess_data_for_user(
                                parsed_user, "assign_roles_failed")
                            raise

                    # Always check other environments as per requirement
                    await self._disable_user_comprehensive(parsed_user)

                try:
                    await self._disable_user_regions_not_in_file(parsed_user)
                except Exception as cleanup_err:
                    self.logger.debug(f"Regional cleanup skipped/failed for {parsed_user.login}: {cleanup_err}")

                results["users_processed"] += 1
                self.processing_results["users_processed"] += 1

        except asyncio.TimeoutError:
            error_msg = f"User processing timed out after 300 seconds"
            self.logger.error(f"Timeout processing user {parsed_user.login}: {error_msg}")
            await self._store_reprocess_data_for_user(
                parsed_user, "timeout")
            results["errors"].append(error_msg)
            self.processing_results["errors"].append(error_msg)
        except Exception as e:
            error_msg = f"Error processing user {parsed_user.login}: {e}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)
            self.processing_results["errors"].append(error_msg)

    async def _get_user_data_from_TargetSystem(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> \
            Optional[TargetSystemUser]:
        try:
            return await self.TargetSystem_service.get_user_details(user_id, bundle, env, correlation_id)
        except Exception as e:
            self.logger.warning(f"User {user_id} not found in TargetSystem; will be created")
            return None

    async def _compare_user_data(self, source_user, TargetSystem_user: TargetSystemUser, TargetSystem_assignments, bundle: str,
                                 env: str, correlation_id: str = None) -> ComparisonResult:
        from ..models.IDENTITY_MANAGER import IdentityUser

        return await self.comparison_orchestrator.comparison_service.compare_user_data(
            source_user, TargetSystem_user, TargetSystem_assignments
        )

    def _build_comparison_from_parsed(self, parsed_user: ParsedUser, TargetSystem_user: Optional[TargetSystemUser],
                                      TargetSystem_assignments: Optional[TargetSystemUserAssignments]) -> ComparisonResult:
        try:
            if TargetSystem_assignments and not isinstance(TargetSystem_assignments, TargetSystemUserAssignments):
                if isinstance(TargetSystem_assignments, dict):
                    data = TargetSystem_assignments.get("data") if "data" in TargetSystem_assignments else TargetSystem_assignments
                    TargetSystem_assignments = TargetSystemUserAssignments(**data)
        except Exception as e:
            self.logger.debug(f"Failed to normalize TargetSystem_assignments to TargetSystemUserAssignments: {e}")

        desired_roles = list(dict.fromkeys(parsed_user.roles or []))
        desired_assoc = list(dict.fromkeys(parsed_user.associations or []))
        desired_default = parsed_user.default_role or None

        current_roles: List[str] = []
        current_assoc: List[str] = []
        current_default: Optional[str] = None
        current_domain: Optional[str] = None

        if isinstance(TargetSystem_assignments, TargetSystemUserAssignments):
            current_roles = list(dict.fromkeys(TargetSystem_assignments.roles or []))
            current_assoc = list(dict.fromkeys(TargetSystem_assignments.associations or []))
            current_default = TargetSystem_assignments.default_role or None
            current_domain = TargetSystem_assignments.domain or None
        elif TargetSystem_user:
            current_domain = getattr(TargetSystem_user, 'domain_name', None)

        self.logger.debug(
            f"Comparison snapshot for {parsed_user.login} @ {parsed_user.bundle}/{parsed_user.env}: "
            f"desired(domain={parsed_user.domain}, roles={desired_roles}, associations={desired_assoc}, default={desired_default}); "
            f"current(domain={current_domain}, roles={current_roles}, associations={current_assoc}, default={current_default})"
        )

        roles_to_add = [r for r in desired_roles if r not in current_roles]
        roles_to_remove = [r for r in current_roles if r not in desired_roles]
        assoc_to_add = [a for a in desired_assoc if a not in current_assoc]
        assoc_to_remove = [a for a in current_assoc if a not in desired_assoc]

        default_update: Optional[str] = None
        if desired_default and desired_default != current_default:
            default_update = desired_default
        elif not desired_default:
            default_update = None

        domain_update_required = False
        new_domain: Optional[str] = None
        if parsed_user.domain and current_domain and parsed_user.domain != current_domain:
            domain_update_required = True
            new_domain = parsed_user.domain

        comparison = ComparisonResult(
            roles_to_add=roles_to_add,
            roles_to_remove=roles_to_remove,
            associations_to_add=assoc_to_add,
            associations_to_remove=assoc_to_remove,
            default_role_update=default_update,
            domain_update_required=domain_update_required,
            new_domain=new_domain
        )

        self.logger.debug(
            f"Comparison result for {parsed_user.login}: +roles={comparison.roles_to_add}, -roles={comparison.roles_to_remove}, "
            f"+assoc={comparison.associations_to_add}, -assoc={comparison.associations_to_remove}, "
            f"default_update={comparison.default_role_update}, domain_update_required={comparison.domain_update_required}, new_domain={comparison.new_domain}"
        )

        return comparison

    async def _set_user_roles(self, parsed_user: ParsedUser, comparison_result: ComparisonResult,
                              correlation_id: str = None, TargetSystem_user: TargetSystemUser = None):
        should_disable = await self._should_disable_user(parsed_user)
        if should_disable:
            self.logger.info(f"User {parsed_user.login} should be disabled - skipping role removal operations")
            self.logger.info(
                f"User has no roles ({len(parsed_user.roles)}) and no associations ({len(parsed_user.associations)}) in IdentityManager data")

            if comparison_result.roles_to_add or comparison_result.associations_to_add:
                self.logger.info(f"Processing role additions for user {parsed_user.login} before disable")
            if comparison_result.roles_to_remove or comparison_result.associations_to_remove:
                self.logger.info(f"Skipping role removals for user {parsed_user.login} - user will be disabled instead")

            try:
                await self.TargetSystem_service.disable_user(parsed_user.login, parsed_user.bundle, parsed_user.env,
                                                    correlation_id)
                self.logger.info(
                    f"Successfully disabled user {parsed_user.login} in {parsed_user.bundle}/{parsed_user.env}")
            except Exception as e:
                self.logger.error(
                    f"Failed to disable user {parsed_user.login} in {parsed_user.bundle}/{parsed_user.env}: {e}")
                raise

            if comparison_result.roles_to_add or comparison_result.associations_to_add:
                assignment_request = TargetSystemAssignmentRequest(
                    user_id=parsed_user.login,
                    roles=comparison_result.roles_to_add,
                    associations=comparison_result.associations_to_add
                )
                await self._execute_assignment_operation(
                    operation_func=self.TargetSystem_service.add_user_assignments,
                    request=assignment_request,
                    bundle=parsed_user.bundle,
                    env=parsed_user.env,
                    correlation_id=correlation_id,
                    user_login=parsed_user.login,
                    operation_type="add",
                    roles=comparison_result.roles_to_add,
                    associations=comparison_result.associations_to_add,
                    error_prefix="assign_roles_failed",
                    domain=parsed_user.domain
                )

            if comparison_result.default_role_update:
                role_request = TargetSystemDefaultRoleRequest(
                    user_id=parsed_user.login,
                    default_role=comparison_result.default_role_update
                )
                await self._execute_default_role_operation(
                    request=role_request,
                    bundle=parsed_user.bundle,
                    env=parsed_user.env,
                    correlation_id=correlation_id,
                    user_login=parsed_user.login,
                    default_role=comparison_result.default_role_update,
                    domain=parsed_user.domain
                )

            return

        validation_status = "validated" if self.config.engine.check_roles_exist_in_TargetSystem else "unvalidated"

        if comparison_result.roles_to_add or comparison_result.roles_to_remove or comparison_result.associations_to_add or comparison_result.associations_to_remove or comparison_result.default_role_update:
            self.logger.info(
                f"Processing {validation_status} role/association changes for user {parsed_user.login} in domain '{parsed_user.domain}', bundle '{parsed_user.bundle}', environment '{parsed_user.env}'")
            if comparison_result.roles_to_add:
                self.logger.info(f"Roles to add ({validation_status}): {comparison_result.roles_to_add}")
            if comparison_result.roles_to_remove:
                self.logger.info(f"Roles to remove ({validation_status}): {comparison_result.roles_to_remove}")
            if comparison_result.associations_to_add:
                self.logger.info(f"Associations to add: {comparison_result.associations_to_add}")
            if comparison_result.associations_to_remove:
                self.logger.info(f"Associations to remove: {comparison_result.associations_to_remove}")
        if comparison_result.domain_update_required and comparison_result.new_domain:
            self.logger.info(f"Domain will be updated to '{comparison_result.new_domain}' (enforcing 1 domain per region)")
            await self._handle_domain_change(
                parsed_user,
                comparison_result.new_domain,
                correlation_id,
                TargetSystem_user
            )
            return
        if comparison_result.default_role_update:
            self.logger.info(
                f"Default role will be updated to ({validation_status}): {comparison_result.default_role_update}")

        if comparison_result.roles_to_add or comparison_result.associations_to_add:
            assignment_request = TargetSystemAssignmentRequest(
                user_id=parsed_user.login,
                roles=comparison_result.roles_to_add,
                associations=comparison_result.associations_to_add
            )
            await self._execute_assignment_operation(
                operation_func=self.TargetSystem_service.add_user_assignments,
                request=assignment_request,
                bundle=parsed_user.bundle,
                env=parsed_user.env,
                correlation_id=correlation_id,
                user_login=parsed_user.login,
                operation_type="add",
                roles=comparison_result.roles_to_add,
                associations=comparison_result.associations_to_add,
                error_prefix="assign_roles_failed",
                domain=parsed_user.domain
            )

        if comparison_result.roles_to_remove or comparison_result.associations_to_remove:
            removal_request = TargetSystemAssignmentRequest(
                user_id=parsed_user.login,
                roles=comparison_result.roles_to_remove,
                associations=comparison_result.associations_to_remove
            )
            await self._execute_assignment_operation(
                operation_func=self.TargetSystem_service.remove_user_assignments,
                request=removal_request,
                bundle=parsed_user.bundle,
                env=parsed_user.env,
                correlation_id=correlation_id,
                user_login=parsed_user.login,
                operation_type="remove",
                roles=comparison_result.roles_to_remove,
                associations=comparison_result.associations_to_remove,
                error_prefix="unassign_roles_failed",
                domain=parsed_user.domain
            )

        if comparison_result.default_role_update:
            role_request = TargetSystemDefaultRoleRequest(
                user_id=parsed_user.login,
                default_role=comparison_result.default_role_update
            )
            await self._execute_default_role_operation(
                request=role_request,
                bundle=parsed_user.bundle,
                env=parsed_user.env,
                correlation_id=correlation_id,
                user_login=parsed_user.login,
                default_role=comparison_result.default_role_update,
                domain=parsed_user.domain
            )

    async def _execute_assignment_operation(self, operation_func, request, bundle: str, env: str,
                                            correlation_id: str, user_login: str, operation_type: str,
                                            roles: List, associations: List, error_prefix: str, domain: str = None):
        if self.config.engine.role_domain_logging_enabled and roles and domain:
            domain_prefix_validation = await self.role_validator.validate_role_domain_prefix(
                roles, domain
            )
            self.role_validator.log_role_domain_validation_results(
                user_login, domain_prefix_validation, domain
            )

        try:
            await operation_func(request, bundle, env, correlation_id)
            self._log_assignment_success(user_login, operation_type, roles, associations, bundle, env, domain)
        except Exception as e:
            self._log_assignment_error(user_login, operation_type, roles, associations, e, bundle, env, domain)
            raise Exception(f"{error_prefix}: {e}")

    async def _execute_default_role_operation(self, request, bundle: str, env: str,
                                              correlation_id: str, user_login: str, default_role: str,
                                              domain: str = None):
        if self.config.engine.role_domain_logging_enabled and default_role and domain:
            domain_prefix_validation = await self.role_validator.validate_role_domain_prefix(
                [default_role], domain
            )
            self.role_validator.log_role_domain_validation_results(
                user_login, domain_prefix_validation, domain
            )

        context_info = f" in bundle '{bundle}', environment '{env}'"
        if domain:
            context_info += f", domain '{domain}'"

        try:
            await self.TargetSystem_service.update_user_default_role(request, bundle, env, correlation_id)
            self.logger.info(
                f"Successfully updated default role to '{default_role}' for user {user_login}{context_info}")
        except Exception as e:
            self.logger.error(
                f"Failed to update default role to '{default_role}' for user {user_login}{context_info}: {e}")
            raise Exception(f"update_default_role_failed: {e}")

    async def _handle_domain_change(self, parsed_user: ParsedUser, new_domain: str,
                                    correlation_id: str = None, TargetSystem_user: TargetSystemUser = None):
        old_domain = TargetSystem_user.domain_name if TargetSystem_user else parsed_user.domain
        user_login = parsed_user.login

        try:
            self.logger.info(
                f"Handling domain change for user {user_login} from '{old_domain}' to '{new_domain}' in bundle '{parsed_user.bundle}', environment '{parsed_user.env}'")

            self.logger.info(f"Disabling user {user_login} in current domain '{old_domain}'")
            try:
                await self.TargetSystem_service.disable_user(user_login, parsed_user.bundle, parsed_user.env, correlation_id)
                self.logger.info(f"Successfully disabled user {user_login} in domain '{old_domain}'")
            except Exception as e:
                self.logger.error(f"Failed to disable user {user_login} in domain '{old_domain}': {e}")
                raise Exception(f"disable_user_failed: {e}")

            self.logger.info(f"Creating new user {user_login} in new domain '{new_domain}'")

            new_user = ParsedUser(
                login=parsed_user.login,
                region=parsed_user.region,
                first_name=parsed_user.first_name,
                last_name=parsed_user.last_name,
                domain=new_domain,
                roles=parsed_user.roles,
                default_role=parsed_user.default_role,
                associations=parsed_user.associations,
                authorizations=parsed_user.authorizations
            )

            if self.config.engine.role_domain_logging_enabled:
                all_user_roles = []
                if new_user.roles:
                    all_user_roles.extend(new_user.roles)
                if new_user.default_role:
                    all_user_roles.append(new_user.default_role)

                if all_user_roles:
                    domain_prefix_validation = await self.role_validator.validate_role_domain_prefix(
                        all_user_roles, new_domain
                    )
                    self.role_validator.log_role_domain_validation_results(
                        new_user.login, domain_prefix_validation, new_domain
                    )

            try:
                await self._create_user_in_TargetSystem(new_user, parsed_user.bundle, parsed_user.env, correlation_id)
                self.logger.info(f"Successfully created user {user_login} in new domain '{new_domain}'")
            except Exception as e:
                self.logger.error(f"Failed to create user {user_login} in new domain '{new_domain}': {e}")
                raise Exception(f"create_user_failed: {e}")

        except Exception as e:
            self.logger.error(
                f"Failed to handle domain change for user {user_login} from '{old_domain}' to '{new_domain}': {e}")
            raise

    def _log_assignment_success(self, user_login: str, operation_type: str, roles: List, associations: List,
                                bundle: str = None, env: str = None, domain: str = None):
        context_info = ""
        if bundle and env:
            context_info = f" in bundle '{bundle}', environment '{env}'"
        if domain:
            context_info += f", domain '{domain}'"

        if roles:
            self.logger.info(f"Successfully {operation_type}d roles {roles} for user {user_login}{context_info}")
        if associations:
            self.logger.info(
                f"Successfully {operation_type}d associations {associations} for user {user_login}{context_info}")

    def _log_assignment_error(self, user_login: str, operation_type: str, roles: List, associations: List,
                              error: Exception, bundle: str = None, env: str = None, domain: str = None):
        context_info = ""
        if bundle and env:
            context_info = f" in bundle '{bundle}', environment '{env}'"
        if domain:
            context_info += f", domain '{domain}'"

        if roles:
            self.logger.error(f"Failed to {operation_type} roles {roles} for user {user_login}{context_info}: {error}")
        if associations:
            self.logger.error(
                f"Failed to {operation_type} associations {associations} for user {user_login}{context_info}: {error}")

    async def _initialize(self):
        self.logger.info("Initializing Access Sync Engine")

        self.file_service.file_processor.ensure_directories()

        await self._ensure_status_file_exists()

        try:
            if self.config.engine.check_roles_exist_in_TargetSystem:
                redis_result = await self.redis_service.test_connection(
                    bundle=self.config.default_test_bundle,
                    env=self.config.default_test_environment
                )
                if redis_result:
                    self.logger.info(f"Successfully connected to Redis")
                else:
                    self.logger.warning(f"Failed to connect to Redis")
            else:
                self.logger.info("Redis connectivity test skipped (CHECK_ROLES_EXIST_IN_TargetSystem=false)")

            if self.config.engine.execute_without_IDENTITY_MANAGER_read and self.IDENTITY_MANAGER_service.config.request_rest_api_url:
                IDENTITY_MANAGER_result = await self.IDENTITY_MANAGER_service.test_connectivity(self.correlation_id)
                if IDENTITY_MANAGER_result:
                    self.logger.info(
                        f"Successfully connected to IdentityManager API at URL: {self.IDENTITY_MANAGER_service.config.request_rest_api_url}")
                else:
                    self.logger.warning(
                        f"Failed to connect to IdentityManager API at URL: {self.IDENTITY_MANAGER_service.config.request_rest_api_url}")
            elif not self.config.engine.execute_without_IDENTITY_MANAGER_read:
                self.logger.info("IdentityManager connectivity check skipped (EXECUTE WITH IdentityManager READ=false)")
            else:
                self.logger.warning("IdentityManager API URL is not configured. Skipping connectivity test.")

            if self.TargetSystem_service.config.request_rest_api_url:
                TargetSystem_result = await self.TargetSystem_service.test_connectivity(
                    bundle=self.config.default_test_bundle,
                    env=self.config.default_test_environment,
                    correlation_id=self.correlation_id
                )
                if TargetSystem_result.get("api_accessible", False):
                    self.logger.info(
                        f"Successfully connected to TargetSystem API at URL: {self.TargetSystem_service.config.request_rest_api_url}")
                else:
                    self.logger.warning(
                        f"Failed to connect to TargetSystem API at URL: {self.TargetSystem_service.config.request_rest_api_url}")
            else:
                self.logger.warning("TargetSystem API URL is not configured. Skipping connectivity test.")

        except Exception as e:
            self.logger.warning(f"Connectivity test failed: {e}")

    async def _ensure_status_file_exists(self):
        try:
            current_date = datetime.utcnow()
            daily_folder = self.file_service.file_processor._get_daily_folder(current_date)
            status_file_path = self.file_service.file_processor._get_status_file_path(current_date)

            if not daily_folder.exists():
                self.logger.info(f"Creating daily folder: {daily_folder}")
                daily_folder.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Daily folder created successfully: {daily_folder}")

            if not status_file_path.exists():
                self.logger.info(f"Creating status file: {status_file_path}")
                empty_status_data = await self.status_manager.load_status_file(current_date)
                await self.status_manager.save_status_file(empty_status_data, current_date)
                self.logger.info(f"Status file created successfully: {status_file_path}")
            else:
                self.logger.debug(f"Status file already exists: {status_file_path}")
        except Exception as e:
            self.logger.warning(f"Failed to ensure status file exists: {e}")

    async def _get_last_successful_check_time(self) -> str:
        try:
            current_date = datetime.utcnow()
            days_to_check = self.config.engine.previous_days_check

            for days_back in range(0, days_to_check + 1):
                check_date = current_date - timedelta(days=days_back)
                try:
                    status_data = await self.status_manager.load_status_file(check_date)

                    latest_success_time = None
                    for record_id, record in status_data.records.items():
                        if latest_success_time is None or record.start_time > latest_success_time:
                            latest_success_time = record.start_time

                    if latest_success_time:
                        self.logger.info(
                            f"Found last successful check time from status files: {latest_success_time.strftime('%Y-%m-%dT%H:%M:%SZ')}")
                        return latest_success_time.strftime('%Y-%m-%dT%H:%M:%SZ')

                except Exception as e:
                    self.logger.debug(f"Could not load status file for {check_date.strftime('%Y-%m-%d')}: {e}")
                    continue

            default_time = self.config.time.default_last_time_check
            self.logger.info(f"No successful records found in status files, using configured default: {default_time}")
            return default_time

        except Exception as e:
            default_time = self.config.time.default_last_time_check
            self.logger.warning(
                f"Error reading last successful check time from status files: {e}. Using configured default: {default_time}")
            return default_time

    async def _get_data_from_IDENTITY_MANAGER(self, last_check: str = None) -> List[str]:
        if not self.config.engine.execute_without_IDENTITY_MANAGER_read:
            self.logger.error("CRITICAL: _get_data_from_IDENTITY_MANAGER called but EXECUTE_WITHOUT_IDENTITY_MANAGER_READ=false!")
            self.logger.error("This indicates a bug in the flag logic. IdentityManager operations should be disabled.")
            raise RuntimeError("IdentityManager operations are disabled by configuration but _get_data_from_IDENTITY_MANAGER was called")

        if last_check is None:
            last_check = await self._get_last_successful_check_time()

        start_timestamp = datetime.utcnow()
        self.logger.info(f"Starting IdentityManager data fetch at {start_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}")

        self.logger.info("Fetching data from IdentityManager (EXECUTE_WITHOUT_IDENTITY_MANAGER_READ=true)")
        users_data = await self.IDENTITY_MANAGER_service.fetch_modified_users_with_metadata(last_check, self.correlation_id)

        file_path = await self.file_service.file_processor.save_IDENTITY_MANAGER_response(users_data, start_timestamp)

        await self.status_manager.add_new_file_record(file_path, start_timestamp)
        self.logger.info(f"Added new file record to status file: {file_path}")

        return [file_path]

    def _extract_date_from_filename(self, file_path: str) -> Optional[datetime]:
        filename = Path(file_path).name

        pattern = r'^(\d{4})(\d{2})(\d{2})T\d{6}Z\.json$'
        match = re.match(pattern, filename)

        if match:
            year, month, day = match.groups()
            try:
                return datetime(int(year), int(month), int(day))
            except ValueError:
                self.logger.warning(f"Invalid date extracted from filename {filename}: {year}-{month}-{day}")
                return None

        return None

    def _resolve_file_path(self, stored_path: str, date: datetime) -> str:
        filename = stored_path.replace('\\', '/').split('/')[-1]

        daily_folder = self.status_manager.file_processor._get_daily_folder(date)
        local_path = daily_folder / filename

        return str(local_path)

    async def _get_files_with_new_status(self) -> List[str]:
        self.logger.info("Getting files with NEW status")
        files_with_new_status = []
        files_with_timestamps = []

        try:
            current_date = datetime.utcnow()

            days_to_check = self.config.engine.previous_days_check
            self.logger.info(f"Checking files from {days_to_check} days ago to current day")

            folders_to_check = []
            for days_back in range(0, days_to_check + 1):
                check_date = current_date - timedelta(days=days_back)
                folder_path = self.status_manager.file_processor._get_daily_folder(check_date)
                folders_to_check.append(str(folder_path))

            self.logger.debug(f"DEBUG: Folders to check for status files: {folders_to_check}")

            current_folder = self.status_manager.file_processor._get_daily_folder(current_date)
            self.logger.debug(f"DEBUG: Checking current date folder: {current_folder}")
            status_data = await self.status_manager.load_status_file(current_date)

            total_records = len(status_data.records)
            new_status_count = sum(1 for record in status_data.records.values() if record.status == FileStatus.NEW)
            self.logger.debug(
                f"DEBUG: Current date folder ({current_date.strftime('%Y-%m-%d')}) - Total records: {total_records}, NEW status files: {new_status_count}")

            for record_id, record in status_data.records.items():
                if record.status == FileStatus.NEW:
                    local_file_path = self._resolve_file_path(record.json_file_path, current_date)
                    if Path(local_file_path).exists():
                        files_with_timestamps.append((local_file_path, record.start_time))
                        self.logger.info(f"Found file with NEW status: {local_file_path}")
                    else:
                        self.logger.warning(
                            f"File with NEW status not found on disk: {local_file_path} (original path: {record.json_file_path})")

            for days_back in range(1, days_to_check + 1):
                try:
                    past_date = current_date - timedelta(days=days_back)
                    past_folder = self.status_manager.file_processor._get_daily_folder(past_date)
                    self.logger.debug(f"DEBUG: Checking past date folder: {past_folder}")
                    past_status_data = await self.status_manager.load_status_file(past_date)

                    past_total_records = len(past_status_data.records)
                    past_new_status_count = sum(
                        1 for record in past_status_data.records.values() if record.status == FileStatus.NEW)
                    self.logger.debug(
                        f"DEBUG: Past date folder ({past_date.strftime('%Y-%m-%d')}) - Total records: {past_total_records}, NEW status files: {past_new_status_count}")

                    for record_id, record in past_status_data.records.items():
                        if record.status == FileStatus.NEW:
                            local_file_path = self._resolve_file_path(record.json_file_path, past_date)
                            if Path(local_file_path).exists():
                                file_already_exists = any(
                                    file_path == local_file_path for file_path, _ in files_with_timestamps)
                                if not file_already_exists:
                                    files_with_timestamps.append((local_file_path, record.start_time))
                                    self.logger.info(
                                        f"Found file with NEW status from {past_date.strftime('%Y-%m-%d')}: {local_file_path}")
                            else:
                                self.logger.warning(
                                    f"File with NEW status not found on disk: {local_file_path} (original path: {record.json_file_path})")
                except Exception as e:
                    self.logger.debug(f"No status file found for {past_date.strftime('%Y-%m-%d')}: {e}")

            files_with_timestamps.sort(key=lambda x: x[1])
            files_with_new_status = [file_path for file_path, _ in files_with_timestamps]

            if files_with_new_status:
                self.logger.debug("DEBUG: Complete list of files with NEW status:")
                for i, file_path in enumerate(files_with_new_status, 1):
                    self.logger.debug(f"DEBUG:   {i}. {file_path}")
            else:
                self.logger.debug("DEBUG: No files with NEW status found")

            self.logger.info(
                f"Found {len(files_with_new_status)} files with NEW status, sorted chronologically from oldest to newest")
            return files_with_new_status

        except Exception as e:
            self.logger.error(f"Error getting files with NEW status: {e}")
            self.processing_results["errors"].append(f"Failed to get files with NEW status: {e}")
            return []

    async def _prepare_failed_files(self):
        self.logger.info("Preparing failed files for reprocessing (legacy method)")
        await self._check_error_status_files()
        await self._check_in_progress_status_files()

    async def _check_error_status_files(self):
        self.logger.debug("Check files status - error")
        error_files_count = 0
        current_date = datetime.utcnow()
        days_to_check = self.config.engine.previous_days_check

        for days_back in range(0, days_to_check + 1):
            try:
                check_date = current_date - timedelta(days=days_back)
                status_data = await self.status_manager.load_status_file(check_date)

                for record_id, record in status_data.records.items():
                    if record.status == FileStatus.ERROR:
                        if not self.config.engine.enable_error_reprocessing:
                            self.logger.warning(
                                f"Skipping ERROR->NEW for {record.json_file_path} because ENABLE_ERROR_REPROCESSING=false")
                            continue
                        max_err = self.config.engine.max_error_reprocess_count
                        if record.reprocess_count >= max_err:
                            self.logger.info(
                                f"Max ERROR reprocess attempts reached ({record.reprocess_count}/{max_err}) for {record.json_file_path}; keeping status ERROR")
                            continue
                        self.logger.info(
                            f"Changing status from ERROR to NEW for file: {record.json_file_path} (from {check_date.strftime('%Y-%m-%d')}); attempt {record.reprocess_count + 1}/{max_err}")
                        await self.status_manager.update_file_status(
                            record_id,
                            FileStatus.NEW,
                            timestamp=check_date,
                            increment_reprocess_count=True
                        )
                        error_files_count += 1
            except Exception as e:
                self.logger.debug(f"No status file found for {check_date.strftime('%Y-%m-%d')}: {e}")

        if error_files_count > 0:
            self.logger.info(f"Changed status from ERROR to NEW for {error_files_count} files")
        else:
            self.logger.info("No files with ERROR status found")

    async def _check_in_progress_status_files(self):
        self.logger.debug("Check file status - in_progress")
        stuck_in_progress_count = 0
        current_date = datetime.utcnow()
        days_to_check = self.config.engine.previous_days_check

        for days_back in range(0, days_to_check + 1):
            try:
                check_date = current_date - timedelta(days=days_back)
                status_data = await self.status_manager.load_status_file(check_date)

                for record_id, record in status_data.records.items():
                    if record.status == FileStatus.IN_PROGRESS:
                        start_time = record.start_time
                        if start_time.tzinfo is not None:
                            current_date_aware = current_date.replace(tzinfo=start_time.tzinfo)
                            time_since_start = current_date_aware - start_time
                        else:
                            time_since_start = current_date - start_time
                        if time_since_start.total_seconds() > 7200:
                            if not self.config.engine.enable_in_progress_reprocessing:
                                self.logger.warning(
                                    f"Skipping IN_PROGRESS stuck handling for {record.json_file_path} because ENABLE_IN_PROGRESS_REPROCESSING=false")
                                continue
                            max_inprog = self.config.engine.max_in_progress_reprocess_count
                            if record.reprocess_count >= max_inprog:
                                error_message = (
                                    f"File reprocessing failed after {record.reprocess_count} attempts. "
                                    f"Maximum IN_PROGRESS reprocess count ({max_inprog}) reached. "
                                    f"File was stuck in IN_PROGRESS status for {time_since_start}."
                                )
                                self.logger.warning(
                                    f"Marking file as ERROR due to max IN_PROGRESS reprocess attempts: {record.json_file_path}")
                                await self.status_manager.update_file_status(
                                    record_id,
                                    FileStatus.ERROR,
                                    error_message,
                                    timestamp=check_date
                                )
                                stuck_in_progress_count += 1
                            else:
                                error_message = (
                                    f"File was stuck in IN_PROGRESS status for {time_since_start}. "
                                    f"Resetting to NEW for reprocessing attempt {record.reprocess_count + 1}/{max_inprog}."
                                )
                                self.logger.info(
                                    f"Changing status from IN_PROGRESS to NEW for stuck file: {record.json_file_path} (stuck for {time_since_start})")
                                await self.status_manager.update_file_status(
                                    record_id,
                                    FileStatus.NEW,
                                    error_message,
                                    timestamp=check_date,
                                    increment_reprocess_count=True
                                )
                                stuck_in_progress_count += 1
            except Exception as e:
                self.logger.debug(f"No status file found for {check_date.strftime('%Y-%m-%d')}: {e}")

        if stuck_in_progress_count > 0:
            self.logger.info(f"Handled {stuck_in_progress_count} files stuck in IN_PROGRESS status")
        else:
            self.logger.info("No files stuck in IN_PROGRESS status found")

    async def _reprocess_failed_steps(self):
        self.logger.info("Reprocessing failed steps")

        if not self.config.engine.enable_json_error_reprocessing:
            self.logger.warning(
                "*.json_error reprocessing is disabled by configuration (ENABLE_JSON_ERROR_REPROCESSING=false). Skipping reprocessing of reprocess files.")
            return

        try:
            data_dir = Path(self.config.database.json_file_db_path)
            json_error_files_with_timestamps = []

            current_date = datetime.utcnow()
            days_to_check = self.config.engine.previous_days_check
            self.logger.info(f"Checking for *.json_error files from {days_to_check} days ago to current day")

            for days_back in range(0, days_to_check + 1):
                check_date = current_date - timedelta(days=days_back)
                daily_folder = data_dir / check_date.strftime('%Y-%m-%d')

                if daily_folder.exists():
                    self.logger.debug(f"Checking folder for *.json_error files: {daily_folder}")
                    for json_error_file in daily_folder.glob("*.json_error"):
                        file_timestamp = check_date
                        try:
                            file_name = Path(json_error_file).stem.replace('_error', '')
                            if 'T' in file_name and 'Z' in file_name:
                                timestamp_str = file_name.split('/')[-1]
                                if len(timestamp_str) == 16 and timestamp_str.endswith('Z'):
                                    file_timestamp = datetime.strptime(timestamp_str, '%Y%m%dT%H%M%SZ')
                        except Exception:
                            pass

                        json_error_files_with_timestamps.append((str(json_error_file), file_timestamp))
                        self.logger.debug(f"Found *.json_error file: {json_error_file}")

            json_error_files_with_timestamps.sort(key=lambda x: x[1])
            json_error_files = [file_path for file_path, _ in json_error_files_with_timestamps]

            if json_error_files:
                self.logger.info(
                    f"Found {len(json_error_files)} *.json_error files for reprocessing, sorted chronologically from oldest to newest")

                for i, json_error_file in enumerate(json_error_files, 1):
                    self.logger.info(f"Processing *.json_error file {i}/{len(json_error_files)}: {json_error_file}")
                    try:
                        self.logger.info(f"Reprocessing file: {json_error_file}")

                        original_file_path = json_error_file.replace("_error", "")

                        max_reprocess_count = self.config.engine.max_error_reprocess_count
                        reprocess_file = await self.file_service.reprocess_manager.load_reprocess_file(
                            original_file_path,
                            increment_counter=False,
                            max_reprocess_count=max_reprocess_count
                        )

                        if reprocess_file.reprocess_count >= max_reprocess_count:
                            self.logger.warning(
                                f"Too many retries for file {json_error_file}. Reprocess count ({reprocess_file.reprocess_count}) exceeds or equals maximum allowed ({max_reprocess_count}). Skipping reprocessing.")
                            continue

                        if reprocess_file.data:
                            reprocess_file.reprocess_count += 1
                            await self.file_service.reprocess_manager.save_reprocess_file(reprocess_file,
                                                                                          original_file_path)

                            self.logger.info(
                                f"Reprocessing file {json_error_file} - reprocess count: {reprocess_file.reprocess_count}/{max_reprocess_count}")

                            self.logger.info(
                                f"Processing {len(reprocess_file.data)} bundle/environment combinations from reprocess file")

                            for bundle_env, users_data in reprocess_file.data.items():
                                self.logger.info(
                                    f"Processing bundle/environment: {bundle_env} with {len(users_data)} users")

                                create_user_failed_users = []
                                other_users = []
                                for user_id, reprocess_data in users_data.items():
                                    if reprocess_data.request_type == "create_user_failed":
                                        create_user_failed_users.append((user_id, reprocess_data))
                                    else:
                                        other_users.append((user_id, reprocess_data))

                                all_users = create_user_failed_users + other_users

                                for user_id, reprocess_data in all_users:
                                    try:
                                        self.logger.info(
                                            f"Processing {user_id} for {bundle_env} with request_type: {reprocess_data.request_type}")

                                        destination_bundle = reprocess_data.bundle or (
                                            bundle_env.split('_', 1)[0] if '_' in bundle_env else '')
                                        destination_env = reprocess_data.env or (
                                            bundle_env.split('_', 1)[1] if '_' in bundle_env else '')
                                        destination_region = reprocess_data.region or ''

                                        await self._process_user_data_for_bundle_env(
                                            user_id,
                                            destination_bundle,
                                            destination_env,
                                            reprocess_data.json_data,
                                            reprocess_data.first_name,
                                            reprocess_data.last_name,
                                            reprocess_data.request_type,
                                            destination_region
                                        )

                                        self.logger.info(
                                            f"Successfully reprocessed {user_id} for {bundle_env} - removing from reprocess file")
                                        await self.file_service.reprocess_manager.remove_reprocess_data(
                                            original_file_path, user_id, bundle_env
                                        )

                                    except Exception as user_error:
                                        self.logger.error(
                                            f"Error reprocessing user {user_id} for {bundle_env}: {user_error}")
                                        self.processing_results["errors"].append(
                                            f"Failed to reprocess user {user_id} for {bundle_env}: {user_error}")

                        else:
                            self.logger.warning(f"No data found in reprocess file: {json_error_file}")

                    except Exception as e:
                        self.logger.error(f"Error reprocessing file {json_error_file}: {e}")
                        self.processing_results["errors"].append(f"Failed to reprocess {json_error_file}: {e}")
            else:
                self.logger.info("No *.json_error files found for reprocessing")

        except Exception as e:
            self.logger.error(f"Error in reprocessing failed steps: {e}")
            self.processing_results["errors"].append(f"Failed to reprocess failed steps: {e}")

    def _parse_file_data(self, file_data: Dict[str, Any]) -> tuple[ParsedData, List]:
        from ..models.IDENTITY_MANAGER import IdentityUser

        original_source_users = []
        skipped_users = []

        if "data" in file_data and "modifiedUsers" in file_data["data"]:
            users_data = file_data["data"]["modifiedUsers"].get("users", [])
        elif "users" in file_data:
            users_data = file_data["users"]
        else:
            users_data = file_data if isinstance(file_data, list) else [file_data]

        filtered_users_data = []

        for user_data in users_data:
            try:
                if isinstance(user_data, dict):
                    should_skip, domain_count = self._should_skip_user_for_domain_check(user_data)

                    if should_skip:
                        user_login = user_data.get("login", "unknown")
                        max_domains = self.config.engine.max_domains_per_user

                        domain_names = self._extract_domain_names(user_data)
                        domain_names_str = ", ".join(domain_names) if domain_names else "unknown"

                        self.logger.warning(
                            f"Skipping user {user_login} due to domain limit exceeded: "
                            f"found {domain_count} domains (max allowed: {max_domains}). "
                            f"Domains found: {domain_names_str}"
                        )

                        skipped_users.append({
                            "login": user_login,
                            "domain_count": domain_count,
                            "domains": domain_names,
                            "reason": f"Domain count {domain_count} exceeds maximum allowed {max_domains}"
                        })
                        continue

                    filtered_users_data.append(user_data)

            except Exception as e:
                self.logger.error(f"Error during domain checking for user: {e}")
                filtered_users_data.append(user_data)
                continue

        if self.config.engine.domain_check_enabled:
            total_users = len(users_data)
            processed_users = len(filtered_users_data)
            skipped_count = len(skipped_users)

            self.logger.info(
                f"Domain checking summary: {processed_users}/{total_users} users will be processed, "
                f"{skipped_count} users skipped due to domain limit"
            )

            if not hasattr(self, 'processing_results'):
                self.processing_results = {"users_skipped_domain_check": []}
            if "users_skipped_domain_check" not in self.processing_results:
                self.processing_results["users_skipped_domain_check"] = []

            self.processing_results["users_skipped_domain_check"].extend(skipped_users)

        for user_data in filtered_users_data:
            try:
                if isinstance(user_data, dict):
                    source_user = IdentityUser(**user_data)
                    original_source_users.append(source_user)
            except Exception as e:
                self.logger.error(f"Failed to parse IdentityManagerUser: {e}")
                continue

        filtered_file_data = file_data.copy()
        if "data" in filtered_file_data and "modifiedUsers" in filtered_file_data["data"]:
            filtered_file_data["data"]["modifiedUsers"]["users"] = filtered_users_data
        elif "users" in filtered_file_data:
            filtered_file_data["users"] = filtered_users_data
        else:
            filtered_file_data = filtered_users_data

        parsed_data = self.data_parser.parse_file_data(filtered_file_data)

        return parsed_data, original_source_users

    async def _store_parsed_data(self, parsed_data: ParsedData, file_path: str):
        pass

    def _count_user_domains(self, user_data: Dict[str, Any]) -> int:
        domain_count = 0

        try:
            authorizations = user_data.get("authorizations", [])

            for authorization in authorizations:
                application_hierarchies = authorization.get("applicationHierarchies", [])

                for hierarchy in application_hierarchies:
                    app_hierarchy = hierarchy.get("applicationHierarchy", {})
                    if app_hierarchy.get("label") == "Domain":
                        attribute_values = hierarchy.get("attributeValues", [])
                        domain_count += len(attribute_values)

        except Exception as e:
            self.logger.error(f"Error counting domains for user: {e}")
            return 0

        return domain_count

    def _extract_domain_names(self, user_data: Dict[str, Any]) -> List[str]:
        domain_names = []

        try:
            authorizations = user_data.get("authorizations", [])

            for authorization in authorizations:
                application_hierarchies = authorization.get("applicationHierarchies", [])

                for hierarchy in application_hierarchies:
                    app_hierarchy = hierarchy.get("applicationHierarchy", {})
                    if app_hierarchy.get("label") == "Domain":
                        attribute_values = hierarchy.get("attributeValues", [])
                        for attr_value in attribute_values:
                            domain_name = attr_value.get("valueName", "unknown")
                            if domain_name not in domain_names:
                                domain_names.append(domain_name)

        except Exception as e:
            self.logger.error(f"Error extracting domain names for user: {e}")
            return []

        return domain_names

    def _should_skip_user_for_domain_check(self, user_data: Dict[str, Any]) -> tuple[bool, int]:
        if not self.config.engine.domain_check_enabled:
            return False, 0

        domain_count = self._count_user_domains(user_data)
        domain_names = self._extract_domain_names(user_data)
        max_domains = self.config.engine.max_domains_per_user
        user_id = user_data.get("userId", "unknown")

        should_skip = domain_count > max_domains

        if domain_count > 0:
            self.logger.info(
                f"Domain check for user {user_id}: found {domain_count} domains {domain_names}, max allowed: {max_domains}")
            if should_skip:
                self.logger.warning(
                    f"User {user_id} will be skipped - domain count ({domain_count}) exceeds maximum allowed ({max_domains}). Domains: {domain_names}")
            else:
                self.logger.info(
                    f"User {user_id} passed domain check - domain count ({domain_count}) is within limit ({max_domains}). Domains: {domain_names}")
        else:
            self.logger.info(f"User {user_id} has no domains assigned")

        return should_skip, domain_count

    async def _should_disable_user(self, parsed_user: ParsedUser) -> bool:
        return len(parsed_user.roles) == 0 and len(parsed_user.associations) == 0

    async def _should_disable_user_comprehensive(self, parsed_user: ParsedUser) -> bool:
        if len(parsed_user.roles) == 0 and len(parsed_user.associations) == 0:
            self.logger.info(
                f"User {parsed_user.login} has no roles/associations in IdentityManager data - checking for comprehensive disable")
            return True

        return False

    async def _disable_user_in_all_environments(self, parsed_user: ParsedUser):
        self.logger.info(f"Starting comprehensive user disable for {parsed_user.login}")
        self.logger.info(
            f"User to disable: {parsed_user.login} (domain: '{parsed_user.domain}', first_name: {parsed_user.first_name}, last_name: {parsed_user.last_name})")
        self.logger.info(
            f"Reason: User has no roles ({len(parsed_user.roles)}) and no associations ({len(parsed_user.associations)}) in IdentityManager data")

        environments = self.config.environment_list
        bundle_region_map = self.config.bundle_region_map

        disable_results = []

        for env_entry in environments:
            if '_' in env_entry:
                parts = env_entry.split('_', 1)
                bundle = parts[0]
                env = parts[1]
            else:
                env = env_entry
                bundle = None
                for bundle_key, regions in bundle_region_map.items():
                    if isinstance(regions, str):
                        region_list = [r.strip() for r in regions.split(',')]
                    else:
                        region_list = regions if isinstance(regions, list) else [regions]

                    for region in region_list:
                        if env.startswith(region) or env == region:
                            bundle = bundle_key
                            break
                    if bundle:
                        break

            if not bundle:
                self.logger.warning(f"Could not determine bundle for environment entry {env_entry}, skipping")
                continue

            try:
                result = await self.TargetSystem_service.disable_user(
                    parsed_user.login,
                    bundle,
                    env
                )
                disable_results.append({
                    "env": env,
                    "bundle": bundle,
                    "status": "success",
                    "message": result.message if hasattr(result, 'message') else "User disabled successfully"
                })
                self.logger.info(f"Successfully disabled user {parsed_user.login} in {bundle}/{env}")

            except Exception as e:
                disable_results.append({
                    "env": env,
                    "bundle": bundle,
                    "status": "error",
                    "message": str(e)
                })
                self.logger.error(f"Failed to disable user {parsed_user.login} in {bundle}/{env}: {e}")

        disable_info = UserDisableInfo(
            user_id=parsed_user.login,
            first_name=parsed_user.first_name,
            last_name=parsed_user.last_name
        )
        self.processing_results["users_disabled"].append(disable_info)

        successful_disables = [r for r in disable_results if r["status"] == "success"]
        failed_disables = [r for r in disable_results if r["status"] == "error"]

        self.logger.info(
            f"User {parsed_user.login} disable summary: {len(successful_disables)} successful, {len(failed_disables)} failed")

        if failed_disables:
            self.logger.warning(
                f"Failed to disable user {parsed_user.login} in environments: {[r['env'] for r in failed_disables]}")

    async def _disable_user_comprehensive(self, parsed_user: ParsedUser):
        self.logger.info(f"Starting comprehensive disable check for user {parsed_user.login}")

        environments = self.config.environment_list
        bundle_region_map = self.config.bundle_region_map

        user_regions_current_file = set()
        try:
            if hasattr(self, 'user_regions_map') and isinstance(self.user_regions_map, dict):
                user_regions_current_file = set(self.user_regions_map.get(parsed_user.login, set()) or set())
                if user_regions_current_file:
                    self.logger.debug(
                        f"Regions for user {parsed_user.login} present in current file: {sorted(list(user_regions_current_file))}")
        except Exception as e:
            self.logger.debug(f"Failed to read user_regions_map for {parsed_user.login}: {e}")

        current_bundle_env = f"{parsed_user.bundle}_{parsed_user.env}"

        disable_results = []
        environments_to_check = []

        for env_entry in environments:
            if '_' in env_entry:
                parts = env_entry.split('_', 1)
                bundle = parts[0]
                env = parts[1]
            else:
                env = env_entry
                bundle = None
                for bundle_key, regions in bundle_region_map.items():
                    if isinstance(regions, str):
                        region_list = [r.strip() for r in regions.split(',')]
                    else:
                        region_list = regions if isinstance(regions, list) else [regions]

                    for region in region_list:
                        if env.startswith(region) or env == region:
                            bundle = bundle_key
                            break
                    if bundle:
                        break

            if bundle:
                environments_to_check.append((bundle, env, env_entry))
            else:
                self.logger.warning(f"Could not determine bundle for environment entry {env_entry}, skipping")

        self.logger.info(f"Checking user {parsed_user.login} access across {len(environments_to_check)} environments")

        for bundle, env, env_entry in environments_to_check:
            try:
                if env_entry == current_bundle_env:
                    self.logger.info(f"Skipping {env_entry} - already handled by current IdentityManager processing")
                    continue

                self.logger.debug(f"Checking user {parsed_user.login} access in {bundle}/{env}")

                try:
                    TargetSystem_present = False
                    TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env)

                    if TargetSystem_user is not None:
                        TargetSystem_present = True
                        self.logger.info(f"User {parsed_user.login} has access in {bundle}/{env}")
                    else:
                        try:
                            self.logger.info(
                                f"Comprehensive disable: checking assignments for {parsed_user.login} in {bundle}/{env}"
                            )
                            TargetSystem_assignments = await self.TargetSystem_service.get_user_roles_and_associations(
                                parsed_user.login, bundle, env
                            )
                            if TargetSystem_assignments and (
                                    getattr(TargetSystem_assignments, 'roles', None) or
                                    getattr(TargetSystem_assignments, 'associations', None) or
                                    getattr(TargetSystem_assignments, 'default_role', None) or
                                    getattr(TargetSystem_assignments, 'user_id', None)
                            ):
                                TargetSystem_present = True
                                roles_count = len(getattr(TargetSystem_assignments, 'roles', []) or [])
                                assoc_count = len(getattr(TargetSystem_assignments, 'associations', []) or [])
                                default_present = bool(getattr(TargetSystem_assignments, 'default_role', None))
                                self.logger.info(
                                    f"User {parsed_user.login} appears present in {bundle}/{env} based on assignments (roles={roles_count}, associations={assoc_count}, default_role_present={default_present})"
                                )
                        except Exception as assign_err:
                            self.logger.debug(
                                f"Assignments check failed for {parsed_user.login} in {bundle}/{env}: {assign_err}"
                            )

                    if TargetSystem_present:
                        destination_region = None
                        try:
                            bundle_base = bundle.split('_')[0] if '_' in bundle else bundle
                            for key, value in (bundle_region_map or {}).items():
                                if isinstance(value, str):
                                    items = [v.strip() for v in value.split(',') if v.strip()]
                                else:
                                    items = value if isinstance(value, list) else [value]

                                if bundle_base in items:
                                    destination_region = key
                                    break

                                if key == bundle_base and items:
                                    destination_region = items[0]
                                    break
                        except Exception as re_err:
                            self.logger.debug(f"Failed to resolve region for {bundle}/{env}: {re_err}")

                        should_revoke_due_to_empty = (
                                len(parsed_user.roles) == 0 and len(parsed_user.associations) == 0)

                        if should_revoke_due_to_empty:
                            result = await self.TargetSystem_service.disable_user(parsed_user.login, bundle, env)

                            message = "Access revoked - user not in IdentityManager data"

                            disable_results.append({
                                "env": env,
                                "bundle": bundle,
                                "env_entry": env_entry,
                                "status": "success",
                                "message": message
                            })
                            self.logger.info(
                                f"Successfully revoked access for user {parsed_user.login} in {bundle}/{env}: {message}")
                        else:
                            self.logger.info(
                                f"Keeping access for user {parsed_user.login} in {bundle}/{env} - has roles/associations in current file")
                    else:
                        self.logger.info(
                            f"User {parsed_user.login} not present in TargetSystem for {bundle}/{env} - no action needed")

                except Exception as check_error:
                    self.logger.debug(
                        f"Could not check user {parsed_user.login} access in {bundle}/{env}: {check_error}")
                    continue

            except Exception as e:
                disable_results.append({
                    "env": env,
                    "bundle": bundle,
                    "env_entry": env_entry,
                    "status": "error",
                    "message": str(e)
                })
                self.logger.error(
                    f"Error processing comprehensive disable for user {parsed_user.login} in {bundle}/{env}: {e}")

        successful_disables = [r for r in disable_results if r["status"] == "success"]
        failed_disables = [r for r in disable_results if r["status"] == "error"]

        if successful_disables:
            self.logger.info(
                f"Comprehensive disable for user {parsed_user.login}: {len(successful_disables)} environments processed successfully")
            for result in successful_disables:
                self.logger.info(f"  - {result['bundle']}/{result['env']}: {result['message']}")

        if failed_disables:
            self.logger.warning(
                f"Comprehensive disable for user {parsed_user.login}: {len(failed_disables)} environments failed")
            for result in failed_disables:
                self.logger.warning(f"  - {result['bundle']}/{result['env']}: {result['message']}")

        if successful_disables:
            disable_info = UserDisableInfo(
                user_id=parsed_user.login,
                first_name=parsed_user.first_name,
                last_name=parsed_user.last_name
            )
            self.processing_results["users_disabled"].append(disable_info)

    async def _disable_user_regions_not_in_file(self, parsed_user: ParsedUser):
        try:
            self.logger.info(f"Starting regional cleanup for user {parsed_user.login}")
            user_regions_current_file = set()
            if hasattr(self, 'user_regions_map') and isinstance(self.user_regions_map, dict):
                user_regions_current_file = set(self.user_regions_map.get(parsed_user.login, set()) or set())

            if not user_regions_current_file:
                self.logger.info(
                    f"Skip regional cleanup for {parsed_user.login}: no region info found in current file")
                return

            current_bundle_env = f"{parsed_user.bundle}_{parsed_user.env}"
            bundle_region_map = self.config.bundle_region_map or {}

            environments_to_check = []
            for env_entry in self.config.environment_list:
                if '_' in env_entry:
                    parts = env_entry.split('_', 1)
                    bundle = parts[0]
                    env = parts[1]
                else:
                    env = env_entry
                    bundle = None

                    if bundle is None:
                        for key, value in (bundle_region_map or {}).items():
                            items = [v.strip() for v in value.split(',')] if isinstance(value, str) else (
                                value if isinstance(value, list) else [value])
                            if env in items:
                                bundle = key
                                break

                if bundle:
                    environments_to_check.append((bundle, env, env_entry))
                else:
                    self.logger.info(f"Regional cleanup: cannot determine bundle for env entry '{env_entry}', skipping")

            user_envs_current_file: set[tuple[str, str]] = set()
            try:
                if hasattr(self, 'user_envs_map') and isinstance(self.user_envs_map, dict):
                    user_envs_current_file = set(self.user_envs_map.get(parsed_user.login, set()) or set())
            except Exception:
                user_envs_current_file = set()

            disable_count = 0
            for bundle, env, env_entry in environments_to_check:
                if env_entry == current_bundle_env:
                    continue

                bundle_base = (bundle.split('_', 1)[0] if '_' in bundle else bundle).lower()
                env_norm = (env or '').lower()

                if (bundle_base, env_norm) in user_envs_current_file:
                    self.logger.info(
                        f"Regional cleanup: keeping access for {parsed_user.login} in {bundle}/{env} - present in current file (bundle/env match)")
                    continue

                try:
                    await self.TargetSystem_service.disable_user(parsed_user.login, bundle, env)
                    disable_count += 1
                    self.logger.info(
                        f"Regional cleanup: revoked access for {parsed_user.login} in {bundle}/{env} (bundle/env not present in current file)")
                    self.processing_results["users_disabled"].append(UserDisableInfo(
                        user_id=parsed_user.login,
                        first_name=parsed_user.first_name,
                        last_name=parsed_user.last_name,
                        reason=f"Bundle/env '{bundle}/{env}' missing in latest file"
                    ))
                except Exception as e:
                    self.logger.debug(f"Regional cleanup: failed to disable {parsed_user.login} in {bundle}/{env}: {e}")

            if disable_count:
                self.logger.info(
                    f"Regional cleanup completed for {parsed_user.login}: disabled in {disable_count} environment(s)")

        except Exception as e:
            self.logger.debug(f"Regional cleanup failed for {parsed_user.login}: {e}")

    async def _check_TargetSystem_status(self, bundle: str, env: str) -> bool:
        try:
            await self.TargetSystem_service.check_api_status(bundle, env)
            await self.TargetSystem_service.check_TargetSystem_status(bundle, env)
            return True
        except Exception as e:
            self.logger.error(f"TargetSystem status check failed: {e}")
            return False

    async def _create_user_in_TargetSystem(self, parsed_user: ParsedUser, bundle: str, env: str, correlation_id: str = None):

        if self.config.engine.role_domain_logging_enabled:
            all_user_roles = []
            if parsed_user.roles:
                all_user_roles.extend(parsed_user.roles)
            if parsed_user.default_role:
                all_user_roles.append(parsed_user.default_role)

            if all_user_roles:
                domain_prefix_validation = await self.role_validator.validate_role_domain_prefix(
                    all_user_roles, parsed_user.domain
                )
                self.role_validator.log_role_domain_validation_results(
                    parsed_user.login, domain_prefix_validation, parsed_user.domain
                )

        user_request = TargetSystemUserRequest(
            user_id=parsed_user.login,
            first_name=parsed_user.first_name,
            last_name=parsed_user.last_name,
            domain=parsed_user.domain,
            roles=parsed_user.roles,
            default_role=parsed_user.default_role,
            associations=parsed_user.associations
        )
        await self.TargetSystem_service.create_new_user(user_request, bundle, env, correlation_id)

    def _has_changes(self, comparison_result: ComparisonResult) -> bool:
        return (
                bool(comparison_result.roles_to_add) or
                bool(comparison_result.roles_to_remove) or
                comparison_result.domain_update_required or
                bool(comparison_result.associations_to_add) or
                bool(comparison_result.associations_to_remove) or
                bool(comparison_result.default_role_update)
        )

    async def _store_reprocess_data_for_user(self, parsed_user: ParsedUser,
                                             request_type: str):
        try:
            domain = parsed_user.domain

            json_data = {}

            if domain:
                domain_roles = {}
                for role in parsed_user.roles:
                    domain_roles[role] = {
                        "defaulted": role == parsed_user.default_role
                    }

                domain_associations = []
                for association in parsed_user.associations:
                    domain_associations.append(association)

                json_data[domain] = {
                    "assignments": {
                        "roles": domain_roles,
                        "associations": domain_associations
                    }
                }

            from src.models.processing import ReprocessData
            reprocess_data = ReprocessData(
                user_id=parsed_user.login,
                bundle=parsed_user.bundle,
                env=parsed_user.env,
                region=parsed_user.region,
                json_data=json_data,
                request_type=request_type,
                first_name=parsed_user.first_name,
                last_name=parsed_user.last_name
            )

            if hasattr(self, '_current_file_path') and self._current_file_path:
                bundle_env = f"{parsed_user.bundle}_{parsed_user.env}"
                await self.file_service.reprocess_manager.add_reprocess_data(
                    self._current_file_path,
                    parsed_user.login,
                    bundle_env,
                    reprocess_data
                )
                self.logger.info(
                    f"Stored reprocess data for user {parsed_user.login} with request_type: {request_type}")
            else:
                self.logger.warning(
                    f"Cannot store reprocess data for user {parsed_user.login}: current file path not available")

        except Exception as e:
            self.logger.error(f"Failed to store reprocess data for user {parsed_user.login}: {e}")

    def _create_source_user_from_json(self, user_id: str, first_name: str, last_name: str, json_data: Dict[str, Any]):
        from ..models.IDENTITY_MANAGER import IdentityUser, UserDetail, Authorization, ApplicationInstance, ApplicationHierarchyData, \
            ApplicationHierarchy, AttributeValue
        from datetime import datetime

        user_detail = UserDetail(
            firstName=first_name,
            lastName=last_name
        )

        authorizations = []
        assignments = json_data.get("assignments", {})

        for domain, domain_data in assignments.items():
            app_instance = ApplicationInstance(name=domain)

            app_hierarchies = []
            roles = domain_data.get("roles", {})

            if roles:
                attribute_values = []
                for role_name, role_data in roles.items():
                    attr_value = AttributeValue(
                        id=role_name,
                        value=role_name,
                        valueName=role_name,
                        parentId=None,
                        defaulted=role_data.get("defaulted", False)
                    )
                    attribute_values.append(attr_value)

                app_hierarchy = ApplicationHierarchy(label=domain)

                app_hierarchy_data = ApplicationHierarchyData(
                    applicationHierarchy=app_hierarchy,
                    attributeValues=attribute_values
                )
                app_hierarchies.append(app_hierarchy_data)

            if app_hierarchies:
                authorization = Authorization(
                    applicationInstance=app_instance,
                    applicationHierarchies=app_hierarchies
                )
                authorizations.append(authorization)

        source_user = IdentityUser(
            id=user_id,
            login=user_id,
            created=datetime.utcnow(),
            updated=datetime.utcnow(),
            userDetail=user_detail,
            authorizations=authorizations
        )

        return source_user

    async def _process_user_data_for_bundle_env(self, user_id: str, bundle: str, env: str,
                                                json_data: Dict[str, Any], first_name: str, last_name: str,
                                                request_type: str = None, region: str = ""):
        user_correlation_id = str(uuid.uuid4())

        try:
            self.logger.info(
                f"Reprocessing user {user_id} for bundle {bundle} and environment {env} - skipping comparison, applying direct TargetSystem operations")

            domain_key = list(json_data.keys())[0] if json_data else "ACME"
            domain = domain_key

            parsed_user = ParsedUser(
                user_id=user_id,
                first_name=first_name,
                last_name=last_name,
                domain=domain,
                roles=[],
                default_role="",
                associations=[],
                bundle=bundle,
                env=env,
                region=region
            )

            all_roles = []
            all_associations = []
            default_role = None

            for domain_name, domain_data in json_data.items():
                self.logger.info(f"Processing domain {domain_name} for user {user_id}")
                assignments = domain_data.get("assignments", {})

                roles = assignments.get("roles", {})
                for role_name, role_data in roles.items():
                    all_roles.append(role_name)
                    self.logger.info(f"Found role {role_name} from domain {domain_name}")
                    if role_data.get("defaulted", False):
                        default_role = role_name
                        self.logger.info(f"Set default role: {role_name}")

                associations = assignments.get("associations", [])
                all_associations.extend(associations)
                if associations:
                    self.logger.info(f"Found {len(associations)} associations from domain {domain_name}")

            self.logger.info(f"Total roles extracted from all domains: {len(all_roles)} - {all_roles}")
            self.logger.info(
                f"Total associations extracted from all domains: {len(all_associations)} - {all_associations}")

            parsed_user.roles = all_roles
            parsed_user.associations = all_associations
            parsed_user.default_role = default_role or (all_roles[0] if all_roles else "")

            if not await self._check_TargetSystem_status(bundle, env):
                raise TargetSystemApiError(f"TargetSystem API is not available for {bundle}/{env}")

            TargetSystem_user = await self._get_user_data_from_TargetSystem(user_id, bundle, env, user_correlation_id)

            if TargetSystem_user is None:
                self.logger.info(f"Creating user {user_id} in TargetSystem for {bundle}/{env}")
                await self._create_user_in_TargetSystem(parsed_user, bundle, env, user_correlation_id)
                self.processing_results["users_processed"] += 1
            else:
                self.logger.info(
                    f"Applying direct TargetSystem operations for user {user_id} in {bundle}/{env} - no comparison needed")
                await self._apply_direct_TargetSystem_operations(parsed_user, bundle, env, user_correlation_id, request_type)
                self.processing_results["users_processed"] += 1

            self.logger.info(f"Successfully reprocessed user {user_id} for {bundle}/{env}")

        except Exception as e:
            error_msg = f"Error reprocessing user {user_id} for {bundle}/{env}: {e}"
            self.logger.error(error_msg)
            self.processing_results["errors"].append(error_msg)
            raise

    def _get_region_from_bundle(self, bundle: str) -> str:
        bundle_region_map = self.config.bundle_region_map

        for region_key, bundle_list in bundle_region_map.items():
            if isinstance(bundle_list, str):
                bundles = [b.strip() for b in bundle_list.split(',')]
            else:
                bundles = bundle_list if isinstance(bundle_list, list) else [bundle_list]

            if bundle in bundles:
                return region_key

        self.logger.warning(f"Bundle '{bundle}' not found in BUNDLE_REGION_MAP, using bundle as region")
        return bundle

    async def _validate_and_filter_roles(self, parsed_user: ParsedUser, bundle: str, env: str,
                                         request_type: str = None) -> Dict[str, Any]:
        validation_result = {
            'valid_roles': [],
            'invalid_roles_by_domain': {},
            'valid_default_role': None,
            'invalid_default_role': None
        }

        try:
            region_name = self._get_region_from_bundle(bundle)

            user_domain = parsed_user.domain
            self.logger.info(f"Validating roles for user {parsed_user.login} against user domain: {user_domain}")

            if parsed_user.roles:
                self.logger.info(f"Validating {len(parsed_user.roles)} roles: {parsed_user.roles}")

                domain_validation = await self.role_validator.validate_roles_for_domain(
                    parsed_user.roles, user_domain, bundle, env, region_name
                )

                validation_result['valid_roles'].extend(domain_validation['valid_roles'])

                if domain_validation['invalid_roles']:
                    validation_result['invalid_roles_by_domain'][user_domain] = domain_validation['invalid_roles']

            if parsed_user.default_role:
                self.logger.info(
                    f"Validating default role {parsed_user.default_role} for user {parsed_user.login} against user domain: {user_domain}")

                default_role_validation = await self.role_validator.validate_roles_for_domain(
                    [parsed_user.default_role], user_domain, bundle, env, region_name
                )

                if default_role_validation['valid_roles']:
                    validation_result['valid_default_role'] = parsed_user.default_role
                else:
                    validation_result['invalid_default_role'] = parsed_user.default_role
                    if user_domain not in validation_result['invalid_roles_by_domain']:
                        validation_result['invalid_roles_by_domain'][user_domain] = []

                    if parsed_user.default_role not in validation_result['invalid_roles_by_domain'][user_domain]:
                        validation_result['invalid_roles_by_domain'][user_domain].append(parsed_user.default_role)

            if validation_result['invalid_roles_by_domain']:
                await self.role_validator.store_invalid_roles(
                    validation_result['invalid_roles_by_domain'],
                    region_name,
                    f"user_{parsed_user.login}_{request_type}"
                )

                self.logger.warning(
                    f"Invalid roles found for user {parsed_user.login}: {validation_result['invalid_roles_by_domain']}")

            self.logger.info(
                f"Role validation completed for user {parsed_user.login}: {len(validation_result['valid_roles'])} valid roles, {sum(len(roles) for roles in validation_result['invalid_roles_by_domain'].values())} invalid roles")

            if self.config.engine.role_domain_logging_enabled:
                all_user_roles = []
                if parsed_user.roles:
                    all_user_roles.extend(parsed_user.roles)
                if parsed_user.default_role:
                    all_user_roles.append(parsed_user.default_role)

                if all_user_roles:
                    domain_prefix_validation = await self.role_validator.validate_role_domain_prefix(
                        all_user_roles, user_domain
                    )
                    self.role_validator.log_role_domain_validation_results(
                        parsed_user.login, domain_prefix_validation, user_domain
                    )

        except Exception as e:
            self.logger.error(f"Error during role validation for user {parsed_user.login}: {e}")
            validation_result['valid_roles'] = parsed_user.roles or []
            validation_result['valid_default_role'] = parsed_user.default_role

        return validation_result

    async def _apply_direct_TargetSystem_operations(self, parsed_user: ParsedUser, bundle: str, env: str,
                                           correlation_id: str = None, request_type: str = None):
        try:
            self.logger.info(
                f"Applying direct TargetSystem operations for user {parsed_user.login} with request_type: {request_type}")

            TargetSystem_service = self.TargetSystem_service if not self.config.TargetSystem.use_dynamic_api else self.dynamic_TargetSystem_service

            if request_type == "create_user_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before creation attempt")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if TargetSystem_user:
                    self.logger.info(f"User {parsed_user.login} already exists in TargetSystem. Checking domain.")
                    current_domain = getattr(TargetSystem_user, 'domain_name', None)

                    if current_domain == parsed_user.domain:
                        self.logger.info(f"User {parsed_user.login} is in the correct domain '{parsed_user.domain}'. Synchronizing data.")
                        TargetSystem_assignments = await self.TargetSystem_service.get_user_roles_and_associations(parsed_user.login, bundle, env, correlation_id)
                        comparison_result = self._build_comparison_from_parsed(parsed_user, TargetSystem_user, TargetSystem_assignments)
                        await self._set_user_roles(parsed_user, comparison_result, correlation_id, TargetSystem_user)
                    else:
                        self.logger.info(f"User {parsed_user.login} is in a different domain '{current_domain}'. Expected: '{parsed_user.domain}'.")
                        self.logger.info(f"Disabling user {parsed_user.login} in current domain '{current_domain}'")
                        await self.TargetSystem_service.disable_user(parsed_user.login, bundle, env, correlation_id)
                        self.logger.info(f"Creating user {parsed_user.login} in new domain '{parsed_user.domain}'")
                        await self._create_user_in_TargetSystem(parsed_user, bundle, env, correlation_id)
                else:
                    self.logger.info(f"User {parsed_user.login} not found in TargetSystem. Proceeding with creation.")
                    await self._create_user_in_TargetSystem(parsed_user, bundle, env, correlation_id)

            elif request_type == "enable_user_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before enable attempt")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for enable attempt. Attempting to create.")
                    await self._create_user_in_TargetSystem(parsed_user, bundle, env, correlation_id)
                else:
                    self.logger.info(f"Re-enabling user {parsed_user.login} in TargetSystem")
                    if parsed_user.roles or parsed_user.associations:
                        assignment_request = TargetSystemAssignmentRequest(
                            user_id=parsed_user.login,
                            roles=parsed_user.roles,
                            associations=parsed_user.associations
                        )
                        await TargetSystem_service.add_user_assignments(assignment_request, bundle, env, correlation_id)
                        self._log_assignment_success(parsed_user.login, "enable", parsed_user.roles,
                                                     parsed_user.associations)

            elif request_type == "assign_roles_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before role assignment")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for role assignment. Attempting to create.")
                    await self._create_user_in_TargetSystem(parsed_user, bundle, env, correlation_id)
                else:
                    if parsed_user.roles or parsed_user.associations:
                        if self.config.engine.check_roles_exist_in_TargetSystem:
                            validation_result = await self._validate_and_filter_roles(parsed_user, bundle, env, request_type)
                        else:
                            validation_result = {
                                'valid_roles': parsed_user.roles or [],
                                'valid_default_role': parsed_user.default_role,
                                'invalid_roles_by_domain': {},
                                'invalid_default_role': None
                            }

                        valid_roles = validation_result['valid_roles']

                        if valid_roles or parsed_user.associations:
                            assignment_request = TargetSystemAssignmentRequest(
                                user_id=parsed_user.login,
                                roles=valid_roles,
                                associations=parsed_user.associations
                            )

                            self.logger.info(
                                f"Adding assignments for user {parsed_user.login}: valid_roles={valid_roles}, associations={parsed_user.associations}")
                            await TargetSystem_service.add_user_assignments(assignment_request, bundle, env, correlation_id)
                            self._log_assignment_success(parsed_user.login, "add", valid_roles, parsed_user.associations)
                        else:
                            self.logger.warning(f"No valid roles or associations to assign for user {parsed_user.login}")

                        valid_default_role = validation_result['valid_default_role']
                        if valid_default_role:
                            default_role_request = TargetSystemDefaultRoleRequest(
                                user_id=parsed_user.login,
                                default_role=valid_default_role
                            )

                            self.logger.info(
                                f"Setting valid default role for user {parsed_user.login}: {valid_default_role}")
                            await TargetSystem_service.update_user_default_role(default_role_request, bundle, env, correlation_id)
                            self.logger.info(
                                f"Successfully set default role {valid_default_role} for user {parsed_user.login}")
                        elif parsed_user.default_role and validation_result['invalid_default_role']:
                            self.logger.warning(
                                f"Skipped invalid default role for user {parsed_user.login}: {validation_result['invalid_default_role']}")

                        if validation_result['invalid_roles_by_domain']:
                            self.logger.warning(
                                f"Skipped invalid roles for user {parsed_user.login}: {validation_result['invalid_roles_by_domain']}")

            elif request_type == "unassign_roles_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before role removal")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for role removal. Skipping.")
                else:
                    if parsed_user.roles or parsed_user.associations:
                        assignment_request = TargetSystemAssignmentRequest(
                            user_id=parsed_user.login,
                            roles=parsed_user.roles,
                            associations=parsed_user.associations
                        )

                        self.logger.info(
                            f"Removing assignments for user {parsed_user.login}: roles={parsed_user.roles}, associations={parsed_user.associations}")
                        await TargetSystem_service.remove_user_assignments(assignment_request, bundle, env, correlation_id)
                        self._log_assignment_success(parsed_user.login, "remove", parsed_user.roles,
                                                     parsed_user.associations)

            elif request_type == "update_default_role_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before updating default role")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for updating default role. Skipping.")
                else:
                    if parsed_user.default_role:
                        if self.config.engine.check_roles_exist_in_TargetSystem:
                            validation_result = await self._validate_and_filter_roles(parsed_user, bundle, env, request_type)
                        else:
                            validation_result = {
                                'valid_roles': parsed_user.roles or [],
                                'valid_default_role': parsed_user.default_role,
                                'invalid_roles_by_domain': {},
                                'invalid_default_role': None
                            }

                        valid_default_role = validation_result['valid_default_role']

                        if valid_default_role:
                            default_role_request = TargetSystemDefaultRoleRequest(
                                user_id=parsed_user.login,
                                default_role=valid_default_role
                            )

                            self.logger.info(
                                f"Setting valid default role for user {parsed_user.login}: {valid_default_role}")
                            await TargetSystem_service.update_user_default_role(default_role_request, bundle, env, correlation_id)
                            self.logger.info(
                                f"Successfully set default role {valid_default_role} for user {parsed_user.login}")
                        else:
                            self.logger.warning(
                                f"Default role {parsed_user.default_role} is invalid for user {parsed_user.login}, skipping default role assignment")

                        if validation_result['invalid_default_role']:
                            self.logger.warning(
                                f"Skipped invalid default role for user {parsed_user.login}: {validation_result['invalid_default_role']}")

            elif request_type == "disable_user_failed":
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before disable attempt")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for disable attempt. Skipping.")
                else:
                    self.logger.info(f"Disabling user {parsed_user.login} in TargetSystem")
                    await TargetSystem_service.disable_user(parsed_user.login, bundle, env, correlation_id)
                    self.logger.info(f"Successfully disabled user {parsed_user.login}")

            else:
                self.logger.info(f"Checking if user {parsed_user.login} exists in TargetSystem before applying default operations for request_type: {request_type}")
                TargetSystem_user = await self._get_user_data_from_TargetSystem(parsed_user.login, bundle, env, correlation_id)

                if not TargetSystem_user:
                    self.logger.warning(f"User {parsed_user.login} not found in TargetSystem for default operations. Attempting to create.")
                    await self._create_user_in_TargetSystem(parsed_user, bundle, env, correlation_id)
                else:
                    self.logger.info(f"Applying default operations with role validation for request_type: {request_type}")

                    if self.config.engine.check_roles_exist_in_TargetSystem:
                        validation_result = await self._validate_and_filter_roles(parsed_user, bundle, env, request_type)
                    else:
                        validation_result = {
                            'valid_roles': parsed_user.roles or [],
                            'valid_default_role': parsed_user.default_role,
                            'invalid_roles_by_domain': {},
                            'invalid_default_role': None
                        }

                    valid_roles = validation_result['valid_roles']
                    if valid_roles or parsed_user.associations:
                        assignment_request = TargetSystemAssignmentRequest(
                            user_id=parsed_user.login,
                            roles=valid_roles,
                            associations=parsed_user.associations
                        )

                        self.logger.info(
                            f"Adding assignments for user {parsed_user.login}: valid_roles={valid_roles}, associations={parsed_user.associations}")
                        await TargetSystem_service.add_user_assignments(assignment_request, bundle, env, correlation_id)
                        self._log_assignment_success(parsed_user.login, "add", valid_roles, parsed_user.associations)

                    valid_default_role = validation_result['valid_default_role']
                    if valid_default_role:
                        default_role_request = TargetSystemDefaultRoleRequest(
                            user_id=parsed_user.login,
                            default_role=valid_default_role
                        )

                        self.logger.info(f"Setting valid default role for user {parsed_user.login}: {valid_default_role}")
                        await TargetSystem_service.update_user_default_role(default_role_request, bundle, env, correlation_id)
                        self.logger.info(f"Successfully set default role {valid_default_role} for user {parsed_user.login}")
                    elif parsed_user.default_role and validation_result['invalid_default_role']:
                        self.logger.warning(
                            f"Skipped invalid default role for user {parsed_user.login}: {validation_result['invalid_default_role']}")

                    if validation_result['invalid_roles_by_domain']:
                        self.logger.warning(
                            f"Skipped invalid roles for user {parsed_user.login}: {validation_result['invalid_roles_by_domain']}")

            self.logger.info(f"Successfully applied direct TargetSystem operations for user {parsed_user.login}")

        except Exception as e:
            error_msg = f"Error applying direct TargetSystem operations for user {parsed_user.login}: {e}"
            self.logger.error(error_msg)
            self._log_assignment_error(parsed_user.login, "direct_operations", parsed_user.roles,
                                       parsed_user.associations, e, bundle, env)
            raise

    def _generate_execution_summary(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "execution_time": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "results": self.processing_results,
            "summary": {
                "total_files_processed": len(self.processing_results["successful_files"]) + len(
                    self.processing_results["failed_files"]),
                "successful_files": len(self.processing_results["successful_files"]),
                "failed_files": len(self.processing_results["failed_files"]),
                "users_processed": self.processing_results["users_processed"],
                "users_disabled": len(self.processing_results["users_disabled"]),
                "total_errors": len(self.processing_results["errors"])
            }
        }


class SyncService:

    def __init__(self, config: SyncConfig):
        self.engine = AccessSyncEngine(config)
        self.correlation_id = config.correlation_id or str(uuid.uuid4())

    async def run_full_sync(self, last_check: str = None) -> Dict[str, Any]:
        return await self.engine.execute_sync_engine(
            read_from_IDENTITY_MANAGER=True,
            last_check=last_check,
            correlation_id=self.correlation_id
        )

    async def process_existing_files(self) -> Dict[str, Any]:
        return await self.engine.execute_sync_engine(
            read_from_IDENTITY_MANAGER=False,
            correlation_id=self.correlation_id
        )

    async def process_single_file(self, file_path: str) -> ProcessingResult:
        return await self.engine.process_file(file_path)
