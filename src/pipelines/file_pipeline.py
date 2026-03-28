
import sys
import os
import asyncio
import logging
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

async def main():

    try:

        from src.clients.identity_manager import IdentityManagerService
        from src.services.file_processor import AsyncFileProcessor
        from src.config.settings import get_config

        config = await get_config()
        correlation_id = str(uuid.uuid4())
        config.correlation_id = correlation_id

        log_level = logging.DEBUG if config.logging.is_debug else getattr(logging, config.logging.log_level.upper(), logging.INFO)

        if config.logging.log_format.lower() == 'json':
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        else:
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        logging.basicConfig(
            level=log_level,
            format=log_format,
            force=True
        )
        logger = logging.getLogger(f"{__name__}-{correlation_id}")

        logger.info("Starting IdentityManager Data Loader...")
        logger.debug(f"Debug logging enabled: {config.logging.is_debug}")
        logger.debug(f"Log level: {config.logging.log_level}")
        logger.debug(f"Log format: {config.logging.log_format}")
        logger.info("Configuration loaded successfully")

        IDENTITY_MANAGER_service = IdentityManagerService(config.IDENTITY_MANAGER)
        file_processor = AsyncFileProcessor(config.database)
        logger.info("IdentityManager service and file processor initialized")

        if len(sys.argv) > 1:
            operation = sys.argv[1].lower()

            if operation == "test-connection":

                logger.info("Testing IdentityManager connectivity")
                await test_IDENTITY_MANAGER_connection(IDENTITY_MANAGER_service, correlation_id, logger)

            elif operation == "fetch-data":

                last_check = sys.argv[2] if len(sys.argv) > 2 else None
                logger.info(f"Fetching data from IdentityManager (last_check: {last_check})")
                await fetch_IDENTITY_MANAGER_data(IDENTITY_MANAGER_service, file_processor, last_check, correlation_id, logger)

            elif operation == "fetch-with-metadata":

                last_check = sys.argv[2] if len(sys.argv) > 2 else None
                logger.info(f"Fetching data with metadata from IdentityManager (last_check: {last_check})")
                await fetch_IDENTITY_MANAGER_data_with_metadata(IDENTITY_MANAGER_service, file_processor, last_check, correlation_id, logger)

            elif operation == "fetch-recent":

                hours_back = int(sys.argv[2]) if len(sys.argv) > 2 else 24
                logger.info(f"Fetching recent data from IdentityManager (last {hours_back} hours)")
                await fetch_recent_data(IDENTITY_MANAGER_service, file_processor, hours_back, correlation_id, logger)

            else:
                logger.error(f"Unknown operation: {operation}")
                print_usage()
                return False
        else:

            logger.info("No operation specified, running default: test connection and fetch recent data")
            await test_IDENTITY_MANAGER_connection(IDENTITY_MANAGER_service, correlation_id, logger)
            await fetch_recent_data(IDENTITY_MANAGER_service, file_processor, 24, correlation_id, logger)

        logger.info("IdentityManager Data Loader completed successfully")
        return True

    except ImportError as e:

        try:
            logger.error(f"Import error: {e}")
        except NameError:
            print(f"Import error: {e}")
        return False
    except Exception as e:

        try:
            logger.error(f"Error running IdentityManager data loader: {e}", exc_info=True)
        except NameError:
            print(f"Error running IdentityManager data loader: {e}")
        return False

async def test_IDENTITY_MANAGER_connection(IDENTITY_MANAGER_service: 'IdentityManagerService', correlation_id: str, logger):

    try:
        result = await IDENTITY_MANAGER_service.test_connectivity(correlation_id)
        if result:
            logger.info(" IdentityManager connectivity test successful")
            print(" IdentityManager connectivity test successful")
        else:
            logger.error(" IdentityManager connectivity test failed")
            print(" IdentityManager connectivity test failed")
    except Exception as e:
        logger.error(f" IdentityManager connectivity test failed: {e}")
        print(f" IdentityManager connectivity test failed: {e}")

def format_datetime_for_IDENTITY_MANAGER(dt: datetime) -> str:

    if dt.tzinfo is not None:

        dt_utc = dt.utctimetuple()
        return datetime(*dt_utc[:6]).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

async def get_last_fetch_timestamp(status_manager: 'FileStatusManager', logger) -> Optional[datetime]:

    try:

        current_date = datetime.utcnow()

        for days_back in range(30):
            check_date = current_date - timedelta(days=days_back)

            try:
                status_data = await status_manager.load_status_file(check_date)

                if status_data.records:

                    record_ids = [int(record_id) for record_id in status_data.records.keys()]
                    highest_record_id = max(record_ids)
                    last_record = status_data.records[str(highest_record_id)]

                    timestamp_to_use = None
                    timestamp_source = None

                    if last_record.start_time:
                        timestamp_to_use = last_record.start_time
                        timestamp_source = "start_time"
                    elif last_record.end_time:
                        timestamp_to_use = last_record.end_time
                        timestamp_source = "end_time"

                    if timestamp_to_use:
                        logger.info(f"Found last record (ID: {highest_record_id}) in last status file ({check_date.strftime('%Y-%m-%d')})")
                        logger.info(f"Using {timestamp_source}: {timestamp_to_use}")
                        return timestamp_to_use

            except Exception as e:

                logger.debug(f"Could not load status file for {check_date.strftime('%Y-%m-%d')}: {e}")
                continue

        logger.info("No previous records found in status files")
        return None

    except Exception as e:
        logger.error(f"Error getting last fetch timestamp: {e}")
        return None

async def fetch_IDENTITY_MANAGER_data(IDENTITY_MANAGER_service: 'IdentityManagerService', file_processor: 'AsyncFileProcessor',
                           last_check: Optional[str], correlation_id: str, logger):

    from src.services.file_processor import FileStatusManager
    from src.models.processing import FileStatus

    status_manager = FileStatusManager(file_processor)
    record_id = None
    execution_start_time = datetime.utcnow()

    try:
        if last_check is None:

            last_fetch_timestamp = await get_last_fetch_timestamp(status_manager, logger)

            if last_fetch_timestamp:
                last_check = format_datetime_for_IDENTITY_MANAGER(last_fetch_timestamp)
                logger.info(f"Using last fetch timestamp from status file: {last_check}")
            else:
                default_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                last_check = format_datetime_for_IDENTITY_MANAGER(default_time)
                logger.info(f"No previous fetch found, using default last_check: {last_check}")

        logger.info(f"Fetching modified users from IdentityManager since: {last_check}")
        users_data = await IDENTITY_MANAGER_service.fetch_modified_users(last_check, correlation_id)

        if users_data:

            timestamp = datetime.utcnow()
            file_path = await file_processor.save_IDENTITY_MANAGER_response(users_data, timestamp)
            logger.info(f" Data saved to: {file_path}")
            print(f" Data saved to: {file_path}")

            file_record_id = await status_manager.add_new_file_record(file_path, timestamp)
            logger.info(f"Created status record {file_record_id} for new file: {file_path} with status NEW")

            user_count = len(users_data)
            logger.info(f" Fetched {user_count} users")
            print(f" Fetched {user_count} users")
        else:
            logger.info("No data received from IdentityManager")
            print("No data received from IdentityManager")

            record_id = await status_manager.add_new_file_record("none", execution_start_time)
            await status_manager.update_file_status(
                record_id, 
                FileStatus.EMPTY, 
                error_message="no data received from IdentityManager",
                timestamp=execution_start_time
            )
            logger.info(f"Created empty status record {record_id} to track no data result")

    except Exception as e:
        logger.error(f" Failed to fetch data from IdentityManager: {e}")
        print(f" Failed to fetch data from IdentityManager: {e}")

        error_record_id = await status_manager.add_new_file_record("none", execution_start_time)
        await status_manager.update_file_status(
            error_record_id, 
            FileStatus.ERROR, 
            error_message=str(e),
            timestamp=execution_start_time
        )
        logger.info(f"Created error status record {error_record_id} to track fetch failure")

        raise

async def fetch_IDENTITY_MANAGER_data_with_metadata(IDENTITY_MANAGER_service: 'IdentityManagerService', file_processor: 'AsyncFileProcessor',
                                         last_check: Optional[str], correlation_id: str, logger):

    from src.services.file_processor import FileStatusManager
    from src.models.processing import FileStatus

    status_manager = FileStatusManager(file_processor)
    record_id = None
    execution_start_time = datetime.utcnow()

    try:
        if last_check is None:

            last_fetch_timestamp = await get_last_fetch_timestamp(status_manager, logger)

            if last_fetch_timestamp:
                last_check = format_datetime_for_IDENTITY_MANAGER(last_fetch_timestamp)
                logger.info(f"Using last fetch timestamp from status file: {last_check}")
            else:
                default_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                last_check = format_datetime_for_IDENTITY_MANAGER(default_time)
                logger.info(f"No previous fetch found, using default last_check: {last_check}")

        logger.info(f"Fetching modified users with metadata from IdentityManager since: {last_check}")
        users_data = await IDENTITY_MANAGER_service.fetch_modified_users_with_metadata(last_check, correlation_id)

        if users_data:

            timestamp = datetime.utcnow()
            file_path = await file_processor.save_IDENTITY_MANAGER_response(users_data, timestamp)
            logger.info(f" Data with metadata saved to: {file_path}")
            print(f" Data with metadata saved to: {file_path}")

            file_record_id = await status_manager.add_new_file_record(file_path, timestamp)
            logger.info(f"Created status record {file_record_id} for new file: {file_path} with status NEW")

            user_count = len(users_data.users)
            total_count = users_data.total
            logger.info(f" Fetched {user_count} users (total available: {total_count})")
            print(f" Fetched {user_count} users (total available: {total_count})")
        else:
            logger.info("No data received from IdentityManager")
            print("No data received from IdentityManager")

            record_id = await status_manager.add_new_file_record("none", execution_start_time)
            await status_manager.update_file_status(
                record_id, 
                FileStatus.EMPTY, 
                error_message="no data received from IdentityManager",
                timestamp=execution_start_time
            )
            logger.info(f"Created empty status record {record_id} to track no data result")

    except Exception as e:
        logger.error(f" Failed to fetch data with metadata from IdentityManager: {e}")
        print(f" Failed to fetch data with metadata from IdentityManager: {e}")

        error_record_id = await status_manager.add_new_file_record("none", execution_start_time)
        await status_manager.update_file_status(
            error_record_id, 
            FileStatus.ERROR, 
            error_message=str(e),
            timestamp=execution_start_time
        )
        logger.info(f"Created error status record {error_record_id} to track fetch failure")

        raise

async def fetch_recent_data(IDENTITY_MANAGER_service: 'IdentityManagerService', file_processor: 'AsyncFileProcessor',
                           hours_back: int, correlation_id: str, logger):

    from src.services.file_processor import FileStatusManager
    from src.models.processing import FileStatus

    status_manager = FileStatusManager(file_processor)
    record_id = None
    execution_start_time = datetime.utcnow()

    try:

        last_check_time = datetime.utcnow() - timedelta(hours=hours_back)
        last_check = format_datetime_for_IDENTITY_MANAGER(last_check_time)

        logger.info(f"Fetching data from last {hours_back} hours (since: {last_check})")
        users_data = await IDENTITY_MANAGER_service.fetch_modified_users_with_metadata(last_check, correlation_id)

        if users_data:

            timestamp = datetime.utcnow()
            file_path = await file_processor.save_IDENTITY_MANAGER_response(users_data, timestamp)
            logger.info(f" Recent data saved to: {file_path}")
            print(f" Recent data saved to: {file_path}")

            file_record_id = await status_manager.add_new_file_record(file_path, timestamp)
            logger.info(f"Created status record {file_record_id} for new file: {file_path} with status NEW")

            user_count = len(users_data.users)
            total_count = users_data.total
            logger.info(f" Fetched {user_count} users from last {hours_back} hours (total available: {total_count})")
            print(f" Fetched {user_count} users from last {hours_back} hours (total available: {total_count})")
        else:
            logger.info(f"No data found in last {hours_back} hours")
            print(f"No data found in last {hours_back} hours")

            record_id = await status_manager.add_new_file_record("none", execution_start_time)
            await status_manager.update_file_status(
                record_id, 
                FileStatus.EMPTY, 
                error_message="no data received from IdentityManager",
                timestamp=execution_start_time
            )
            logger.info(f"Created empty status record {record_id} to track no data result")

    except Exception as e:
        logger.error(f"Failed to fetch recent data from IdentityManager: {e}")
        print(f"Failed to fetch recent data from IdentityManager: {e}")

        error_record_id = await status_manager.add_new_file_record("none", execution_start_time)
        await status_manager.update_file_status(
            error_record_id, 
            FileStatus.ERROR, 
            error_message=str(e),
            timestamp=execution_start_time
        )
        logger.info(f"Created error status record {error_record_id} to track fetch failure")

        raise

def print_usage():

    print("\nUsage:")
    print("  python run_IDENTITY_MANAGER_loader.py")


def check_environment():

    use_vault = os.getenv("USE_VAULT", "true").lower() == "true"

    if use_vault:
        vault_url = os.getenv("VAULT_URL")
        vault_token = os.getenv("VAULT_TOKEN")

        if not vault_url:
            print("VAULT_URL environment variable is required when USE_VAULT=true")
            return False
        if not vault_token:
            print("VAULT_TOKEN environment variable is required when USE_VAULT=true")
            return False

        print(f"Vault configuration: {vault_url}")
    else:
        print("Using environment variables for configuration")

    return True

if __name__ == "__main__":
    print("=" * 80)
    print("IdentityManager Data Loader")
    print("=" * 80)

    if len(sys.argv) > 1 and sys.argv[1].lower() in ["help", "--help", "-h"]:
        print_usage()
        sys.exit(0)

    if not check_environment():
        print("\n Environment check failed. Please set required environment variables.")
        print_usage()
        sys.exit(1)

    try:
        success = asyncio.run(main())

        if success:
            print("\n IdentityManager Data Loader completed successfully!")
        else:
            print("\n IdentityManager Data Loader failed.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n  Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        sys.exit(1)

    print("=" * 80)
