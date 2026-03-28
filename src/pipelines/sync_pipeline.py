
import sys
import os
import asyncio
import logging
import uuid
from pathlib import Path
from statistics import correlation
from typing import Optional

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

async def main():

    try:

        from src.services.sync_engine import AccessSyncEngine, SyncService
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

        logger.info("Starting Access Sync Engine Service...")
        logger.debug(f"Debug logging enabled: {config.logging.is_debug}")
        logger.debug(f"Log level: {config.logging.log_level}")
        logger.debug(f"Log format: {config.logging.log_format}")
        logger.info("Configuration loaded successfully")

        sync_service = SyncService(config)
        sync_service.correlation_id = correlation_id
        logger.info("Engine service initialized")

        if len(sys.argv) > 1:
            operation = sys.argv[1].lower()

            if operation == "full-sync":

                await sync_service.run_full_sync()

            elif operation == "process-existing":

                logger.info("Processing existing files")
                await sync_service.process_existing_files()

            elif operation == "process-file":

                if len(sys.argv) < 3:
                    logger.error("File path required for process-file operation")
                    return False
                file_path = sys.argv[2]
                logger.info(f"Processing single file: {file_path}")
                await sync_service.process_single_file(file_path)

            else:
                logger.error(f"Unknown operation: {operation}")
                print_usage()
                return False
        else:

            logger.info("No operation specified, running default full synchronization")
            await sync_service.run_full_sync()

        logger.info("Access Sync Engine Service completed successfully")
        return True

    except ImportError as e:

        try:
            logger.error(f"Import error: {e}")
        except NameError:
            print(f"Import error: {e}")
        return False
    except Exception as e:

        try:
            logger.error(f"Error running engine service: {e}", exc_info=True)
        except NameError:
            print(f"Error running engine service: {e}")
        return False

def print_usage():

    print("\nUsage:")
    print("  python run_sync_service.py")

def check_environment():

    from dotenv import load_dotenv
    load_dotenv()
    
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
    print("Access Sync Engine Service - Production Runner")
    print("=" * 80)

    if not check_environment():
        print("\n Environment check failed. Please set required environment variables.")
        print_usage()
        sys.exit(1)

    try:
        success = asyncio.run(main())

        if success:
            print("\n Access Sync Engine Service completed successfully!")
        else:
            print("\n Access Sync Engine Service failed.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n  Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        sys.exit(1)

    print("=" * 80)