
import aiohttp
import asyncio
import ssl
import uuid
from jinja2 import Environment, BaseLoader, Template
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..models.IDENTITY_MANAGER import (
    IdentityUser,
    IdentityManagerGraphQLResponse,
    IdentityManagerGraphQLRequest,
    ModifiedUsersResponse
)
from ..exceptions.base import (
    IdentityManagerConnectionError,
    IdentityManagerAuthenticationError,
    IdentityManagerGraphQLError,
    TemplateError,
    handle_api_errors
)
from ..config.settings import IdentityManagerConfig

GRAPHQL_QUERY_TEMPLATE = """query ModifiedUsers($lastCheck: String!) {
    modifiedUsers(lastCheck: $lastCheck) {
        users {
            id
            login
            created
            updated
            userDetail {
                firstName
                lastName
            }
            authorizations {
                applicationInstance {
                    name
                }
                applicationHierarchies {
                    applicationHierarchy {
                        label
                    }
                    attributeValues {
                        id
                        value
                        valueName
                        parentId
                        defaulted
                    }
                }
            }
        }
        total
    }
}""".strip()

class IdentityManagerClient:

    def __init__(self, config: IdentityManagerConfig):
        self.api_url = config.request_rest_api_url
        self.auth_token = config.request_rest_api_authorization
        self.timeout = config.request_rest_api_timeout
        self.verify_ssl = config.verify_ssl
        self.template_env = Environment(loader=BaseLoader())
        self.correlation_id = None

        self.client_timeout = aiohttp.ClientTimeout(total=self.timeout)

    def set_correlation_id(self, correlation_id: str):

        self.correlation_id = correlation_id

    async def __aenter__(self):

        ssl_context = None
        if not self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(limit=100, limit_per_host=30, ssl=ssl_context)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.client_timeout
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):

        if hasattr(self, 'session'):
            await self.session.close()

    def _prepare_headers(self) -> Dict[str, str]:

        headers = {
            "Content-Type": "application/json",
            "Authorization": self.auth_token
        }

        if self.correlation_id:
            headers["X-REQUEST-ID"] = self.correlation_id

        return headers

    def _sanitize_headers_for_logging(self, headers: Dict[str, str]) -> Dict[str, str]:

        sanitized = {}
        sensitive_keys = ['authorization', 'x-api-key', 'x-auth-token', 'bearer', 'token']
        
        for key, value in headers.items():
            key_lower = key.lower()
            if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):

                if len(value) > 10:
                    sanitized[key] = f"{value[:4]}...{value[-4:]}"
                else:
                    sanitized[key] = "***MASKED***"
            else:
                sanitized[key] = value
        
        return sanitized

    def _render_query_template(self, last_check: str) -> str:

        try:
            query_template = self.template_env.from_string(GRAPHQL_QUERY_TEMPLATE)
            return query_template.render(lastCheck=last_check)
        except Exception as e:
            raise TemplateError(f"Failed to render GraphQL query template: {e}")

    def _prepare_graphql_request(self, last_check: str) -> IdentityManagerGraphQLRequest:

        query = self._render_query_template(last_check)
        return IdentityManagerGraphQLRequest(
            query=query,
            variables={"lastCheck": last_check}
        )

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_modified_users(self, last_check: str) -> List[IdentityUser]:

        import logging
        logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
        
        logger.debug(f"Starting IdentityManager get_modified_users request with last_check: {last_check}")
        logger.debug(f"IdentityManager API URL: {self.api_url}")
        logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            logger.debug("Session not initialized, raising IdentityManagerConnectionError")
            raise IdentityManagerConnectionError("Client session not initialized. Use async context manager.")

        logger.debug("Preparing GraphQL request")
        graphql_request = self._prepare_graphql_request(last_check)
        logger.debug(f"GraphQL request prepared: query length={len(graphql_request.query)}, variables={graphql_request.variables}")
        
        logger.debug("Preparing request headers")
        headers = self._prepare_headers()
        logger.debug(f"Headers prepared: {list(headers.keys())}")

        logger.debug("=" * 60)
        logger.debug("IdentityManager FULL REQUEST DETAILS:")
        logger.debug(f"Method: POST")
        logger.debug(f"URL: {self.api_url}")
        logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        logger.debug(f"GraphQL Query: {graphql_request.query}")
        logger.debug(f"GraphQL Variables: {graphql_request.variables}")
        logger.debug(f"Request Body: {graphql_request.dict()}")
        logger.debug("=" * 60)

        try:
            logger.debug(f"Sending POST request to IdentityManager API: {self.api_url}")
            async with self.session.post(
                self.api_url,
                json=graphql_request.dict(),
                headers=headers
            ) as response:
                logger.debug(f"Received response with status: {response.status}")
                logger.debug(f"Response headers: {dict(response.headers)}")

                if response.status == 401:
                    logger.debug("Authentication failed (401), raising IdentityManagerAuthenticationError")
                    raise IdentityManagerAuthenticationError("IdentityManager authentication failed")
                elif response.status == 403:
                    logger.debug("Access forbidden (403), raising IdentityManagerAuthenticationError")
                    raise IdentityManagerAuthenticationError("IdentityManager access forbidden")
                elif response.status >= 500:
                    logger.debug(f"Server error ({response.status}), raising IdentityManagerConnectionError")
                    raise IdentityManagerConnectionError(f"IdentityManager server error: {response.status}")
                elif response.status != 200:
                    logger.debug(f"Request failed with status {response.status}, raising IdentityManagerConnectionError")
                    raise IdentityManagerConnectionError(f"IdentityManager request failed with status: {response.status}")

                logger.debug("HTTP status OK (200), parsing JSON response")

                response_data = await response.json()
                logger.debug(f"JSON response parsed, keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'non-dict response'}")

                logger.debug("=" * 60)
                logger.debug("IdentityManager FULL RESPONSE DETAILS:")
                logger.debug(f"Status Code: {response.status}")
                logger.debug(f"Response Headers: {dict(response.headers)}")
                logger.debug(f"Response Body: {response_data}")
                logger.debug("=" * 60)

                if "errors" in response_data:
                    logger.debug(f"GraphQL errors found in response: {response_data['errors']}")
                    error_messages = [error.get("message", "Unknown error") for error in response_data["errors"]]
                    logger.debug(f"Extracted error messages: {error_messages}")
                    raise IdentityManagerGraphQLError(f"GraphQL errors: {', '.join(error_messages)}")

                logger.debug("No GraphQL errors found, validating and parsing response")

                graphql_response = IdentityManagerGraphQLResponse(data=response_data.get("data", {}))
                modified_users_response = graphql_response.modified_users
                logger.debug(f"Response parsed successfully, users count: {len(modified_users_response.users)}")
                logger.debug(f"Modified users response: total_count={getattr(modified_users_response, 'total_count', 'not_available')}")

                logger.debug(f"IdentityManager get_modified_users completed successfully, returning {len(modified_users_response.users)} users")
                return modified_users_response.users

        except aiohttp.ClientError as e:
            logger.debug(f"aiohttp.ClientError caught: {str(e)}")
            raise IdentityManagerConnectionError(f"Failed to connect to IdentityManager: {e}")
        except asyncio.TimeoutError as e:
            logger.debug(f"Timeout error caught: {str(e)}")

            try:
                error_str = str(e)
                if not error_str or error_str.isspace():
                    error_message = f"IdentityManager request timed out ({type(e).__name__} - no error message provided)"
                else:
                    error_message = f"IdentityManager request timed out: {error_str}"
            except (TypeError, AttributeError):
                error_message = f"IdentityManager request timed out ({type(e).__name__} - error message unavailable)"
            raise IdentityManagerConnectionError(error_message)
        except asyncio.CancelledError as e:
            logger.debug(f"Request was cancelled: {str(e)}")
            raise IdentityManagerConnectionError("IdentityManager request was cancelled (timeout or external cancellation)")
        except Exception as e:
            logger.debug(f"Exception caught during IdentityManager request: {str(e)}", exc_info=True)
            if isinstance(e, (IdentityManagerConnectionError, IdentityManagerAuthenticationError, IdentityManagerGraphQLError)):
                logger.debug(f"Re-raising known exception type: {type(e).__name__}")
                raise
            logger.debug("Raising IdentityManagerGraphQLError for unexpected exception")

            try:
                error_str = str(e)
                if not error_str or error_str.isspace():
                    error_message = f"Unexpected {type(e).__name__} during IdentityManager request (no error message provided)"
                else:
                    error_message = f"Unexpected error during IdentityManager request: {error_str}"
            except (TypeError, AttributeError):
                error_message = f"Unexpected {type(e).__name__} during IdentityManager request (error message unavailable)"
            raise IdentityManagerGraphQLError(error_message)

    async def get_modified_users_with_metadata(self, last_check: str) -> ModifiedUsersResponse:

        import logging
        logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
        
        logger.debug(f"Starting IdentityManager get_modified_users_with_metadata request with last_check: {last_check}")
        logger.debug(f"IdentityManager API URL: {self.api_url}")
        logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            logger.debug("Session not initialized, raising IdentityManagerConnectionError")
            raise IdentityManagerConnectionError("Client session not initialized. Use async context manager.")

        logger.debug("Preparing GraphQL request")
        graphql_request = self._prepare_graphql_request(last_check)
        logger.debug(f"GraphQL request prepared: query length={len(graphql_request.query)}, variables={graphql_request.variables}")
        
        logger.debug("Preparing request headers")
        headers = self._prepare_headers()
        logger.debug(f"Headers prepared: {list(headers.keys())}")

        logger.debug("=" * 60)
        logger.debug("IdentityManager FULL REQUEST DETAILS (with metadata):")
        logger.debug(f"Method: POST")
        logger.debug(f"URL: {self.api_url}")
        logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        logger.debug(f"GraphQL Query: {graphql_request.query}")
        logger.debug(f"GraphQL Variables: {graphql_request.variables}")
        logger.debug(f"Request Body: {graphql_request.dict()}")
        logger.debug("=" * 60)

        try:
            logger.debug(f"Sending POST request to IdentityManager API: {self.api_url}")
            async with self.session.post(
                self.api_url,
                json=graphql_request.dict(),
                headers=headers
            ) as response:
                logger.debug(f"Received response with status: {response.status}")
                logger.debug(f"Response headers: {dict(response.headers)}")

                if response.status != 200:
                    raise IdentityManagerConnectionError(f"IdentityManager request failed with status: {response.status}")

                response_data = await response.json()

                logger.debug("=" * 60)
                logger.debug("IdentityManager FULL RESPONSE DETAILS (with metadata):")
                logger.debug(f"Status Code: {response.status}")
                logger.debug(f"Response Headers: {dict(response.headers)}")
                logger.debug(f"Response Body: {response_data}")
                logger.debug("=" * 60)

                if "errors" in response_data:
                    error_messages = [error.get("message", "Unknown error") for error in response_data["errors"]]
                    raise IdentityManagerGraphQLError(f"GraphQL errors: {', '.join(error_messages)}")

                graphql_response = IdentityManagerGraphQLResponse(data=response_data.get("data", {}))
                return graphql_response.modified_users

        except aiohttp.ClientError as e:
            raise IdentityManagerConnectionError(f"Failed to connect to IdentityManager: {e}")
        except asyncio.TimeoutError as e:

            try:
                error_str = str(e)
                if not error_str or error_str.isspace():
                    error_message = f"IdentityManager request timed out ({type(e).__name__} - no error message provided)"
                else:
                    error_message = f"IdentityManager request timed out: {error_str}"
            except (TypeError, AttributeError):
                error_message = f"IdentityManager request timed out ({type(e).__name__} - error message unavailable)"
            raise IdentityManagerConnectionError(error_message)
        except asyncio.CancelledError as e:
            raise IdentityManagerConnectionError("IdentityManager request was cancelled (timeout or external cancellation)")
        except Exception as e:
            if isinstance(e, (IdentityManagerConnectionError, IdentityManagerAuthenticationError, IdentityManagerGraphQLError)):
                raise

            try:
                error_str = str(e)
                if not error_str or error_str.isspace():
                    error_message = f"Unexpected {type(e).__name__} during IdentityManager request (no error message provided)"
                else:
                    error_message = f"Unexpected error during IdentityManager request: {error_str}"
            except (TypeError, AttributeError):
                error_message = f"Unexpected {type(e).__name__} during IdentityManager request (error message unavailable)"
            raise IdentityManagerGraphQLError(error_message)

    async def test_connection(self) -> bool:

        try:

            test_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            await self.get_modified_users(test_timestamp)
            return True
        except Exception:
            return False

class IdentityManagerService:

    def __init__(self, config: IdentityManagerConfig):
        self.config = config

    async def fetch_modified_users(self, last_check: str, correlation_id: str = None) -> List[IdentityUser]:

        async with IdentityManagerClient(self.config) as client:
            if correlation_id:
                client.set_correlation_id(correlation_id)
            return await client.get_modified_users(last_check)

    async def fetch_modified_users_with_metadata(self, last_check: str, correlation_id: str = None) -> ModifiedUsersResponse:

        current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        import logging
        logger = logging.getLogger(f"{__name__}-{correlation_id or 'no-correlation-id'}")
        logger.info(f"Loading IdentityManager data for {last_check} - {current_time}")

        async with IdentityManagerClient(self.config) as client:
            if correlation_id:
                client.set_correlation_id(correlation_id)
            return await client.get_modified_users_with_metadata(last_check)

    async def test_connectivity(self, correlation_id: str = None) -> bool:

        async with IdentityManagerClient(self.config) as client:
            if correlation_id:
                client.set_correlation_id(correlation_id)
            return await client.test_connection()
