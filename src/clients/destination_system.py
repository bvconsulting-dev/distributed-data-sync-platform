import aiohttp
import json
import ssl
import uuid
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..models.TargetSystem import (
	TargetUser,
	TargetSystemUserRequest,
	TargetSystemUserAssignments,
	TargetSystemAssignmentRequest,
	TargetSystemDefaultRoleRequest,
	TargetSystemApiResponse,
	TargetSystemTransmissionResponse,
	TargetSystemDomainsResponse,
	TargetSystemStatusResponse
)
from ..exceptions.base import (
    TargetSystemApiError,
    TargetSystemConnectionError,
    TargetSystemAuthenticationError,
    VaultConnectionError,
    handle_api_errors
)
from ..config.settings import TargetSystemConfig, VaultConfigLoader


class TargetSystemClient:

    def __init__(self, config: TargetSystemConfig, correlation_id: str = None):
        self.base_url = config.request_rest_api_url.rstrip('/')
        self.timeout = config.request_rest_api_timeout
        self.verify_ssl = config.verify_ssl
        self.dry_run_mode = config.dry_run_mode
        self.correlation_id = correlation_id
        if not self.correlation_id:
            self.correlation_id = f"disp-TargetSystem_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        elif not self.correlation_id.startswith("disp-"):
            self.correlation_id = f"disp-{self.correlation_id}"

        try:
            self.base_headers = json.loads(config.request_rest_api_header_value)
        except json.JSONDecodeError:
            raise TargetSystemApiError("Invalid TargetSystem API header configuration")

        self.headers = self.base_headers.copy()

        self.client_timeout = aiohttp.ClientTimeout(total=self.timeout)

        self.logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

    def set_correlation_id(self, correlation_id: str):
        if correlation_id and not correlation_id.startswith("disp-"):
            correlation_id = f"disp-{correlation_id}"
            
        self.headers = self.base_headers.copy()
        self.headers['X-REQUEST-ID'] = correlation_id

        if hasattr(self, 'session') and self.session:
            self.session._default_headers.update({'X-REQUEST-ID': correlation_id})

    async def __aenter__(self):
        ssl_context = None
        if not self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(limit=100, limit_per_host=30, ssl=ssl_context)
        
        if self.correlation_id:
            self.headers['X-REQUEST-ID'] = self.correlation_id
            
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.client_timeout,
            headers=self.headers
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'session'):
            await self.session.close()

    def _prepare_params(self, bundle: str, env: str) -> Dict[str, str]:
        return {"bundle": bundle, "env": env}

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

    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        if response.status == 401:
            raise TargetSystemAuthenticationError("TargetSystem authentication failed")
        elif response.status == 403:
            raise TargetSystemAuthenticationError("TargetSystem access forbidden")
        elif response.status >= 500:
            raise TargetSystemConnectionError(f"TargetSystem server error: {response.status}")

        try:
            response_data = await response.json()
        except Exception as e:
            try:
                response_text = await response.text()
                self.logger.error(f"Failed to parse TargetSystem response as JSON. Status: {response.status}, Response text: {response_text}")
                raise TargetSystemApiError(f"Failed to parse TargetSystem response: {e}. Response text: {response_text}")
            except Exception:
                raise TargetSystemApiError(f"Failed to parse TargetSystem response: {e}")

        return_code = response_data.get("return_code")
        response_status = response_data.get("status")

        if response.status != 200 or response_status == "error":
            message = response_data.get("message", f"Request failed with status {response.status}")
            error_code = response_data.get("code", response.status)
            error_status = response_status or "error"
            error_data = response_data.get("data", {})
            
            error_log_msg = f"TargetSystem API error response - Status: {response.status}, Code: {error_code}, Message: {message}"
            if return_code:
                error_log_msg += f", return_code: {return_code}"
            
            self.logger.warning(error_log_msg)
            if error_data:
                self.logger.error(f"TargetSystem API error data: {error_data}")
            self.logger.warning(f"Full response body: {response_data}")
            
            detailed_message = f"TargetSystem API error: {message}"
            if error_code and error_code != response.status:
                detailed_message += f" (Code: {error_code})"
            if return_code:
                detailed_message += f" (return_code: {return_code})"
            if error_data:
                if isinstance(error_data, dict):
                    error_details = []
                    for key, value in error_data.items():
                        if key.lower() in ['error', 'details', 'reason', 'description']:
                            error_details.append(f"{key}: {value}")
                    if error_details:
                        detailed_message += f" - {', '.join(error_details)}"
                else:
                    detailed_message += f" - Data: {error_data}"
            
            raise TargetSystemApiError(detailed_message)

        return response_data

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_users(self, bundle: str, env: str) -> List[TargetUser]:
        if not hasattr(self, 'session'):
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        params = self._prepare_params(bundle, env)
        url = f"{self.base_url}/users"

        headers = dict(self.session.headers) if hasattr(self.session, 'headers') else {}
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem FULL REQUEST DETAILS:")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        self.logger.debug(f"Parameters: {params}")
        self.logger.debug(f"Request Body: None (GET request)")
        self.logger.debug("=" * 60)

        try:
            self.logger.debug(f"Sending GET request to TargetSystem API: {url}")
            async with self.session.get(url, params=params) as response:
                self.logger.debug(f"Received response with status: {response.status}")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                response_data = await self._handle_response(response)

                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem FULL RESPONSE DETAILS:")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)

                users_data = response_data.get("data", [])
                return [TargetUser(**user_data) for user_data in users_data]

        except aiohttp.ClientError as e:
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def create_user(self, user_request: TargetSystemUserRequest, bundle: str, env: str) -> TargetSystemApiResponse:
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would create user in TargetSystem - Bundle: {bundle}, Env: {env}")
            self.logger.info(f"[DRY RUN] Request payload: {user_request.dict()}")
            return TargetSystemApiResponse(
                message="DRY RUN: User creation request logged successfully",
                code=200,
                status="success",
                data={"user_id": f"dry_run_user_{uuid.uuid4().hex[:8]}"}
            )

        if not hasattr(self, 'session'):
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        params = self._prepare_params(bundle, env)
        url = f"{self.base_url}/users"
        request_body = user_request.dict()

        headers = dict(self.session.headers) if hasattr(self.session, 'headers') else {}
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem FULL REQUEST DETAILS:")
        self.logger.debug(f"Method: PUT")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        self.logger.debug(f"Parameters: {params}")
        self.logger.debug(f"Request Body: {request_body}")
        self.logger.debug("=" * 60)

        try:
            self.logger.debug(f"Sending POST request to TargetSystem API: {url}")
            async with self.session.put(
                url,
                json=request_body,
                params=params
            ) as response:
                self.logger.debug(f"Received response with status: {response.status}")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                response_data = await self._handle_response(response)

                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem FULL RESPONSE DETAILS (create_user):")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)

                return TargetSystemApiResponse(**response_data)

        except aiohttp.ClientError as e:
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def add_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str) -> TargetSystemApiResponse:
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would add user assignments in TargetSystem - Bundle: {bundle}, Env: {env}")
            self.logger.info(f"[DRY RUN] Request payload: {assignment_request.dict()}")
            return TargetSystemApiResponse(
                message="DRY RUN: User assignments addition request logged successfully",
                code=200,
                status="success",
                data={"assignment_id": f"dry_run_assignment_{uuid.uuid4().hex[:8]}"}
            )

        if not hasattr(self, 'session'):
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        params = self._prepare_params(bundle, env)
        url = f"{self.base_url}/users/assignments"
        request_body = assignment_request.dict()

        headers = dict(self.session.headers) if hasattr(self.session, 'headers') else {}
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem FULL REQUEST DETAILS:")
        self.logger.debug(f"Method: POST")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        self.logger.debug(f"Parameters: {params}")
        self.logger.debug(f"Request Body: {request_body}")
        self.logger.debug("=" * 60)

        try:
            self.logger.debug(f"Sending POST request to TargetSystem API: {url}")
            async with self.session.post(
                url,
                json=request_body,
                params=params
            ) as response:
                self.logger.debug(f"Received response with status: {response.status}")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                response_data = await self._handle_response(response)

                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem FULL RESPONSE DETAILS (add_user_assignments):")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)

                return TargetSystemApiResponse(**response_data)

        except aiohttp.ClientError as e:
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def remove_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str) -> TargetSystemApiResponse:
        self.logger.debug(f"Starting TargetSystem remove_user_assignments request - Bundle: {bundle}, Env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        self.logger.debug(f"Assignment request data: {assignment_request.dict()}")
        
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would remove user assignments in TargetSystem - Bundle: {bundle}, Env: {env}")
            self.logger.info(f"[DRY RUN] Request payload: {assignment_request.dict()}")
            return TargetSystemApiResponse(
                message="DRY RUN: User assignments removal request logged successfully",
                code=200,
                status="success",
                data={"assignment_id": f"dry_run_removal_{uuid.uuid4().hex[:8]}"}
            )

        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/assignments"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem REMOVE USER ASSIGNMENTS REQUEST")
        self.logger.debug(f"Method: DELETE")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug(f"JSON Payload: {assignment_request.dict()}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.delete(
                url,
                json=assignment_request.dict(),
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem REMOVE USER ASSIGNMENTS RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = TargetSystemApiResponse(**response_data)
                self.logger.debug(f"TargetSystem remove_user_assignments completed successfully")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem remove_user_assignments: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem remove_user_assignments: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def update_user_default_role(self, role_request: TargetSystemDefaultRoleRequest, bundle: str, env: str) -> TargetSystemApiResponse:
        self.logger.debug(f"Starting TargetSystem update_user_default_role request - Bundle: {bundle}, Env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        self.logger.debug(f"Role request data: {role_request.dict()}")
        
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would update user default role in TargetSystem - Bundle: {bundle}, Env: {env}")
            self.logger.info(f"[DRY RUN] Request payload: {role_request.dict()}")
            return TargetSystemApiResponse(
                message="DRY RUN: User default role update request logged successfully",
                code=200,
                status="success",
                data={"role_update_id": f"dry_run_role_{uuid.uuid4().hex[:8]}"}
            )

        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/default_role"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem UPDATE USER DEFAULT ROLE REQUEST")
        self.logger.debug(f"Method: PATCH")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug(f"JSON Payload: {role_request.dict()}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.patch(
                url,
                json=role_request.dict(),
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem UPDATE USER DEFAULT ROLE RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = TargetSystemApiResponse(**response_data)
                self.logger.debug(f"TargetSystem update_user_default_role completed successfully")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem update_user_default_role: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem update_user_default_role: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_user(self, user_id: str, bundle: str, env: str) -> Optional[TargetUser]:
        self.logger.debug(f"Starting TargetSystem get_user request for user_id: {user_id}, bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/{user_id}"
        self.logger.debug(f"Request URL: {url}")

        headers = dict(self.session.headers) if hasattr(self.session, 'headers') else {}
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem FULL REQUEST DETAILS:")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(headers)}")
        self.logger.debug(f"Parameters: {params}")
        self.logger.debug(f"Request Body: None (GET request)")
        self.logger.debug("=" * 60)

        try:
            self.logger.debug(f"Sending GET request to TargetSystem API: {url}")
            async with self.session.get(url, params=params) as response:
                self.logger.debug(f"Received response with status: {response.status}")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                
                if response.status == 500:
                    self.logger.debug(f"Received 500 status for get_user - interpreting as user {user_id} doesn't exist")
                    return None
                
                self.logger.debug("Processing response through _handle_response")
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response data keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'non-dict response'}")
                
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem FULL RESPONSE DETAILS (get_user):")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                user_data = response_data.get("data", {})
                self.logger.debug(f"Extracted user data: {list(user_data.keys()) if isinstance(user_data, dict) else 'non-dict user_data'}")
                
                if not user_data:
                    self.logger.debug("No user data found in response")
                else:
                    self.logger.debug(f"User data found: user_id={user_data.get('user_id', 'not_found')}, enabled={user_data.get('enabled', 'not_found')}")
                
                TargetSystem_user = TargetUser(**user_data)
                self.logger.debug(f"TargetSystem get_user completed successfully for user: {user_id}")
                return TargetSystem_user

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem get_user: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem get_user: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def delete_user(self, user_id: str, bundle: str, env: str) -> TargetSystemApiResponse:
        self.logger.debug(f"Starting TargetSystem delete_user request for user_id: {user_id}, bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would delete user in TargetSystem - User ID: {user_id}, Bundle: {bundle}, Env: {env}")
            return TargetSystemApiResponse(
                message="DRY RUN: User deletion request logged successfully",
                code=200,
                status="success",
                data={"deleted_user_id": user_id}
            )

        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/{user_id}"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem DELETE USER REQUEST")
        self.logger.debug(f"Method: DELETE")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.delete(
                url,
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem DELETE USER RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = TargetSystemApiResponse(**response_data)
                self.logger.debug(f"TargetSystem delete_user completed successfully for user: {user_id}")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem delete_user: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem delete_user: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def disable_user(self, user_id: str, bundle: str, env: str) -> TargetSystemApiResponse:
        self.logger.debug(f"Starting TargetSystem disable_user request for user_id: {user_id}, bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if self.dry_run_mode:
            self.logger.info(f"[DRY RUN] Would disable user in TargetSystem - User ID: {user_id}, Bundle: {bundle}, Env: {env}")
            return TargetSystemApiResponse(
                message="DRY RUN: User disable request logged successfully",
                code=200,
                status="success",
                data={"disabled_user_id": user_id}
            )

        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/{user_id}/disable"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem DISABLE USER REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.post(
                url,
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem DISABLE USER RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = TargetSystemApiResponse(**response_data)
                self.logger.debug(f"TargetSystem disable_user completed successfully for user: {user_id}")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem disable_user: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem disable_user: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_user_assignments(self, user_id: str, bundle: str, env: str) -> TargetSystemUserAssignments:
        self.logger.debug(f"Starting TargetSystem get_user_assignments request for user_id: {user_id}, bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/users/{user_id}/assignments"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem GET USER ASSIGNMENTS REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.get(
                url,
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem GET USER ASSIGNMENTS RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                assignments_data = response_data.get("data", {})
                result = TargetSystemUserAssignments(**assignments_data)
                self.logger.debug(f"TargetSystem get_user_assignments completed successfully for user: {user_id}")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem get_user_assignments: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem get_user_assignments: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_transmission(self, transmission_id: str, bundle: str, env: str) -> Dict[str, Any]:
        self.logger.debug(f"Starting TargetSystem get_transmission request for transmission_id: {transmission_id}, bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/transmission/{transmission_id}"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem GET TRANSMISSION REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.get(
                url,
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem GET TRANSMISSION RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = response_data.get("data", {})
                self.logger.debug(f"TargetSystem get_transmission completed successfully for transmission: {transmission_id}")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem get_transmission: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem get_transmission: {str(e)}", exc_info=True)
            raise

    @handle_api_errors(max_retries=3, backoff_factor=2.0)
    async def get_domains_and_roles(self, bundle: str, env: str) -> Dict[str, List[str]]:
        self.logger.debug(f"Starting TargetSystem get_domains_and_roles request - bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/domains"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem GET DOMAINS AND ROLES REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.get(
                url,
                params=params
            ) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem GET DOMAINS AND ROLES RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                
                response_data = await self._handle_response(response)
                self.logger.debug(f"Response Body: {response_data}")
                self.logger.debug("=" * 60)
                
                result = response_data.get("data", {})
                self.logger.debug(f"TargetSystem get_domains_and_roles completed successfully")
                return result

        except aiohttp.ClientError as e:
            self.logger.debug(f"aiohttp.ClientError caught during TargetSystem get_domains_and_roles: {str(e)}")
            raise TargetSystemConnectionError(f"Failed to connect to TargetSystem: {e}")
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem get_domains_and_roles: {str(e)}", exc_info=True)
            raise

    async def validate_roles_exist(self, roles: List[str], domain: str, bundle: str, env: str) -> List[str]:
        self.logger.info(f"Starting role validation for domain '{domain}' in bundle '{bundle}', env '{env}'")
        self.logger.info(f"Roles to validate: {roles} (count: {len(roles)})")
        
        if not roles:
            self.logger.info("No roles to validate, returning empty list")
            return []
        
        try:
            self.logger.debug(f"Fetching available domains and roles from TargetSystem")
            domains_roles = await self.get_domains_and_roles(bundle, env)
            self.logger.debug(f"Retrieved domains and roles: {domains_roles}")
            
            if domain not in domains_roles:
                self.logger.warning(f"Domain '{domain}' not found in TargetSystem. Available domains: {list(domains_roles.keys())}")
                self.logger.info(f"Role validation failed - domain not found. Returning empty list.")
                return []
            
            available_roles = domains_roles[domain]
            self.logger.info(f"Available roles in domain '{domain}': {available_roles} (count: {len(available_roles)})")
            
            valid_roles = []
            invalid_roles = []
            
            for role in roles:
                if role in available_roles:
                    valid_roles.append(role)
                    self.logger.debug(f"Role '{role}' is valid in domain '{domain}'")
                else:
                    invalid_roles.append(role)
                    self.logger.debug(f"Role '{role}' is invalid in domain '{domain}'")
            
            self.logger.info(f"Role validation completed for domain '{domain}':")
            self.logger.info(f"  - Valid roles: {valid_roles} (count: {len(valid_roles)})")
            
            if invalid_roles:
                self.logger.warning(f"  - Invalid roles found: {invalid_roles} (count: {len(invalid_roles)})")
                self.logger.warning(f"Invalid roles will be filtered out from operations")
            else:
                self.logger.info(f"  - All roles are valid")
            
            return valid_roles
            
        except Exception as e:
            self.logger.error(f"Role validation failed for domain '{domain}': {e}")
            self.logger.warning(f"Proceeding with all roles due to validation failure (fail-safe mode)")
            return roles

    async def check_api_status(self) -> bool:
        self.logger.debug(f"Starting TargetSystem check_api_status request")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        url = f"{self.base_url}/status"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem CHECK API STATUS REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.get(url) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem CHECK API STATUS RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug("=" * 60)
                
                if response.status != 200:
                    self.logger.debug(f"TargetSystem check_api_status completed - API accessible: False (Status {response.status})")
                    return False
                
                try:
                    response_data = await response.json()
                    response_status = response_data.get("status")
                    if response_status == "error":
                        self.logger.debug(f"TargetSystem check_api_status completed - API accessible: False (Body status: error)")
                        return False
                except Exception:
                    pass

                self.logger.debug(f"TargetSystem check_api_status completed - API accessible: True")
                return True
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem check_api_status: {str(e)}", exc_info=True)
            self.logger.debug(f"TargetSystem check_api_status completed - API accessible: False (due to exception)")
            return False

    async def check_TargetSystem_status(self, bundle: str, env: str) -> bool:
        self.logger.debug(f"Starting TargetSystem check_TargetSystem_status request - bundle: {bundle}, env: {env}")
        self.logger.debug(f"TargetSystem base URL: {self.base_url}")
        self.logger.debug(f"Correlation ID: {getattr(self, 'correlation_id', 'not_set')}")
        
        if not hasattr(self, 'session'):
            self.logger.debug("Session not initialized, raising TargetSystemConnectionError")
            raise TargetSystemConnectionError("Client session not initialized. Use async context manager.")

        self.logger.debug("Preparing request parameters")
        params = self._prepare_params(bundle, env)
        self.logger.debug(f"Request parameters prepared: {params}")
        
        url = f"{self.base_url}/status/TargetSystem"
        self.logger.debug(f"Request URL: {url}")
        
        self.logger.debug("=" * 60)
        self.logger.debug("TargetSystem CHECK TargetSystem STATUS REQUEST")
        self.logger.debug(f"Method: GET")
        self.logger.debug(f"URL: {url}")
        self.logger.debug(f"Headers: {self._sanitize_headers_for_logging(dict(self.session._default_headers))}")
        self.logger.debug(f"Params: {params}")
        self.logger.debug("=" * 60)

        try:
            async with self.session.get(url, params=params) as response:
                self.logger.debug("=" * 60)
                self.logger.debug("TargetSystem CHECK TargetSystem STATUS RESPONSE")
                self.logger.debug(f"Status Code: {response.status}")
                self.logger.debug(f"Response Headers: {dict(response.headers)}")
                self.logger.debug("=" * 60)
                
                if response.status != 200:
                    self.logger.debug(f"TargetSystem check_TargetSystem_status completed - TargetSystem accessible: False (Status {response.status})")
                    return False

                try:
                    response_data = await response.json()
                    response_status = response_data.get("status")
                    if response_status == "error":
                        self.logger.debug(f"TargetSystem check_TargetSystem_status completed - TargetSystem accessible: False (Body status: error)")
                        return False
                except Exception:
                    pass

                self.logger.debug(f"TargetSystem check_TargetSystem_status completed - TargetSystem accessible: True")
                return True
        except Exception as e:
            self.logger.debug(f"Exception caught during TargetSystem check_TargetSystem_status: {str(e)}", exc_info=True)
            self.logger.debug(f"TargetSystem check_TargetSystem_status completed - TargetSystem accessible: False (due to exception)")
            return False


class TargetSystemService:

    def __init__(self, config: TargetSystemConfig):
        self.config = config

    async def get_all_users(self, bundle: str, env: str, correlation_id: str = None) -> List[TargetUser]:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_users(bundle, env)

    async def create_new_user(self, user_request: TargetSystemUserRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.create_user(user_request, bundle, env)

    async def get_user_details(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetUser:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_user(user_id, bundle, env)

    async def get_user_roles_and_associations(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetSystemUserAssignments:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_user_assignments(user_id, bundle, env)

    async def add_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.add_user_assignments(assignment_request, bundle, env)

    async def remove_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.remove_user_assignments(assignment_request, bundle, env)

    async def update_user_default_role(self, role_request: TargetSystemDefaultRoleRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.update_user_default_role(role_request, bundle, env)


    async def disable_user(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.disable_user(user_id, bundle, env)

    async def check_api_status(self, correlation_id: str = None) -> bool:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.check_api_status()

    async def check_TargetSystem_status(self, bundle: str, env: str, correlation_id: str = None) -> bool:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.check_TargetSystem_status(bundle, env)

    async def test_connectivity(self, bundle: str, env: str, correlation_id: str = None) -> Dict[str, bool]:
        async with TargetSystemClient(self.config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            api_status = await client.check_api_status()
            TargetSystem_status = await client.check_TargetSystem_status(bundle, env)
            return {"api_accessible": api_status, "TargetSystem_accessible": TargetSystem_status}


class DynamicTargetSystemService:

    def __init__(self, base_config: TargetSystemConfig, vault_loader: VaultConfigLoader = None, bundle_region_map: Dict[str, str] = None):
        self.base_config = base_config
        self.vault_loader = vault_loader
        self.bundle_region_map = bundle_region_map or {}
        self._config_cache = {}

    @property
    def config(self) -> TargetSystemConfig:
        return self.base_config

    async def _get_dynamic_config(self, bundle: str, env: str) -> TargetSystemConfig:
        cache_key = f"{bundle}_{env}"
        if cache_key in self._config_cache:
            return self._config_cache[cache_key]

        try:
            import os
            use_vault = os.getenv("USE_VAULT", "false").lower() == "true"
            redis_use_dynamic = os.getenv("REDIS_USE_DYNAMIC_CONFIG", "false").lower() == "true"
            TargetSystem_use_dynamic = os.getenv("TargetSystem_USE_DYNAMIC_API", "false").lower() == "true"
            deployment_destination = os.getenv("DEPLOYMENT_TARGET", "OCI")

            if TargetSystem_use_dynamic and redis_use_dynamic and deployment_destination == "OCI":
                if use_vault:
                    if not self.vault_loader:
                        raise TargetSystemApiError("Vault loader not available for OCI dynamic configuration")

                    vault_config = await self.vault_loader.load_oci_api_config(bundle, env)

                    import json
                    header_dict = {"Content-Type": "application/json", "X-API-KEY": vault_config.get('token', '')}
                    api_config = {
                        'request_rest_api_url': vault_config.get('url', self.base_config.request_rest_api_url),
                        'request_rest_api_header_value': json.dumps(header_dict),
                        'request_rest_api_timeout': vault_config.get('timeout',
                                                                     self.base_config.request_rest_api_timeout),
                        'verify_ssl': self.base_config.verify_ssl,
                        'dry_run_mode': self.base_config.dry_run_mode
                    }
                else:
                    from ..config.settings import VaultConfigLoader
                    env_config = VaultConfigLoader.load_env_api_config(bundle, env, self.bundle_region_map)

                    import json
                    header_dict = {"Content-Type": "application/json", "X-API-KEY": env_config.get('token', '')}
                    api_config = {
                        'request_rest_api_url': env_config.get('url', self.base_config.request_rest_api_url),
                        'request_rest_api_header_value': json.dumps(header_dict),
                        'request_rest_api_timeout': env_config.get('timeout',
                                                                   self.base_config.request_rest_api_timeout),
                        'verify_ssl': self.base_config.verify_ssl,
                        'dry_run_mode': self.base_config.dry_run_mode
                    }
            elif TargetSystem_use_dynamic and not redis_use_dynamic and deployment_destination == "OCI":
                if use_vault:
                    if not self.vault_loader:
                        raise TargetSystemApiError("Vault loader not available for OCI dynamic configuration")

                    vault_config = await self.vault_loader.load_oci_api_config(bundle, env)

                    import json
                    header_dict = {"Content-Type": "application/json", "X-API-KEY": vault_config.get('token', '')}
                    api_config = {
                        'request_rest_api_url': vault_config.get('url', self.base_config.request_rest_api_url),
                        'request_rest_api_header_value': json.dumps(header_dict),
                        'request_rest_api_timeout': vault_config.get('timeout',
                                                                     self.base_config.request_rest_api_timeout),
                        'verify_ssl': self.base_config.verify_ssl,
                        'dry_run_mode': self.base_config.dry_run_mode
                    }
                else:
                    from ..config.settings import VaultConfigLoader
                    env_config = VaultConfigLoader.load_env_api_config(bundle, env, self.bundle_region_map)

                    import json
                    header_dict = {"Content-Type": "application/json", "X-API-KEY": env_config.get('token', '')}
                    api_config = {
                        'request_rest_api_url': env_config.get('url', self.base_config.request_rest_api_url),
                        'request_rest_api_header_value': json.dumps(header_dict),
                        'request_rest_api_timeout': env_config.get('timeout',
                                                                   self.base_config.request_rest_api_timeout),
                        'verify_ssl': self.base_config.verify_ssl,
                        'dry_run_mode': self.base_config.dry_run_mode
                    }
            else:
                if not self.vault_loader:
                    raise TargetSystemApiError("Vault loader not available for dynamic configuration")

                vault_config = await self.vault_loader.load_TargetSystem_api_config(bundle, env, self.bundle_region_map)
                api_config = {
                    'request_rest_api_url': vault_config.get('request_rest_api_url',
                                                             self.base_config.request_rest_api_url),
                    'request_rest_api_header_value': vault_config.get('request_rest_api_header_value',
                                                                      self.base_config.request_rest_api_header_value),
                    'request_rest_api_timeout': vault_config.get('request_rest_api_timeout',
                                                                 self.base_config.request_rest_api_timeout),
                    'verify_ssl': vault_config.get('verify_ssl', self.base_config.verify_ssl),
                    'dry_run_mode': vault_config.get('dry_run_mode', self.base_config.dry_run_mode)
                }
            dynamic_config = TargetSystemConfig(
                request_rest_api_url=api_config['request_rest_api_url'],
                request_rest_api_header_value=api_config['request_rest_api_header_value'],
                request_rest_api_timeout=api_config['request_rest_api_timeout'],
                verify_ssl=api_config['verify_ssl'],
                dry_run_mode=api_config['dry_run_mode'],
                use_dynamic_api=self.base_config.use_dynamic_api
            )

            self._config_cache[cache_key] = dynamic_config
            return dynamic_config

        except VaultConnectionError as e:
            if "status 404" in str(e):
                logger = logging.getLogger(f"{__name__}-{uuid.uuid4()}")
                logger.warning(f"Vault configuration not found for {bundle}/{env} (404). Falling back to base configuration.")
                self._config_cache[cache_key] = self.base_config
                return self.base_config
            else:
                raise TargetSystemApiError(f"Failed to load dynamic TargetSystem configuration for {bundle}/{env}: {e}")
        except Exception as e:
            raise TargetSystemApiError(f"Failed to load dynamic TargetSystem configuration for {bundle}/{env}: {e}")

    async def _get_config_for_request(self, bundle: str, env: str) -> TargetSystemConfig:
        if self.base_config.use_dynamic_api:
            return await self._get_dynamic_config(bundle, env)
        else:
            return self.base_config

    async def get_all_users(self, bundle: str, env: str, correlation_id: str = None) -> List[TargetUser]:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_users(bundle, env)

    async def create_new_user(self, user_request: TargetSystemUserRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.create_user(user_request, bundle, env)

    async def get_user_details(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetUser:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_user(user_id, bundle, env)

    async def get_user_roles_and_associations(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetSystemUserAssignments:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_user_assignments(user_id, bundle, env)

    async def add_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.add_user_assignments(assignment_request, bundle, env)

    async def remove_user_assignments(self, assignment_request: TargetSystemAssignmentRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.remove_user_assignments(assignment_request, bundle, env)

    async def update_user_default_role(self, role_request: TargetSystemDefaultRoleRequest, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.update_user_default_role(role_request, bundle, env)


    async def disable_user(self, user_id: str, bundle: str, env: str, correlation_id: str = None) -> TargetSystemApiResponse:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.disable_user(user_id, bundle, env)

    async def check_api_status(self, bundle: str, env: str, correlation_id: str = None) -> bool:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.check_api_status()

    async def check_TargetSystem_status(self, bundle: str, env: str, correlation_id: str = None) -> bool:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.check_TargetSystem_status(bundle, env)

    async def get_domains_and_roles(self, bundle: str, env: str, correlation_id: str = None) -> Dict[str, List[str]]:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.get_domains_and_roles(bundle, env)

    async def validate_roles_exist(self, roles: List[str], domain: str, bundle: str, env: str, correlation_id: str = None) -> List[str]:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            return await client.validate_roles_exist(roles, domain, bundle, env)

    async def test_connectivity(self, bundle: str, env: str, correlation_id: str = None) -> Dict[str, bool]:
        config = await self._get_config_for_request(bundle, env)
        async with TargetSystemClient(config, correlation_id) as client:
            client.set_correlation_id(correlation_id) if correlation_id else None
            api_status = await client.check_api_status()
            return {"api_accessible": api_status}
