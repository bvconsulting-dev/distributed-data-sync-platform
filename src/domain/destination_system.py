from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
from datetime import datetime


class TargetUser(BaseModel):
	TARGET_USER_gid: str = Field(alias="TARGET_USER_GID")
	TARGET_USER_xid: str = Field(alias="TARGET_USER_XID")
	username: str = Field(alias="USERNAME")
	default_user_role_gid: str = Field(alias="DEFAULT_USER_ROLE_GID")
	domain_name: str = Field(alias="DOMAIN_NAME")
	email_address: Optional[str] = Field(alias="EMAIL_ADDRESS", default=None)
	last_login_date: Optional[str] = Field(alias="LAST_LOGIN_DATE", default=None)
	TARGET_account_policy_gid: Optional[str] = Field(alias="TARGET_ACCOUNT_POLICY_GID", default=None)
	unsuccessful_login_attempts: Optional[str] = Field(alias="UNSUCCESSFUL_LOGIN_ATTEMPTS", default=None)
	first_name: Optional[str] = Field(alias="FIRST_NAME", default=None)
	last_name: Optional[str] = Field(alias="LAST_NAME", default=None)

	model_config = ConfigDict(populate_by_name=True)


class TargetSystemUserRequest(BaseModel):
	user_id: str
	first_name: str
	last_name: str
	domain: str
	roles: List[str]
	default_role: str
	associations: List[str]


class TargetSystemUserAssignments(BaseModel):
	user_id: str
	first_name: str
	last_name: str
	domain: str
	roles: List[str]
	default_role: str
	associations: List[str]


class TargetSystemAssignmentRequest(BaseModel):
	user_id: str
	roles: List[str]
	associations: List[str]


class TargetSystemDefaultRoleRequest(BaseModel):
	user_id: str
	default_role: str


class TargetSystemApiResponse(BaseModel):
	message: str
	code: Optional[int] = None
	return_code: Optional[int] = None
	status: str
	data: Optional[dict] = None

	model_config = ConfigDict(populate_by_name=True)


class TargetSystemTransmissionResponse(BaseModel):
	transmission_id: str
	status: str
	created_at: datetime
	updated_at: datetime
	request_data: dict
	response_data: Optional[dict] = None
	error_message: Optional[str] = None


class TargetSystemDomainsResponse(BaseModel):
	domains: dict


class TargetSystemStatusResponse(BaseModel):
	message: str
	status: str
	timestamp: datetime
