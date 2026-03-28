from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import List, Optional
from datetime import datetime


class UserDetail(BaseModel):
	first_name: str = Field(alias="firstName")
	last_name: str = Field(alias="lastName")

	model_config = ConfigDict(populate_by_name=True)


class AttributeValue(BaseModel):
	id: str
	value: str
	value_name: Optional[str] = Field(alias="valueName", default="")
	parent_id: Optional[str] = Field(alias="parentId")
	defaulted: bool = Field(default=False)

	model_config = ConfigDict(populate_by_name=True)

	@field_validator('value_name')
	@classmethod
	def validate_value_name(cls, v):
		if v is None:
			return ""
		if isinstance(v, str) and v.lower() == "none":
			return ""
		return str(v) if v is not None else ""


class ApplicationHierarchy(BaseModel):
	label: str


class ApplicationHierarchyData(BaseModel):
	application_hierarchy: ApplicationHierarchy = Field(alias="applicationHierarchy")
	attribute_values: List[AttributeValue] = Field(alias="attributeValues")

	model_config = ConfigDict(populate_by_name=True)


class ApplicationInstance(BaseModel):
	name: str


class Authorization(BaseModel):
	application_instance: ApplicationInstance = Field(alias="applicationInstance")
	application_hierarchies: List[ApplicationHierarchyData] = Field(alias="applicationHierarchies")

	model_config = ConfigDict(populate_by_name=True)


class IdentityUser(BaseModel):
	id: str
	login: str
	created: datetime
	updated: datetime
	user_detail: UserDetail = Field(alias="userDetail")
	authorizations: List[Authorization]

	model_config = ConfigDict(populate_by_name=True)


class ModifiedUsersResponse(BaseModel):
	users: List[IdentityUser]
	total: int


class IdentityManagerGraphQLResponse(BaseModel):
	data: dict

	@property
	def modified_users(self) -> ModifiedUsersResponse:
		modified_users_data = self.data.get("modifiedUsers", {})
		return ModifiedUsersResponse(**modified_users_data)


class IdentityManagerGraphQLRequest(BaseModel):
	query: str
	variables: dict
