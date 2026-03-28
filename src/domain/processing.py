from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from .IDENTITY_MANAGER import Authorization, UserDetail


class FileStatus(str, Enum):
	NEW = "new"
	IN_PROGRESS = "in_progress"
	DONE = "done"
	ERROR = "error"
	FILE_ERROR = "file_error"
	EMPTY = "empty"
	EMPTY_FILE = "empty_file"


class ProcessingResult(BaseModel):
	success: bool
	message: str
	data: Optional[Dict[str, Any]] = None
	error: Optional[str] = None


class ComparisonResult(BaseModel):
	roles_to_add: List[str] = Field(default_factory=list)
	roles_to_remove: List[str] = Field(default_factory=list)
	domain_update_required: bool = False
	new_domain: Optional[str] = None
	associations_to_add: List[str] = Field(default_factory=list)
	associations_to_remove: List[str] = Field(default_factory=list)
	default_role_update: Optional[str] = None


class ParsedUser(BaseModel):
	login: str = Field(alias="user_id")
	first_name: str
	last_name: str
	domain: str
	roles: List[str]
	default_role: str
	associations: List[str]
	region: str = ""
	bundle: str = ""
	env: str = ""
	authorizations: List[Authorization] = []

	model_config = ConfigDict(populate_by_name=True)

	@property
	def user_id(self) -> str:
		return self.login

	@property
	def user_detail(self) -> UserDetail:
		return UserDetail(
			first_name=self.first_name,
			last_name=self.last_name
		)


class ParsedData(BaseModel):
    region: str
    bundle: str
    env: str
    users: List[ParsedUser]


class UserRegionEntry(BaseModel):
    region: str
    bundle: str
    env: str
    domain: str
    roles: List[str]
    associations: List[str]
    default_role: str


class UserWithRegions(BaseModel):
    user_id: str
    first_name: str
    last_name: str
    regions: List[UserRegionEntry] = []


class FileStatusRecord(BaseModel):
	json_file_path: str
	status: FileStatus
	start_time: datetime
	end_time: Optional[datetime] = None
	error_message: Optional[str] = None
	reprocess_count: int = 0


class FileStatusData(BaseModel):
	records: Dict[str, FileStatusRecord] = {}

	def add_record(self, record_id: str, record: FileStatusRecord):
		self.records[record_id] = record

	def update_status(self, record_id: str, status: FileStatus, error_message: Optional[str] = None,
					  increment_reprocess_count: bool = False):
		if record_id in self.records:
			self.records[record_id].status = status
			if error_message:
				self.records[record_id].error_message = error_message
			elif status == FileStatus.DONE:

				self.records[record_id].error_message = None
			if increment_reprocess_count:
				self.records[record_id].reprocess_count += 1
			if status in [FileStatus.DONE, FileStatus.ERROR, FileStatus.FILE_ERROR]:
				self.records[record_id].end_time = datetime.utcnow()


class ReprocessData(BaseModel):
	user_id: str
	bundle: str
	env: str
	region: str
	json_data: Dict[str, Any]
	request_type: str
	first_name: str
	last_name: str


class ReprocessFile(BaseModel):
	data: Dict[str, Dict[str, ReprocessData]] = {}
	reprocess_count: int = 0

	def add_user_data(self, user_id: str, bundle_env: str, reprocess_data: ReprocessData,
					  increment_counter: bool = True):

		if bundle_env not in self.data:
			self.data[bundle_env] = {}
		self.data[bundle_env][user_id] = reprocess_data
		if increment_counter:
			self.reprocess_count += 1

	def add_user_data_without_counter(self, user_id: str, bundle_env: str, reprocess_data: ReprocessData):

		self.add_user_data(user_id, bundle_env, reprocess_data, increment_counter=False)

	def remove_user_data(self, user_id: str, bundle_env: Optional[str] = None):
		if bundle_env and bundle_env in self.data:
			if user_id in self.data[bundle_env]:
				del self.data[bundle_env][user_id]
				if not self.data[bundle_env]:
					del self.data[bundle_env]
		else:

			for be in list(self.data.keys()):
				if user_id in self.data[be]:
					del self.data[be][user_id]
					if not self.data[be]:
						del self.data[be]


class MissingRolesData(BaseModel):
	regions: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]] = {}

	def add_missing_roles(self, region: str, bundle: str, env: str, domain: str, roles: List[str]):
		if region not in self.regions:
			self.regions[region] = {}
		if bundle not in self.regions[region]:
			self.regions[region][bundle] = {}
		if env not in self.regions[region][bundle]:
			self.regions[region][bundle][env] = {}
		if domain not in self.regions[region][bundle][env]:
			self.regions[region][bundle][env][domain] = []

		for role in roles:
			if role not in self.regions[region][bundle][env][domain]:
				self.regions[region][bundle][env][domain].append(role)

	def remove_roles(self, region: str, bundle: str, env: str, domain: str, roles: List[str]):
		if (region in self.regions and
				bundle in self.regions[region] and
				env in self.regions[region][bundle] and
				domain in self.regions[region][bundle][env]):

			for role in roles:
				if role in self.regions[region][bundle][env][domain]:
					self.regions[region][bundle][env][domain].remove(role)

			if not self.regions[region][bundle][env][domain]:
				del self.regions[region][bundle][env][domain]
			if not self.regions[region][bundle][env]:
				del self.regions[region][bundle][env]
			if not self.regions[region][bundle]:
				del self.regions[region][bundle]
			if not self.regions[region]:
				del self.regions[region]


class UserDisableInfo(BaseModel):
	user_id: str
	first_name: str
	last_name: str
	reason: str = "User has no authorizations"
	timestamp: datetime = Field(default_factory=datetime.utcnow)
