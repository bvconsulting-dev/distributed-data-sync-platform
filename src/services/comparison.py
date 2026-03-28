import asyncio
import logging
from typing import List, Dict, Set, Optional, Tuple, Any, TypedDict, Union
from datetime import datetime

from ..models.IDENTITY_MANAGER import IdentityUser, Authorization, ApplicationHierarchyData
from ..models.TargetSystem import TargetUser, TargetSystemUserAssignments
from ..models.processing import (
    ComparisonResult,
    ParsedUser,
    ParsedData,
    UserWithRegions,
    UserRegionEntry,
)
from ..exceptions.base import ComparisonError


class HierarchyEntry(TypedDict):
    region: str
    bundle: str
    env: str
    domain: str
    roles: List[str]
    associations: List[str]
    default_role: str


class DataParser:

	def __init__(self, correlation_id: str = None, config=None):
		self.correlation_id = correlation_id or f"comparison_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
		self.config = config
		self.hierarchy_mappings = {
			"Region": "region",
			"Bundle": "bundle",
			"Environment": "env",
			"Domain": "domain",
			"Mandatory Role": "role"
		}

		from ..utils.bundle_env_extractor import BundleEnvironmentExtractor
		self.bundle_env_extractor = BundleEnvironmentExtractor()

	def parse_IDENTITY_MANAGER_user(self, source_user: IdentityUser) -> List[ParsedUser]:

		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
		logger.debug(f"Starting to parse IdentityManager user: {source_user.login}")

		parsed_users = []

		if not source_user.authorizations:
			logger.warning(
				f"User {source_user.login} has empty authorizations array - revoking access and skipping validation")
			logger.info(
				f"JsonValidator requirement 1: Authorization:[] detected for user {source_user.login} - access revoked")

			parsed_user = ParsedUser(
				user_id=source_user.login,
				first_name=source_user.user_detail.first_name,
				last_name=source_user.user_detail.last_name,
				domain="",
				roles=[],
				default_role="",
				associations=[]
			)
			parsed_users.append(parsed_user)
			return parsed_users

		for authorization in source_user.authorizations:

			hierarchy_data = self._extract_hierarchy_data(authorization.application_hierarchies)

			if not hierarchy_data:
				continue

			if isinstance(hierarchy_data, list):
				created_any = False
				for hd in hierarchy_data:
					missing_components = self._validate_hierarchy_components(hd, source_user.login)
					if missing_components:
						logger.error(
							f"JsonValidator requirement 2: User {source_user.login} has missing hierarchy components: {missing_components} - skipping this combination")
						continue
					parsed_user = ParsedUser(
						user_id=source_user.login,
						first_name=source_user.user_detail.first_name,
						last_name=source_user.user_detail.last_name,
						domain=hd.get("domain", ""),
						roles=hd.get("roles", []),
						default_role=hd.get("default_role", ""),
						associations=hd.get("associations", []),
						region=hd.get("region", ""),
						bundle=hd.get("bundle", ""),
						env=hd.get("env", "")
					)
					logger.debug(
						f"Created ParsedUser for {source_user.login} - Domain: '{parsed_user.domain}', Roles: {len(parsed_user.roles)}, Associations: {len(parsed_user.associations)}")
					parsed_users.append(parsed_user)
					created_any = True
				if not created_any:
					logger.warning(
						f"User {source_user.login} had multiple hierarchy combinations but all were invalid — skipping user for this authorization")
			else:
				missing_components = self._validate_hierarchy_components(hierarchy_data, source_user.login)
				if missing_components:
					logger.error(
						f"JsonValidator requirement 2: User {source_user.login} has missing hierarchy components: {missing_components} - skipping user")
					logger.warning(
						f"Skipping user {source_user.login} due to missing hierarchy components and continuing with next user")
					continue
				parsed_user = ParsedUser(
					user_id=source_user.login,
					first_name=source_user.user_detail.first_name,
					last_name=source_user.user_detail.last_name,
					domain=hierarchy_data.get("domain", ""),
					roles=hierarchy_data.get("roles", []),
					default_role=hierarchy_data.get("default_role", ""),
					associations=hierarchy_data.get("associations", []),
					region=hierarchy_data.get("region", ""),
					bundle=hierarchy_data.get("bundle", ""),
					env=hierarchy_data.get("env", "")
				)
				logger.debug(
					f"Created ParsedUser for {source_user.login} - Domain: '{parsed_user.domain}', Roles: {len(parsed_user.roles)}, Associations: {len(parsed_user.associations)}")
				parsed_users.append(parsed_user)

		logger.debug(
			f"Completed parsing IdentityManager user {source_user.login} - Generated {len(parsed_users)} ParsedUser objects")
		return parsed_users

	def _extract_hierarchy_data(self, hierarchies: List[ApplicationHierarchyData]) -> Union[HierarchyEntry, List[HierarchyEntry]]:


		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
		logger.debug(f"Starting hierarchy data extraction for {len(hierarchies)} hierarchies (with parent→child checks)")

		def _new_data() -> HierarchyEntry:
			return {
				"region": "",
				"bundle": "",
				"env": "",
				"domain": "",
				"roles": [],
				"associations": [],
				"default_role": ""
			}

		by_label: Dict[str, List[Any]] = {}
		for hierarchy in hierarchies:
			label = hierarchy.application_hierarchy.label
			by_label.setdefault(label, []).extend(hierarchy.attribute_values)

		regions = by_label.get("Region", [])
		bundles = by_label.get("Bundle", [])
		envs = by_label.get("Environment", [])
		domains = by_label.get("Domain", [])
		roles_values = (by_label.get("Role", []) or []) + (by_label.get("Mandatory Role", []) or [])
		assoc_values = by_label.get("User Association Value", []) or []

		results: List[HierarchyEntry] = []
		if not regions:
			logger.error("Hierarchy extraction aborted: missing Region level (no entries in 'Region')")
			return []
		else:
			for reg in regions:
				region_id = reg.id
				region_name = reg.value_name
				bundles_under = [b for b in bundles if b.parent_id == region_id] or bundles
				if not bundles_under and bundles:
					logger.warning("Region has no matching bundles by parentId; using all bundles as fallback")
				for b in bundles_under or [None]:
					bundle_id = getattr(b, 'id', None)
					bundle_name = getattr(b, 'value_name', '') if b else ''
					envs_under = [e for e in envs if bundle_id and e.parent_id == bundle_id] or envs
					if not envs_under and envs:
						logger.warning("Bundle has no matching environments by parentId; using all environments as fallback")
					for e in envs_under or [None]:
						env_id = getattr(e, 'id', None)
						env_value = ''
						if e:
							env_value = e.value_name
							if "^" in e.value:
								env_value = e.value.split("^")[1]
						domains_under = [d for d in domains if env_id and d.parent_id == env_id] or domains
						if not domains_under and domains:
							logger.warning("Environment has no matching domains by parentId; using all domains as fallback")
						for d in domains_under or [None]:
							domain_id = getattr(d, 'id', None)
							domain_name = getattr(d, 'value_name', '') if d else ''
							data = _new_data()
							data["region"] = region_name
							data["bundle"] = bundle_name
							data["env"] = env_value
							data["domain"] = domain_name
							defaulted_roles: List[str] = []
							all_roles: List[str] = []
							for rv in roles_values:
								if domain_id and rv.parent_id and rv.parent_id != domain_id:
									continue
								role = rv.value_name
								data["roles"].append(role)
								all_roles.append(role)
								if rv.defaulted:
									defaulted_roles.append(role)
							for av in assoc_values:
								if domain_id and av.parent_id and av.parent_id != domain_id:
									continue
								data["associations"].append(av.value_name)
							if defaulted_roles:
								data["default_role"] = defaulted_roles[0]
							elif all_roles:
								data["default_role"] = all_roles[0]
							results.append(data)

		if len(results) == 1:
			res = results[0]
			logger.debug(
				f"Hierarchy extraction complete - Region: '{res['region']}', Bundle: '{res['bundle']}', Env: '{res['env']}', Domain: '{res['domain']}', Roles: {len(res['roles'])}, Associations: {len(res['associations'])}")
			return res
		logger.debug(f"Hierarchy extraction produced {len(results)} combinations (multi-region/bundle/env/domain)")
		return results

	def _validate_hierarchy_components(self, hierarchy_data: HierarchyEntry, user_login: str) -> List[str]:


		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

		required_components = ["region", "bundle", "env", "domain", "roles"]
		missing_components = []

		for component in required_components:
			if component == "roles":

				if not hierarchy_data.get(component) or len(hierarchy_data.get(component, [])) == 0:
					missing_components.append("role")
			else:

				if not hierarchy_data.get(component) or hierarchy_data.get(component) == "":
					missing_components.append(component)

		if missing_components:
			logger.debug(f"Missing hierarchy components for user {user_login}: {missing_components}")
			logger.debug(
				f"Current hierarchy data: region='{hierarchy_data.get('region', '')}', bundle='{hierarchy_data.get('bundle', '')}', env='{hierarchy_data.get('env', '')}', domain='{hierarchy_data.get('domain', '')}', roles={len(hierarchy_data.get('roles', []))}")

		return missing_components

	def parse_IDENTITY_MANAGER_data_to_grouped(self, source_users: List[IdentityUser]) -> List[ParsedData]:

		grouped_data = {}
		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

		for source_user in source_users:
			parsed_users = self.parse_IDENTITY_MANAGER_user(source_user)


			region = "EMEA"
			bundle = "cloud"
			env = "dev"


			for parsed_user in parsed_users:
				group_key = f"{parsed_user.region}_{parsed_user.bundle}_{parsed_user.env}"

				if group_key not in grouped_data:
					grouped_data[group_key] = ParsedData(
						region=parsed_user.region,
						bundle=parsed_user.bundle,
						env=parsed_user.env,
						users=[]
					)

				grouped_data[group_key].users.append(parsed_user)

		return list(grouped_data.values())

	def _extract_environment_info(self, parsed_user: ParsedUser) -> Tuple[str, str, str]:

		region = "EMEA"
		bundle = "cloud"
		env = "dev"

		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
		logger.warning(
			"Using deprecated _extract_environment_info method with hardcoded defaults. Consider passing region/bundle/env from calling context.")

		if self.config and not getattr(self.config, 'use_IDENTITY_MANAGER_bundle_env', True):
			bundle = getattr(self.config, 'default_test_bundle', 'cloud')
			env = getattr(self.config, 'default_test_environment', 'dev')

		return region, bundle, env

	def parse_file_data(self, file_data: Dict[str, any]) -> ParsedData:

		if "data" in file_data and "modifiedUsers" in file_data["data"]:
			users_data = file_data["data"]["modifiedUsers"].get("users", [])
		elif "users" in file_data:
			users_data = file_data["users"]
		else:

			users_data = file_data if isinstance(file_data, list) else [file_data]

		from ..models.IDENTITY_MANAGER import IdentityUser
		import logging
		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

		source_users = []
		failed_count = 0

		for i, user_data in enumerate(users_data):
			try:
				if isinstance(user_data, dict):
					source_user = IdentityUser(**user_data)
					source_users.append(source_user)
			except Exception as e:

				failed_count += 1
				logger.error(f"Failed to parse user data at index {i}: {e}")
				logger.debug(f"User data that failed parsing: {user_data}")
				continue

		total_users = len(users_data)
		successful_count = len(source_users)
		logger.info(
			f"User parsing summary: {successful_count}/{total_users} users parsed successfully, {failed_count} failed")

		if failed_count > 0:
			logger.warning(
				f"Some users failed to parse - this may indicate data format issues or missing required fields")

		if source_users:
			parsed_data_list = self.parse_IDENTITY_MANAGER_data_to_grouped(source_users)

			if parsed_data_list:

				first_group = parsed_data_list[0]
				all_users = []

				for group in parsed_data_list:
					all_users.extend(group.users)

				parsed_data = ParsedData(
					region=group.region,
					bundle=group.bundle,
					env=group.env,
					users=all_users
				)
				logger.debug(
					f"Created ParsedData with Region: '{parsed_data.region}', Bundle: '{parsed_data.bundle}', Environment: '{parsed_data.env}', Users: {len(parsed_data.users)}")
				return parsed_data

		bundle = "cloud"
		env = "dev"
		region = "EMEA"

		if self.config and getattr(self.config, 'use_IDENTITY_MANAGER_bundle_env', True):
			try:

				bundle_env_combinations = self.bundle_env_extractor.extract_bundle_env_from_json_data(file_data)
				if bundle_env_combinations:

					bundle, env = bundle_env_combinations[0]
					logger.debug(f"Extracted bundle/environment from IdentityManager data: {bundle}/{env}")
				else:
					logger.debug("No bundle/environment found in IdentityManager data, using default values")
			except Exception as e:
				logger.warning(f"Failed to extract bundle/environment from IdentityManager data: {e}, using default values")
		else:

			if self.config:
				bundle = getattr(self.config, 'default_test_bundle', 'cloud')
				env = getattr(self.config, 'default_test_environment', 'dev')
			logger.debug(f"Using configured test values: {bundle}/{env}")

		if self.config and getattr(self.config, 'use_IDENTITY_MANAGER_bundle_env', True):
			if not bundle or not env:
				logger.warning(
					f"Bundle/environment extraction failed with USE_IDENTITY_MANAGER_BUNDLE_ENV=true. Bundle: '{bundle}', Env: '{env}'. Using fallback values.")
				bundle = getattr(self.config, 'default_test_bundle', 'cloud')
				env = getattr(self.config, 'default_test_environment', 'dev')
				logger.info(f"Applied fallback values: Bundle: '{bundle}', Env: '{env}'")

		default_parsed_data = ParsedData(
			region=region,
			bundle=bundle,
			env=env,
			users=[]
		)
		logger.debug(
			f"No users found, returning default ParsedData with Region: '{default_parsed_data.region}', Bundle: '{default_parsed_data.bundle}', Environment: '{default_parsed_data.env}'")
		return default_parsed_data

	def parse_users_with_regions(self, source_users: List[IdentityUser]) -> List[UserWithRegions]:

		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")
		users_map: Dict[str, UserWithRegions] = {}

		for source_user in source_users:
			if source_user.login not in users_map:
				users_map[source_user.login] = UserWithRegions(
					user_id=source_user.login,
					first_name=source_user.user_detail.first_name,
					last_name=source_user.user_detail.last_name,
					regions=[]
				)

			if not source_user.authorizations:
				logger.warning(f"User {source_user.login} has no authorizations; adding empty regions entry is skipped")
				continue

			for authorization in source_user.authorizations:
				hierarchy_data = self._extract_hierarchy_data(authorization.application_hierarchies)
				if not hierarchy_data:
					continue
				missing = self._validate_hierarchy_components(hierarchy_data, source_user.login)
				if missing:
					logger.warning(f"Skipping {source_user.login} auth due to missing components: {missing}")
					continue

				entry = UserRegionEntry(
					region=hierarchy_data.get("region", ""),
					bundle=hierarchy_data.get("bundle", ""),
					env=hierarchy_data.get("env", ""),
					domain=hierarchy_data.get("domain", ""),
					roles=hierarchy_data.get("roles", []) or [],
					associations=hierarchy_data.get("associations", []) or [],
					default_role=hierarchy_data.get("default_role", ""),
				)
				users_map[source_user.login].regions.append(entry)

		result = list(users_map.values())
		logger.debug(f"Built UserWithRegions list: {len(result)} users")
		return result

	def parse_users_with_regions_from_file(self, file_data: Dict[str, any]) -> List[UserWithRegions]:

		if "data" in file_data and "modifiedUsers" in file_data["data"]:
			users_data = file_data["data"]["modifiedUsers"].get("users", [])
		elif "users" in file_data:
			users_data = file_data["users"]
		else:
			users_data = file_data if isinstance(file_data, list) else [file_data]

		from ..models.IDENTITY_MANAGER import IdentityUser
		logger = logging.getLogger(f"{__name__}-{self.correlation_id}")

		source_users = []
		for i, user_data in enumerate(users_data):
			try:
				if isinstance(user_data, dict):
					source_user = IdentityUser(**user_data)
					source_users.append(source_user)
			except Exception as e:
				logger.error(f"Failed to parse user data at index {i}: {e}")
				logger.debug(f"User data that failed parsing: {user_data}")

		return self.parse_users_with_regions(source_users)

	def parse_users_grouped_by_region(self, source_users: List[IdentityUser]) -> Dict[str, Dict[str, List[Dict[str, any]]]]:


		result: Dict[str, Dict[str, List[Dict[str, any]]]] = {}
		users_full = self.parse_users_with_regions(source_users)
		for user in users_full:
			for entry in user.regions:
				region = entry.region or ""
				if region not in result:
					result[region] = {}
				if user.user_id not in result[region]:
					result[region][user.user_id] = []
				result[region][user.user_id].append({
					"bundle": entry.bundle,
					"env": entry.env,
					"domain": entry.domain,
					"roles": entry.roles,
					"associations": entry.associations,
					"default_role": entry.default_role,
					"first_name": user.first_name,
					"last_name": user.last_name,
					"user_id": user.user_id,
				})
		return result

	def parse_users_grouped_by_region_from_file(self, file_data: Dict[str, any]) -> Dict[str, Dict[str, List[Dict[str, any]]]]:

		if "data" in file_data and "modifiedUsers" in file_data["data"]:
			users_data = file_data["data"]["modifiedUsers"].get("users", [])
		elif "users" in file_data:
			users_data = file_data["users"]
		else:
			users_data = file_data if isinstance(file_data, list) else [file_data]

		from ..models.IDENTITY_MANAGER import IdentityUser
		source_users = []
		for user_data in users_data:
			if isinstance(user_data, dict):
				try:
					source_users.append(IdentityUser(**user_data))
				except Exception:
					continue

		return self.parse_users_grouped_by_region(source_users)


class AsyncComparisonService:

	def __init__(self, correlation_id: str = None, config=None):
		self.correlation_id = correlation_id
		self.parser = DataParser(correlation_id, config)

	async def compare_user_data(
			self,
			source_user: IdentityUser,
			TargetSystem_user: TargetUser,
			TargetSystem_assignments: Optional[TargetSystemUserAssignments] = None
	) -> ComparisonResult:

		try:

			parsed_source_users = self.parser.parse_IDENTITY_MANAGER_user(source_user)

			if not parsed_source_users:
				return ComparisonResult()

			parsed_source_user = parsed_source_users[0]

			tasks = [
				self.compare_roles(parsed_source_user, TargetSystem_assignments or self._convert_TargetSystem_user_to_assignments(TargetSystem_user)),
				self.compare_domains(parsed_source_user, TargetSystem_user),
				self.compare_associations(parsed_source_user,
										  TargetSystem_assignments or self._convert_TargetSystem_user_to_assignments(TargetSystem_user))
			]

			role_result, domain_result, association_result = await asyncio.gather(*tasks)

			comparison_result = ComparisonResult(
				roles_to_add=role_result.get("to_add", []),
				roles_to_remove=role_result.get("to_remove", []),
				domain_update_required=domain_result.get("update_required", False),
				new_domain=domain_result.get("new_domain"),
				associations_to_add=association_result.get("to_add", []),
				associations_to_remove=association_result.get("to_remove", []),
				default_role_update=role_result.get("default_role_update")
			)

			return comparison_result

		except Exception as e:
			raise ComparisonError(f"Failed to compare user data: {e}")

	async def compare_roles(self, source_user: ParsedUser, TargetSystem_assignments: TargetSystemUserAssignments) -> Dict[str, any]:

		source_roles = set(source_user.roles)
		TargetSystem_roles = set(TargetSystem_assignments.roles)

		roles_to_add = list(source_roles - TargetSystem_roles)
		roles_to_remove = list(TargetSystem_roles - source_roles)

		default_role_update = None
		if source_user.default_role != TargetSystem_assignments.default_role:
			default_role_update = source_user.default_role

		return {
			"to_add": roles_to_add,
			"to_remove": roles_to_remove,
			"default_role_update": default_role_update
		}

	async def compare_domains(self, source_user: ParsedUser, TargetSystem_user: TargetUser) -> Dict[str, any]:

		update_required = source_user.domain != TargetSystem_user.domain_name
		new_domain = source_user.domain if update_required else None

		return {
			"update_required": update_required,
			"new_domain": new_domain
		}

	async def compare_associations(self, source_user: ParsedUser, TargetSystem_assignments: TargetSystemUserAssignments) -> Dict[str, any]:

		source_associations = set(source_user.associations)
		TargetSystem_associations = set(TargetSystem_assignments.associations)

		associations_to_add = list(source_associations - TargetSystem_associations)
		associations_to_remove = list(TargetSystem_associations - source_associations)

		return {
			"to_add": associations_to_add,
			"to_remove": associations_to_remove
		}

	def _convert_TargetSystem_user_to_assignments(self, TargetSystem_user: TargetUser) -> TargetSystemUserAssignments:

		return TargetSystemUserAssignments(
			user_id=TargetSystem_user.username,
			first_name=TargetSystem_user.first_name if TargetSystem_user.first_name else "",
			last_name=TargetSystem_user.last_name if TargetSystem_user.last_name else "",
			domain=TargetSystem_user.domain_name,
			roles=[],
			default_role=TargetSystem_user.default_user_role_gid,
			associations=[]
		)

	async def compare_multiple_users(
			self,
			source_users: List[IdentityUser],
			TargetSystem_users: List[TargetUser],
			TargetSystem_assignments_map: Optional[Dict[str, TargetSystemUserAssignments]] = None
	) -> Dict[str, ComparisonResult]:

		TargetSystem_user_map = {user.username: user for user in TargetSystem_users}

		tasks = []
		user_ids = []

		for source_user in source_users:
			user_id = source_user.login
			if user_id in TargetSystem_user_map:
				TargetSystem_user = TargetSystem_user_map[user_id]
				TargetSystem_assignments = TargetSystem_assignments_map.get(user_id) if TargetSystem_assignments_map else None

				task = self.compare_user_data(source_user, TargetSystem_user, TargetSystem_assignments)
				tasks.append(task)
				user_ids.append(user_id)

		results = await asyncio.gather(*tasks, return_exceptions=True)

		comparison_results = {}
		for user_id, result in zip(user_ids, results):
			if isinstance(result, Exception):

				comparison_results[user_id] = ComparisonResult()
			else:
				comparison_results[user_id] = result

		return comparison_results

	async def identify_users_for_disable(self, source_users: List[IdentityUser]) -> List[str]:

		users_to_disable = []

		for source_user in source_users:
			if not source_user.authorizations:
				users_to_disable.append(source_user.login)

		return users_to_disable

	async def check_missing_roles_in_TargetSystem(
			self,
			required_roles: List[str],
			available_roles: Dict[str, List[str]],
			domain: str
	) -> List[str]:

		domain_roles = set(available_roles.get(domain, []))
		required_roles_set = set(required_roles)

		missing_roles = list(required_roles_set - domain_roles)
		return missing_roles


class ComparisonOrchestrator:

	def __init__(self, correlation_id: str = None, config=None):
		self.correlation_id = correlation_id
		self.comparison_service = AsyncComparisonService(correlation_id, config)

	async def process_user_comparisons(
			self,
			parsed_data: ParsedData,
			TargetSystem_users: List[TargetUser],
			TargetSystem_assignments_map: Dict[str, TargetSystemUserAssignments],
			available_roles: Dict[str, List[str]]
	) -> Dict[str, any]:

		results = {
			"region": parsed_data.region,
			"bundle": parsed_data.bundle,
			"env": parsed_data.env,
			"user_comparisons": {},
			"users_to_disable": [],
			"missing_roles": {},
			"summary": {
				"total_users": len(parsed_data.users),
				"users_with_changes": 0,
				"users_to_create": 0,
				"users_to_update": 0
			}
		}

		TargetSystem_user_map = {user.username: user for user in TargetSystem_users}

		for parsed_user in parsed_data.users:
			user_id = parsed_user.login

			if user_id in TargetSystem_user_map:

				TargetSystem_user = TargetSystem_user_map[user_id]
				TargetSystem_assignments = TargetSystem_assignments_map.get(user_id)

				if TargetSystem_assignments:

					source_user = self._create_mock_source_user(parsed_user)
					comparison_result = await self.comparison_service.compare_user_data(
						source_user, TargetSystem_user, TargetSystem_assignments
					)

					results["user_comparisons"][user_id] = comparison_result

					if self._has_changes(comparison_result):
						results["summary"]["users_with_changes"] += 1
						results["summary"]["users_to_update"] += 1
			else:

				results["summary"]["users_to_create"] += 1

			missing_roles = await self.comparison_service.check_missing_roles_in_TargetSystem(
				parsed_user.roles, available_roles, parsed_user.domain
			)

			if missing_roles:
				if parsed_user.domain not in results["missing_roles"]:
					results["missing_roles"][parsed_user.domain] = []
				results["missing_roles"][parsed_user.domain].extend(missing_roles)

		return results

	def _create_mock_source_user(self, parsed_user: ParsedUser) -> IdentityUser:

		from ..models.IDENTITY_MANAGER import UserDetail

		return IdentityUser(
			id="mock_id",
			login=parsed_user.login,
			created=datetime.utcnow(),
			updated=datetime.utcnow(),
			user_detail=UserDetail(
				first_name=parsed_user.first_name,
				last_name=parsed_user.last_name
			),
			authorizations=[]
		)

	def _has_changes(self, comparison_result: ComparisonResult) -> bool:

		return (
				bool(comparison_result.roles_to_add) or
				bool(comparison_result.roles_to_remove) or
				comparison_result.domain_update_required or
				bool(comparison_result.associations_to_add) or
				bool(comparison_result.associations_to_remove) or
				bool(comparison_result.default_role_update)
		)
