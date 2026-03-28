import logging
from typing import Dict, List, Optional, Tuple, Any
from ..models.IDENTITY_MANAGER import IdentityUser, Authorization, ApplicationHierarchyData


class BundleEnvironmentExtractor:

	def __init__(self):
		self.logger = logging.getLogger(__name__)

	def extract_bundle_env_from_user(self, user: IdentityUser) -> List[Tuple[str, str]]:

		bundle_env_combinations = []

		try:
			for authorization in user.authorizations:
				bundle_env = self._extract_from_authorization(authorization)
				if bundle_env:
					bundle_env_combinations.append(bundle_env)

		except Exception as e:
			self.logger.error(f"Error extracting bundle/env from user {user.login}: {e}")

		return bundle_env_combinations

	def extract_region_bundle_env_from_user(self, user: IdentityUser) -> List[Tuple[str, str, str]]:

		region_bundle_env_combinations = []

		try:
			for authorization in user.authorizations:
				region_bundle_env = self._extract_region_bundle_env_from_authorization(authorization)
				if region_bundle_env:
					region_bundle_env_combinations.append(region_bundle_env)

		except Exception as e:
			self.logger.error(f"Error extracting region/bundle/env from user {user.login}: {e}")

		return region_bundle_env_combinations

	def _extract_from_authorization(self, authorization: Authorization) -> Optional[Tuple[str, str]]:

		bundle = None
		environment = None

		try:
			for hierarchy_data in authorization.application_hierarchies:
				hierarchy_label = hierarchy_data.application_hierarchy.label

				if hierarchy_label == "Bundle" and hierarchy_data.attribute_values:
					bundle = hierarchy_data.attribute_values[0].value_name
				elif hierarchy_label == "Environment" and hierarchy_data.attribute_values:
					environment = hierarchy_data.attribute_values[0].value_name

			if bundle and environment:
				return (bundle, environment)

		except Exception as e:
			self.logger.error(f"Error extracting from authorization: {e}")

		return None

	def _extract_region_bundle_env_from_authorization(self, authorization: Authorization) -> Optional[
		Tuple[str, str, str]]:

		region = None
		bundle = None
		environment = None

		try:
			for hierarchy_data in authorization.application_hierarchies:
				hierarchy_label = hierarchy_data.application_hierarchy.label

				if hierarchy_label == "Region" and hierarchy_data.attribute_values:
					region = hierarchy_data.attribute_values[0].value_name
				elif hierarchy_label == "Bundle" and hierarchy_data.attribute_values:
					bundle = hierarchy_data.attribute_values[0].value_name
				elif hierarchy_label == "Environment" and hierarchy_data.attribute_values:
					environment = hierarchy_data.attribute_values[0].value_name

			if region and bundle and environment:
				return (region, bundle, environment)

		except Exception as e:
			self.logger.error(f"Error extracting region/bundle/env from authorization: {e}")

		return None

	def extract_bundle_env_from_json_data(self, json_data: Dict[str, Any]) -> List[Tuple[str, str]]:

		bundle_env_combinations = []

		try:

			if "data" in json_data and "modifiedUsers" in json_data["data"]:
				users_data = json_data["data"]["modifiedUsers"].get("users", [])
			elif "users" in json_data:
				users_data = json_data["users"]
			else:
				users_data = [json_data] if isinstance(json_data, dict) else json_data

			for user_data in users_data:
				if "authorizations" in user_data:
					for auth in user_data["authorizations"]:
						bundle_env = self._extract_from_json_authorization(auth)
						if bundle_env and bundle_env not in bundle_env_combinations:
							bundle_env_combinations.append(bundle_env)

		except Exception as e:
			self.logger.error(f"Error extracting bundle/env from JSON data: {e}")

		return bundle_env_combinations

	def extract_region_bundle_env_from_json_data(self, json_data: Dict[str, Any]) -> List[Tuple[str, str, str]]:

		region_bundle_env_combinations = []

		try:

			if "data" in json_data and "modifiedUsers" in json_data["data"]:
				users_data = json_data["data"]["modifiedUsers"].get("users", [])
			elif "users" in json_data:
				users_data = json_data["users"]
			else:
				users_data = [json_data] if isinstance(json_data, dict) else json_data

			for user_data in users_data:
				if "authorizations" in user_data:
					for auth in user_data["authorizations"]:
						region_bundle_env = self._extract_region_bundle_env_from_json_authorization(auth)
						if region_bundle_env and region_bundle_env not in region_bundle_env_combinations:
							region_bundle_env_combinations.append(region_bundle_env)

		except Exception as e:
			self.logger.error(f"Error extracting region/bundle/env from JSON data: {e}")

		return region_bundle_env_combinations

	def _extract_from_json_authorization(self, auth_data: Dict[str, Any]) -> Optional[Tuple[str, str]]:

		bundle = None
		environment = None

		try:
			app_hierarchies = auth_data.get("applicationHierarchies", [])

			for hierarchy in app_hierarchies:
				hierarchy_label = hierarchy.get("applicationHierarchy", {}).get("label", "")
				attribute_values = hierarchy.get("attributeValues", [])

				if hierarchy_label == "Bundle" and attribute_values:
					bundle = attribute_values[0].get("valueName")
				elif hierarchy_label == "Environment" and attribute_values:
					environment = attribute_values[0].get("valueName")

			if bundle and environment:
				return (bundle, environment)

		except Exception as e:
			self.logger.error(f"Error extracting from JSON authorization: {e}")

		return None

	def _extract_region_bundle_env_from_json_authorization(self, auth_data: Dict[str, Any]) -> Optional[
		Tuple[str, str, str]]:

		region = None
		bundle = None
		environment = None

		try:
			app_hierarchies = auth_data.get("applicationHierarchies", [])

			for hierarchy in app_hierarchies:
				hierarchy_label = hierarchy.get("applicationHierarchy", {}).get("label", "")
				attribute_values = hierarchy.get("attributeValues", [])

				if hierarchy_label == "Region" and attribute_values:
					region = attribute_values[0].get("valueName")
				elif hierarchy_label == "Bundle" and attribute_values:
					bundle = attribute_values[0].get("valueName")
				elif hierarchy_label == "Environment" and attribute_values:
					environment = attribute_values[0].get("valueName")

			if region and bundle and environment:
				return (region, bundle, environment)

		except Exception as e:
			self.logger.error(f"Error extracting region/bundle/env from JSON authorization: {e}")

		return None

	def get_unique_bundle_env_combinations(self, users: List[IdentityUser]) -> List[Tuple[str, str]]:

		all_combinations = []

		for user in users:
			user_combinations = self.extract_bundle_env_from_user(user)
			all_combinations.extend(user_combinations)

		unique_combinations = []
		for combo in all_combinations:
			if combo not in unique_combinations:
				unique_combinations.append(combo)

		return unique_combinations

	def get_unique_region_bundle_env_combinations(self, users: List[IdentityUser]) -> List[Tuple[str, str, str]]:

		all_combinations = []

		for user in users:
			user_combinations = self.extract_region_bundle_env_from_user(user)
			all_combinations.extend(user_combinations)

		unique_combinations = []
		for combo in all_combinations:
			if combo not in unique_combinations:
				unique_combinations.append(combo)

		return unique_combinations
