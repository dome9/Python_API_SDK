#!/usr/bin/env python

from enum import Enum
from urllib.parse import urljoin
import json
import requests
from re import match
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Union, Optional, List


class Dome9APIException(Exception):
	def __init__(self, message: str, code: Optional[int] = None, content: Optional[str] = None):
		super().__init__(message)
		self.code = code
		self.content = content


class Protocols(Enum):
	ALL = 'ALL'
	HOPOPT = 'HOPOPT'
	ICMP = 'ICMP'
	IGMP = 'IGMP'
	GGP = 'GGP'
	IPV4 = 'IPV4'
	ST = 'ST'
	TCP = 'TCP'
	CBT = 'CBT'
	EGP = 'EGP'
	IGP = 'IGP'
	BBN_RCC_MON = 'BBN_RCC_MON'
	NVP2 = 'NVP2'
	PUP = 'PUP'
	ARGUS = 'ARGUS'
	EMCON = 'EMCON'
	XNET = 'XNET'
	CHAOS = 'CHAOS'
	UDP = 'UDP'
	MUX = 'MUX'
	DCN_MEAS = 'DCN_MEAS'
	HMP = 'HMP'
	PRM = 'PRM'
	XNS_IDP = 'XNS_IDP'
	TRUNK1 = 'TRUNK1'
	TRUNK2 = 'TRUNK2'
	LEAF1 = 'LEAF1'
	LEAF2 = 'LEAF2'
	RDP = 'RDP'
	IRTP = 'IRTP'
	ISO_TP4 = 'ISO_TP4'
	NETBLT = 'NETBLT'
	MFE_NSP = 'MFE_NSP'
	MERIT_INP = 'MERIT_INP'
	DCCP = 'DCCP'
	ThreePC = 'ThreePC'
	IDPR = 'IDPR'
	XTP = 'XTP'
	DDP = 'DDP'
	IDPR_CMTP = 'IDPR_CMTP'
	TP_PLUS_PLUS = 'TPplusplus'
	IL = 'IL'
	IPV6 = 'IPV6'
	SDRP = 'SDRP'
	IPV6_ROUTE = 'IPV6_ROUTE'
	IPV6_FRAG = 'IPV6_FRAG'
	IDRP = 'IDRP'
	RSVP = 'RSVP'
	GRE = 'GRE'
	DSR = 'DSR'
	BNA = 'BNA'
	ESP = 'ESP'
	AH = 'AH'
	I_NLSP = 'I_NLSP'
	SWIPE = 'SWIPE'
	NARP = 'NARP'
	MOBILE = 'MOBILE'
	TLSP = 'TLSP'
	SKIP = 'SKIP'
	ICMPV6 = 'ICMPV6'
	IPV6_NONXT = 'IPV6_NONXT'
	IPV6_OPTS = 'IPV6_OPTS'
	CFTP = 'CFTP'
	SAT_EXPAK = 'SAT_EXPAK'
	KRYPTOLAN = 'KRYPTOLAN'
	RVD = 'RVD'
	IPPC = 'IPPC'
	SAT_MON = 'SAT_MON'
	VISA = 'VISA'
	IPCV = 'IPCV'
	CPNX = 'CPNX'
	CPHB = 'CPHB'
	WSN = 'WSN'
	PVP = 'PVP'
	BR_SAT_MON = 'BR_SAT_MON'
	SUN_ND = 'SUN_ND'
	WB_MON = 'WB_MON'
	WB_EXPAK = 'WB_EXPAK'
	ISO_IP = 'ISO_IP'
	VMTP = 'VMTP'
	SECURE_VMTP = 'SECURE_VMTP'
	VINES = 'VINES'
	TTP = 'TTP'
	NSFNET_IGP = 'NSFNET_IGP'
	DGP = 'DGP'
	TCF = 'TCF'
	EIGRP = 'EIGRP'
	OSPFIGP = 'OSPFIGP'
	SPRITE_RPC = 'SPRITE_RPC'
	LARP = 'LARP'
	MTP = 'MTP'
	AX25 = 'AX25'
	IPIP = 'IPIP'
	MICP = 'MICP'
	SCC_SP = 'SCC_SP'
	ETHERIP = 'ETHERIP'
	ENCAP = 'ENCAP'
	GMTP = 'GMTP'
	IFMP = 'IFMP'
	PNNI = 'PNNI'
	PIM = 'PIM'
	ARIS = 'ARIS'
	SCPS = 'SCPS'
	QNX = 'QNX'
	AN = 'AN'
	IPCOMP = 'IPCOMP'
	SNP = 'SNP'
	COMPAQ_PEER = 'COMPAQ_PEER'
	IPX_IN_IP = 'IPX_IN_IP'
	VRRP = 'VRRP'
	PGM = 'PGM'
	L2TP = 'L2TP'
	DDX = 'DDX'
	IATP = 'IATP'
	STP = 'STP'
	SRP = 'SRP'
	UTI = 'UTI'
	SMP = 'SMP'
	SM = 'SM'
	PTP = 'PTP'
	ISIS = 'ISIS'
	FIRE = 'FIRE'
	CRTP = 'CRTP'
	CRUDP = 'CRUDP'
	SSCOPMCE = 'SSCOPMCE'
	IPLT = 'IPLT'
	SPS = 'SPS'
	PIPE = 'PIPE'
	SCTP = 'SCTP'
	FC = 'FC'
	RSVP_E2E_IGNORE = 'RSVP_E2E_IGNORE'
	MOBILITY_HEADER = 'MOBILITY_HEADER'
	UDPLITE = 'UDPLITE'
	MPLS_IN_IP = 'MPLS_IN_IP'
	MANET = 'MANET'
	HIP = 'HIP'
	SHIM6 = 'SHIM6'
	WESP = 'WESP'
	ROHC = 'ROHC'


class Regions(Enum):
	US_EAST_1 = 'us_east_1'
	US_WEST_1 = 'us_west_1'
	EU_WEST_1 = 'eu_west_1'
	AP_SOUTHEAST_1 = 'ap_southeast_1'
	AP_NORTHEAST_1 = 'ap_northeast_1'
	US_WEST_2 = 'us_west_2'
	SA_EAST_1 = 'sa_east_1'
	AZ_1_REGION_A_GEO_1 = 'az_1_region_a_geo_1'
	AZ_2_REGION_A_GEO_1 = 'az_2_region_a_geo_1'
	AZ_3_REGION_A_GEO_1 = 'az_3_region_a_geo_1'
	AP_SOUTHEAST_2 = 'ap_southeast_2'
	MELLANOX_REGION = 'mellanox_region'
	US_GOV_WEST_1 = 'us_gov_west_1'
	EU_CENTRAL_1 = 'eu_central_1'
	AP_NORTHEAST_2 = 'ap_northeast_2'
	AP_SOUTH_1 = 'ap_south_1'
	US_EAST_2 = 'us_east_2'
	CA_CENTRAL_1 = 'ca_central_1'
	EU_WEST_2 = 'eu_west_2'
	EU_WEST_3 = 'eu_west_3'
	EU_NORTH_1 = 'eu_north_1'
	CN_NORTH_1 = 'cn_north_1'
	CN_NORTHWEST_1 = 'cn_northwest_1'
	US_GOV_EAST_1 = 'us_gov_east_1'


class RegionProtectionModes(Enum):
	FULL_MANAGE = 'FullManage'
	READ_ONLY = 'ReadOnly'
	RESET = 'Reset'


class OperationModes(Enum):
	READ = 'Read'
	MANAGED = 'Managed'


class ProtectionMode(Enum):
	FULL_MANAGE = 'FullManage'
	READ_ONLY = 'ReadOnly'


class Dome9APISDK:

	class _RequestMethods(Enum):
		GET = 'get'
		POST = 'post'
		PATCH = 'patch'
		PUT = 'put'
		DELETE = 'delete'

	_ORIGIN = 'https://api.dome9.com/v2/'
	# UUID format '01234567-89ab-cdef-01234-567890123456'
	_UUID_REGEX = r'^[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}$'
	_LOWERCASE_ALPHANUMERIC_REGEX = '^[0-9a-z]+$'
	_TWELVE_DIGITS_REGEX = r'^\d{12}$'
	# HTTP URL format http://www.domain:80/page.html
	_HTTP_URL_REGEX = r'^(http)s?://(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,6}\.?|[a-zA-Z0-9-]{2,}\.?)|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/?|[/?]\S+)$'
	# ARN format 'arn:partition:service:region:account-id:resource-type:resource-id'
	_ARN_REGEX = '^arn:aws[^:]*:[^:]*:[^:]*:[^:]*:[^:]*(:[^:]*)?$'
	# IP format '192.168.0.10'
	_IP_REGEX = r'^(((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))$'
	# Duration format [D].H:M:S '1.0:0:0' '2:0:0'
	_DURATION_REGEX = r'^((0\.)|([1-9]\d*\.))?((\d)|(1\d)|(2[0-4])):((\d)|([1-5]\d)):((\d)|([1-5]\d))$'
	# Email format 'abc@google.com'
	_EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

	@staticmethod
	def getJson(path: str) -> Any:
		"""Creates a Python object from a JSON file.

		Args:
			path (str): Path to the file.

		Returns:
			Python object.

		Raises:
			OSError: Could not read file.
			JSONDecodeError: Could not decode file contents.
		"""

		with open(file=path) as jsonFile:
			return json.load(jsonFile)

	def __init__(self, key: str, secret: str, origin: str = _ORIGIN):
		"""Initializes a Dome9 API SDK object.

		Args:
			key (str): API id (key).
			secret (str): API secret.
			origin (str): Origin of API (URL). Defaults to 'https://api.dome9.com/v2/'.
		"""

		if not match(Dome9APISDK._UUID_REGEX, key): raise ValueError
		if not match(Dome9APISDK._LOWERCASE_ALPHANUMERIC_REGEX, secret): raise ValueError
		if not match(Dome9APISDK._HTTP_URL_REGEX, origin): raise ValueError

		self._origin = origin
		self._clientAuth = HTTPBasicAuth(key, secret)

	def _request(self, method: _RequestMethods, route: str, body: Any = None, params: Optional[Dict[str, Union[str, int]]] = None) -> Any:
		"""Sends a HTTP request.

		Args:
			method (_RequestMethods): HTTP method.
			route (str): URL path (does not include origin).
			body (Any): JSON payload. Defaults to None.
			params (Dict[str, Union[str, int]], optional): Parameters. Defaults to None.

		Returns:
			API server's response.

		Raises:
			Dome9APIException: API command failed.
		"""

		url = urljoin(self._origin, route)
		headers = {
			'Accept'      : 'application/json',
			'Content-Type': 'application/json'
		}
		try:
			response = getattr(requests, method.value)(url=url, json=body, params=params, headers=headers, auth=self._clientAuth)
		except requests.ConnectionError as connectionError:
			raise Dome9APIException('{} {}'.format(url, str(connectionError)))
		if response.status_code not in range(200, 299):
			raise Dome9APIException(message=response.reason, code=response.status_code, content=response.content)
		if response.content:
			try:
				jsonResponse = response.json()
				return jsonResponse
			except ValueError as valueError:
				raise Dome9APIException(message=str(valueError), code=response.status_code, content=response.content)

	def getAllUsers(self) -> List[Any]:
		"""Get all Dome9 users.

		Returns:
			List of Dome9 users.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'user'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def getCloudAccounts(self) -> Dict[str, Any]:
		"""Get all AWS cloud accounts.

		Returns:
			List of AWS cloud accounts.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'CloudAccounts'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def getCloudAccountID(self, cloudAccountId: str) -> Dict[str, Any]:
		"""Fetch a specific AWS cloud account.

		Args:
			cloudAccountId (str): Dome9 AWS account id (UUID) or the AWS external account number (12 digit number)

		Returns:
			AWS cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._TWELVE_DIGITS_REGEX, cloudAccountId) and not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError

		route = 'CloudAccounts/{}'.format(cloudAccountId)
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def getCloudAccountRegions(self, cloudAccountId: str) -> List[str]:
		"""Get all regions used in cloud account.

		Args:
			cloudAccountId (str): Dome9 AWS account id (UUID) or the AWS external account number (12 digit number).

		Returns:
			List of regions.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._TWELVE_DIGITS_REGEX, cloudAccountId) and not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError

		cloudAccountID = self.getCloudAccountID(cloudAccountId=cloudAccountId)
		return list({region['region'] for region in cloudAccountID['netSec']['regions']})

	def getRoles(self) -> List[Any]:
		"""Get all roles.

		Returns:
			List of roles.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'role'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def onBoardingAwsAccount(self, arn: str, secret: str, fullProtection: bool = False, allowReadOnly: bool = False, name: Optional[str] = None) -> None:
		"""Add a new AWS cloud account to Dome9. Onboarding an AWS cloud account requires granting Dome9 permissions to access the account. The following document describes the required procedure: https://helpcenter.dome9.com/hc/en-us/articles/360003994613-Onboard-an-AWS-Account

		Args:
			arn (str): AWS Role ARN (to be assumed by Dome9 System)
			secret (str): AWS role External ID (Dome9 System will have to use this secret in order to assume the role)
			fullProtection (bool): As part of the AWS account onboarding, the account security groups are imported. This flag determines whether to enable Tamper Protection mode for those security groups. Defaults to False.
			allowReadOnly (bool): Determines the AWS cloud account operation mode. For "Manage" set to true, for "Readonly" set to false. Defaults to False.
			name (str, optional): Cloud account name. Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._ARN_REGEX, arn): raise ValueError
		if not match(Dome9APISDK._LOWERCASE_ALPHANUMERIC_REGEX, secret): raise ValueError

		route = 'CloudAccounts'
		body = {
			'name'          : name,
			'credentials'   : {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			},
			'fullProtection': fullProtection,
			'allowReadOnly' : allowReadOnly
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	def onBoardingAzureAccount(self, subscriptionID: str, tenantID: str, clientID: str, clientPassword: str, name: Optional[str] = None,
	                           operationMode: OperationModes = OperationModes.READ) -> None:
		"""Add (onboard) an Azure account to the user's Dome9 account.

		Args:
			subscriptionID (str): Azure subscription id for account.
			tenantID (str): Azure tenant id.
			clientID (str): Azure account id.
			clientPassword (str): Password for account.
			name (str, optional): Account name (in Dome9). Defaults to None.
			operationMode (OperationModes): Dome9 operation mode for the Azure account (Read or Managed). Defaults to Read.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, subscriptionID): raise ValueError
		if not match(Dome9APISDK._UUID_REGEX, tenantID): raise ValueError
		if not match(Dome9APISDK._UUID_REGEX, clientID): raise ValueError

		route = 'AzureCloudAccount'
		body = {
			'name'          : name,
			'subscriptionId': subscriptionID,
			'tenantId'      : tenantID,
			'credentials'   : {
				'clientId'      : clientID,
				'clientPassword': clientPassword
			},
			'operationMode' : operationMode,
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	def updateAwsAccountCredentials(self, arn: str, secret: str, externalAccountNumber: Optional[str] = None, cloudAccountID: Optional[str] = None) -> None:
		"""Update credentials for an AWS cloud account in Dome9. At least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber".

		Args:
			arn (str): AWS Role ARN (to be assumed by Dome9 System).
			secret (str): The AWS role External ID (Dome9 System will have to use this secret in order to assume the role).
			externalAccountNumber (str, optional): Aws external account number, at least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber". Defaults to None.
			cloudAccountID (str, optional): The Dome9 cloud account id, at least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber". Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._ARN_REGEX, arn): raise ValueError
		if not match(Dome9APISDK._LOWERCASE_ALPHANUMERIC_REGEX, secret): raise ValueError
		if externalAccountNumber is not None and not match(Dome9APISDK._LOWERCASE_ALPHANUMERIC_REGEX, externalAccountNumber): raise ValueError
		if cloudAccountID is not None and not match(Dome9APISDK._UUID_REGEX, cloudAccountID): raise ValueError

		route = 'CloudAccounts/credentials'
		body = {
			'cloudAccountId': cloudAccountID,
			'externalAccountNumber': externalAccountNumber,
			'data': {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			}
		}
		self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateOrganizationalUnitForAWSCloudAccount(self, cloudAccountID: str, organizationalUnitID: Optional[str] = None) -> Dict[str, Any]:
		"""Update the ID of the Organizational unit that this cloud account will be attached to. Use 'null' for root organizational unit.

		Args:
			cloudAccountID (str): Guid ID of the AWS cloud account.
			organizationalUnitID (str, optional): The Guid ID of the Organizational Unit to attach to. Use null in order to attach to root Organizational Unit. Defaults to None.

		Returns:
			Cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountID): raise ValueError
		if organizationalUnitID is not None and not match(Dome9APISDK._UUID_REGEX, organizationalUnitID): raise ValueError

		route = 'cloudaccounts/{}/organizationalUnit'.format(cloudAccountID)
		body = {
			'organizationalUnitId': organizationalUnitID
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateOrganizationalUnitForAzureCloudAccount(self, cloudAccountID: str, organizationalUnitID: Optional[str] = None) -> Dict[str, Any]:
		"""Update the ID of the Organizational unit that this cloud account will be attached to. Use 'null' for root organizational unit.

		Args:
			cloudAccountID (str): Guid ID of the Azure cloud account.
			organizationalUnitID (str, optional): Guid ID of the Organizational Unit to attach to. Use null in order to attach to root Organizational Unit. Defaults to None.

		Returns:
			Azure cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountID): raise ValueError
		if organizationalUnitID is not None and not match(Dome9APISDK._UUID_REGEX, organizationalUnitID): raise ValueError

		route = 'AzureCloudAccount/{}/organizationalUnit'.format(cloudAccountID)
		body = {
			'organizationalUnitId': organizationalUnitID
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateRoleByID(self, roleID: int, roleName: str, access: Optional[List[str]] = None, manage: Optional[List[str]] = None, create: Optional[List[str]] = None, view: Optional[List[str]] = None,
	                   crossAccountAccess: Optional[List[str]] = None) -> None:
		"""Update a role.

		Args:
			roleID (int): Role id.
			roleName (str): Role Name.
			access (List[str], optional): Access permission list (list of SRL). Defaults to None.
			manage (List[str], optional): Manage permission list (list of SRL). Defaults to None.
			create (List[str], optional): Create permission list (list of SRL). Defaults to None.
			view (List[str], optional): View permission list (list of SRL). Defaults to None.
			crossAccountAccess (List[str], optional): -. Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if roleID < 0: raise ValueError
		if roleName == '': raise ValueError

		body = {
			'name'       : roleName,
			'permissions': {
				'access'            : access,
				'manage'            : manage,
				'create'            : create,
				'view'              : view,
				'crossAccountAccess': crossAccountAccess
			}
		}
		route = 'Role/{}'.format(roleID)
		self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def getRoleByID(self, roleID: int) -> Dict[str, Any]:
		"""Get the specific role with the specified id.

		Args:
			roleID (int): Role id.

		Returns:
			Role.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if roleID < 0: raise ValueError

		route = 'Role/{}'.format(roleID)
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	'''def updateCloudAccountID(self, id: Union[str, int], data):

		# <- add docstring here

		apiCall = self.patch(route='CloudAccounts/{}'.format(id), payload=data)
		return apiCall'''

	def getCloudTrail(self) -> List[Any]:
		"""Get CloudTrail events for a Dome9 user.

		Returns:
			List of CloudTrail events.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'CloudTrail'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def getFlatOrganizationalUnits(self) -> List[Any]:
		"""Get all organizational units flat.

		Returns:
			List of flat organizational units.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'organizationalunit/GetFlatOrganizationalUnits'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	'''def getAwsSecurityGroups(self) -> Dict[str, Any]:

		# <- add docstring here

		return self._request(method=Dome9ApiSDK._RequestMethod.GET, route='view/awssecuritygroup/index')'''

	def getCloudSecurityGroup(self, cloudAccountId: str, regionId: Regions) -> List[Any]:
		"""Get AWS security groups for a specific cloud account and region.

		Args:
			cloudAccountId (str): Cloud account id.
			regionId (Regions): Region.

		Returns:
			List of security groups.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError

		route = 'cloudsecuritygroup/{}'.format(cloudAccountId)
		params = {
			'cloudAccountId': cloudAccountId,
			'regionId': regionId.value
		}
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route, params=params)

	def getAllEntityFetchStatus(self, cloudAccountId: str) -> List[Any]:
		"""This EntityFetchStatus resource queries the status of system data fetching by Dome9. Dome9 fetches information from cloud accounts and occasionally needs to refresh this information (typically in DevSecOps pipeline scenarios). This resource is used together with the SyncNow method in the CloudAccounts resource to fetch fresh cloud account data.

		Args:
			cloudAccountId (str): Dome9 CloudAccountId which can replace the AWS externalAccountNumber.

		Returns:
			List of fetcher run statuses.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError

		route = 'EntityFetchStatus'
		params = {
			'cloudAccountId': cloudAccountId
		}
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route, params=params)

	def cloudAccountSyncNow(self, cloudAccountId: str) -> Dict[str, Any]:
		"""Send a data sync command to immediately fetch cloud account data into Dome9's system caches. This API is used in conjunction with EntityFetchStatus API resource to query the fetch status. Read more and see a full example here: https://github.com/Dome9/Python_API_SDK/blob/master/implementation/runSyncAssessment.md

		Args:
			cloudAccountId (str): Account id.

		Returns:
			AWS sync now result.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError

		route = 'cloudaccounts/{}/SyncNow'.format(cloudAccountId)
		return self._request(method=Dome9APISDK._RequestMethods.POST, route=route)

	def setCloudSecurityGroupProtectionMode(self, securityGroupId: str, protectionMode: ProtectionMode) -> None:
		"""Change the protection mode for an AWS security group.

		Args:
			securityGroupId (str): AWS security group id (Dome9 internal ID / AWS security group ID).
			protectionMode (CloudSecurityGroupProtectionModeChange): Details for the security group, including the protection mode. Only 'ProtectionMode' is required in this call (FullManage or ReadOnly).

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		# <- check securityGroupId format

		route = 'cloudsecuritygroup/{}/protection-mode'.format(securityGroupId)
		body = {
			'protectionMode': protectionMode
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	'''def runAssessmentBundle(self, id, name, description, isCft, dome9CloudAccountId, externalCloudAccountId, cloudAccountId, region, cloudNetwork, cloudAccountType, requestId, params, files) -> Dict[str, Any]:
		# mandatory fields are: CloudAccountId, CloudAccountType, id
		# <- add docstring here

		data = assReq
		route = 'assessment/bundleV2'
		return self._request(method=Dome9ApiSDK._RequestMethod.POST, route=route, payload=data)'''

	def getAccountBundles(self) -> List[Any]:
		"""Get all bundles.

		Returns:
			List of rule bundle results.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'CompliancePolicy'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def updateRuleBundleByID(self, bundleId: int, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Update a Bundle.

		Args:
			bundleId (int): Bundle id.
			rules (List[Dict[str, Any]]): List of rules in the bundle.

		Return:
			Rule bundle result.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if bundleId < 0: raise ValueError
		# <- check rules format

		body = {
			'id': bundleId,
			'rules': rules
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route='CompliancePolicy', body=body)

	def acquireAwsLease(self, cloudAccountId: str, securityGroupId: Union[str, int], ip: str, portFrom: int, portTo: Optional[int] = None, protocol: Optional[Protocols] = None, duration: Optional[str] = None,
	                    region: Optional[Regions] = None, accountId: Optional[int] = None, name: Optional[str] = None, user: Optional[str] = None) -> None:
		"""Acquires an AWS lease.

		Args:
			cloudAccountId (str): AWS account id.
			securityGroupId (int): Security Group affected by lease.
			ip (str): IP address that will be granted elevated access.
			portFrom (int): Lowest IP port in range for the lease.
			portTo (int, optional): Highest IP port in range for the lease. Defaults to None.
			protocol (Protocols, optional): Network protocol to be used in the lease. Defaults to None.
			duration (str, optional): Duration of the lease ([D].H:M:S). Defaults to None.
			region (Regions, optional): AWS region. Defaults to None.
			accountId (int, optional): Account id. Defaults to None.
			name (str, optional): Defaults to None.
			user (str, optional): User for whom the lease was created. Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		if not match(Dome9APISDK._UUID_REGEX, cloudAccountId): raise ValueError
		if securityGroupId < 0: raise ValueError
		if not match(Dome9APISDK._IP_REGEX, ip): raise ValueError
		if portFrom < 0 or portFrom > 65535: raise ValueError
		if portTo is not None and (portTo < 0 or portTo > 65535): raise ValueError
		if not match(Dome9APISDK._DURATION_REGEX, duration): raise ValueError
		if accountId is not None and accountId < 0: raise ValueError
		if user is not None and not match(Dome9APISDK._EMAIL_REGEX, user): raise ValueError

		route = 'accesslease/aws'
		body = {
			'cloudAccountId' : cloudAccountId,
			'securityGroupId': securityGroupId,
			'ip'             : ip,
			'portFrom'       : portFrom,
			'portTo'         : portTo,
			'protocol'       : protocol,
			'length'         : duration,
			'region'         : region,
			'accountId'      : accountId,
			'name'           : name,
			'user'           : user
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)


class Dome9APIClient(Dome9APISDK):

	def getCloudSecurityGroupsInRegion(self, region: Regions, names: bool =False) -> List:
		"""?

		Args:
			region (Regions): ?
			names (bool, optional): ?

		Returns:
			?
		"""

		groupID = 'name' if names else 'id'
		return [secGrp[groupID] for secGrp in self.getAwsSecurityGroups() if secGrp['regionId'] == region]

	def getCloudSecurityGroupsIDsOfVpc(self, vpcID, names: bool =False):
		groupID = 'name' if names else 'id'
		return [secGrp[groupID] for secGrp in self.getAwsSecurityGroups() if secGrp['vpcId'] == vpcID]

	def getCloudSecurityGroupIDsOfVpc(self, vpcID, names: bool =False):
		groupID = 'name' if names else 'id'
		return [secGrp[groupID] for secGrp in self.getAwsSecurityGroups() if secGrp['vpcId'] == vpcID]

	def getCloudSecurityGroupsIdsOfAccount(self, accountID):
		return [secGrp['externalId'] for secGrp in self.getAwsSecurityGroups() if secGrp['awsAccountId'] == accountID]

	def setCloudRegionsProtectedMode(self, ID, protectionMode, regions='all'):
		if protectionMode not in Dome9ApiSDK.REGION_PROTECTION_MODES:
			raise ValueError('Valid modes are: {}'.format(Dome9ApiSDK.REGION_PROTECTION_MODES))

		allUsersRegions = self.getCloudAccountRegions(ID=ID)
		if regions == 'all':
			cloudAccountRegions = allUsersRegions
		else:
			if not set(regions).issubset(allUsersRegions):
				raise Exception('requested regions:{} are not a valid regions, available:{}'.format(regions, allUsersRegions))
			cloudAccountRegions = regions

		for region in cloudAccountRegions:
			data = json.dumps(
				{'externalAccountNumber': ID, 'data': {'region': region, 'newGroupBehavior': protectionMode}})
			print('updating data: {}'.format(data))
			self._request(method=Method.PUT, route='cloudaccounts/region-conf', payload=data)

	def setCloudSecurityGroupsProtectionModeInRegion(self, region, protectionMode):
		secGrpsRegion = self.getCloudSecurityGroupsInRegion(region=region)
		if not secGrpsRegion:
			raise ValueError('got 0 security groups!')
		for secGrpID in secGrpsRegion:
			self.setCloudSecurityGroupProtectionMode(ID=secGrpID, protectionMode=protectionMode, outAsJson=True)

	def setCloudSecurityGroupsProtectionModeOfVpc(self, vpcID, protectionMode):
		vpcSecGrp = self.getCloudSecurityGroupIDsOfVpc(vpcID=vpcID)
		if not vpcSecGrp:
			raise ValueError('got 0 security groups!')
		for secGrpID in vpcSecGrp:
			self.setCloudSecurityGroupProtectionMode(ID=secGrpID, protectionMode=protectionMode, outAsJson=True)

	def updateOrganizationalUnitForCloudAccount(self, vendor, cloudAccountID, organizationalUnitID):
		if vendor == 'aws':
			self.updateOrganizationalUnitForAWSCloudAccount(cloudAccountID, organizationalUnitID)
		elif vendor == 'azure':
			self.updateOrganizationalUnitForAzureCloudAccount(cloudAccountID, organizationalUnitID)
