#!/usr/bin/env python

import json
import requests
from re import match
from enum import Enum
from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Union, Optional, List, Set


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


class OperationModes(Enum):
	READ = 'Read'
	MANAGED = 'Managed'


class ProtectionModes(Enum):
	FULL_MANAGE = 'FullManage'
	READ_ONLY = 'ReadOnly'


class CloudAccountTypes(Enum):
	AWS = 'Aws'
	AZURE = 'Azure'
	GOOGLE = 'Google'
	KUBERNETES = 'Kubernetes'


class NewGroupBehaviors(Enum):
	READ_ONLY = 'ReadOnly'
	FULL_MANAGE = 'FullManage'
	RESET = 'Reset'


class Vendors(Enum):
	AWS = 'aws'
	AZURE = 'azure'
	GOOGLE = 'google'
	KUBERNETES = 'kubernetes'


class Dome9APISDK:
	class _RequestMethods(Enum):
		GET = 'get'
		POST = 'post'
		PATCH = 'patch'
		PUT = 'put'
		DELETE = 'delete'


	_ORIGIN = 'https://api.dome9.com/v2/'

	@staticmethod
	def _checkIsUUID(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', arg):
			raise ValueError

	@staticmethod
	def _checkOnlyContainsLowercaseAlphanumeric(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match('^[0-9a-z]+$', arg):
			raise ValueError

	@staticmethod
	def _checkIsHTTPURL(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match(
				r'^(http)s?://(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,6}\.?|[a-zA-Z0-9-]{2,}\.?)|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/?|[/?]\S+)$',
				arg):
			raise ValueError

	@staticmethod
	def _checkIsARN(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match('^arn:aws[^:]*:[^:]*:[^:]*:[^:]*:[^:]*(:[^:]*)?$', arg):
			raise ValueError

	@staticmethod
	def _checkIsIP(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match(r'^(((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))$', arg):
			raise ValueError

	@staticmethod
	def _checkIsDuration(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match(r'^((0\.)|([1-9]\d*\.))?((\d)|(1\d)|(2[0-4])):((\d)|([1-5]\d)):((\d)|([1-5]\d))$', arg):
			raise ValueError

	@staticmethod
	def _checkIsEmail(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', arg):
			raise ValueError

	@staticmethod
	def _checkIsUUIDOr12Digits(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if not match(r'^\d{12}$', arg) and not match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', arg):
			raise ValueError

	@staticmethod
	def _checkIsNotNegative(arg: int, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if arg < 0:
			raise ValueError

	@staticmethod
	def _checkIsNotEmpty(arg: str, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if arg == '':
			raise ValueError

	@staticmethod
	def _checkIsPort(arg: int, optional: bool = False) -> None:
		if optional and arg is None:
			return
		if arg < 0 or arg > 65535:
			raise ValueError

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

		Dome9APISDK._checkIsUUID(key)
		Dome9APISDK._checkOnlyContainsLowercaseAlphanumeric(secret)
		Dome9APISDK._checkIsHTTPURL(origin)

		self._origin = origin
		self._clientAuth = HTTPBasicAuth(key, secret)

	def _request(self, method: _RequestMethods, route: str, body: Any = None, params: Optional[Dict[str, Union[str, int]]] = None) -> Any:
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

	def getCloudAccountId(self, cloudAccountId: str) -> Dict[str, Any]:
		"""Fetch a specific AWS cloud account.

		Args:
			cloudAccountId (str): Dome9 AWS account id (UUID) or the AWS external account number (12 digit number)

		Returns:
			AWS cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUIDOr12Digits(cloudAccountId)

		route = 'CloudAccounts/{}'.format(cloudAccountId)
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def getCloudAccountRegions(self, cloudAccountId: str) -> Set[str]:
		"""Get all regions used in cloud account.

		Args:
			cloudAccountId (str): Dome9 AWS account id (UUID) or the AWS external account number (12 digit number).

		Returns:
			List of regions.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUIDOr12Digits(cloudAccountId)

		cloudAccountId = self.getCloudAccountId(cloudAccountId=cloudAccountId)
		return {region['region'] for region in cloudAccountId['netSec']['regions']}

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

		Dome9APISDK._checkIsARN(arn)
		Dome9APISDK._checkOnlyContainsLowercaseAlphanumeric(secret)

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

	def onBoardingAzureAccount(self, subscriptionId: str, tenantId: str, clientId: str, clientPassword: str, name: Optional[str] = None,
	                           operationMode: OperationModes = OperationModes.READ) -> None:
		"""Add (onboard) an Azure account to the user's Dome9 account.

		Args:
			subscriptionId (str): Azure subscription id for account.
			tenantId (str): Azure tenant id.
			clientId (str): Azure account id.
			clientPassword (str): Password for account.
			name (str, optional): Account name (in Dome9). Defaults to None.
			operationMode (OperationModes): Dome9 operation mode for the Azure account (Read or Managed). Defaults to Read.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUID(subscriptionId)
		Dome9APISDK._checkIsUUID(tenantId)
		Dome9APISDK._checkIsUUID(clientId)

		route = 'AzureCloudAccount'
		body = {
			'name'          : name,
			'subscriptionId': subscriptionId,
			'tenantId'      : tenantId,
			'credentials'   : {
				'clientId'      : clientId,
				'clientPassword': clientPassword
			},
			'operationMode' : operationMode.value,
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	def updateAwsAccountCredentials(self, arn: str, secret: str, externalAccountNumber: Optional[str] = None, cloudAccountId: Optional[str] = None) -> None:
		"""Update credentials for an AWS cloud account in Dome9. At least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber".

		Args:
			arn (str): AWS Role ARN (to be assumed by Dome9 System).
			secret (str): The AWS role External ID (Dome9 System will have to use this secret in order to assume the role).
			externalAccountNumber (str, optional): Aws external account number, at least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber". Defaults to None.
			cloudAccountId (str, optional): The Dome9 cloud account id, at least one of the following properties must be provided: "cloudAccountId", "externalAccountNumber". Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsARN(arn)
		Dome9APISDK._checkOnlyContainsLowercaseAlphanumeric(secret)
		# check externalAccountNumber format
		Dome9APISDK._checkIsUUID(cloudAccountId, optional=True)

		route = 'CloudAccounts/credentials'
		body = {
			'cloudAccountId'       : cloudAccountId,
			'externalAccountNumber': externalAccountNumber,
			'data'                 : {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			}
		}
		self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateOrganizationalUnitForAWSCloudAccount(self, cloudAccountId: str, organizationalUnitId: Optional[str] = None) -> Dict[str, Any]:
		"""Update the ID of the Organizational unit that this cloud account will be attached to. Use 'null' for root organizational unit.

		Args:
			cloudAccountId (str): Guid ID of the AWS cloud account.
			organizationalUnitId (str, optional): Guid ID of the Organizational Unit to attach to. Use null in order to attach to root Organizational Unit. Defaults to None.

		Returns:
			Cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUID(cloudAccountId)
		Dome9APISDK._checkIsUUID(organizationalUnitId, optional=True)

		route = 'cloudaccounts/{}/organizationalUnit'.format(cloudAccountId)
		body = {
			'organizationalUnitId': organizationalUnitId
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateOrganizationalUnitForAzureCloudAccount(self, cloudAccountId: str, organizationalUnitId: Optional[str] = None) -> Dict[str, Any]:
		"""Update the ID of the Organizational unit that this cloud account will be attached to. Use 'null' for root organizational unit.

		Args:
			cloudAccountId (str): Guid ID of the Azure cloud account.
			organizationalUnitId (str, optional): Guid ID of the Organizational Unit to attach to. Use null in order to attach to root Organizational Unit. Defaults to None.

		Returns:
			Azure cloud account.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUID(cloudAccountId)
		Dome9APISDK._checkIsUUID(organizationalUnitId, optional=True)

		route = 'AzureCloudAccount/{}/organizationalUnit'.format(cloudAccountId)
		body = {
			'organizationalUnitId': organizationalUnitId
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def updateRoleById(self, roleId: int, roleName: str, access: Optional[List[str]] = None, manage: Optional[List[str]] = None, create: Optional[List[str]] = None,
	                   view: Optional[List[str]] = None,
	                   crossAccountAccess: Optional[List[str]] = None) -> None:
		"""Update a role.

		Args:
			roleId (int): Role id.
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

		Dome9APISDK._checkIsNotNegative(roleId)
		Dome9APISDK._checkIsNotEmpty(roleName)

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
		route = 'Role/{}'.format(roleId)
		self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def getRoleById(self, roleId: int) -> Dict[str, Any]:
		"""Get the specific role with the specified id.

		Args:
			roleId (int): Role id.

		Returns:
			Role.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsNotNegative(roleId)

		route = 'Role/{}'.format(roleId)
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	# doesn't exist in documentation
	def updateCloudAccountID(self, cloudAccountId: str, name: Optional[str] = None, fullProtection: Optional[bool] = None, allowReadOnly: Optional[bool] = None,
	                         organizationalUnitId: Optional[str] = None, organizationalUnitPath: Optional[str] = None, organizationalUnitName: Optional[str] = None,
	                         lambdaScanner: Optional[bool] = None, arn: Optional[str] = None, secret: Optional[str] = None) -> None:
		"""Edit an existing AWS cloud account on Dome9.

		Args:
			cloudAccountId (str): Dome9 id.
			name (str, optional): Cloud account name. Defaults to None.
			fullProtection (bool, optional): As part of the AWS account onboarding, the account security groups are imported. This flag determines whether to enable Tamper Protection mode for those security groups. Defaults to None.
			allowReadOnly (bool, optional): Determines the AWS cloud account operation mode. For "Manage" set to true, for "Readonly" set to false. Defaults to None.
			organizationalUnitId (str, optional): -. Defaults to None.
			organizationalUnitPath (str, optional): -. Defaults to None.
			organizationalUnitName (str, optional): -. Defaults to None.
			lambdaScanner (bool, optional): Flag indicating if lambda scanner is enabled/disabled for the account. Defaults to None.
			arn (str, optional): AWS Role ARN (to be assumed by Dome9 System). Defaults to None.
			secret (str, optional): AWS role External ID (Dome9 System will have to use this secret in order to assume the role). Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsUUID(cloudAccountId)
		Dome9APISDK._checkIsUUID(organizationalUnitId, optional=True)
		# validate organizationalUnitPath
		# validate organizationalUnitName
		Dome9APISDK._checkIsARN(arn)
		Dome9APISDK._checkOnlyContainsLowercaseAlphanumeric(secret)

		route = 'CloudAccounts/{}'.format(cloudAccountId)
		body = {
			'name'                   : name,
			'fullProtection'         : fullProtection,
			'allowReadOnly'          : allowReadOnly,
			'organizationalUnitId'   : organizationalUnitId,
			'organizationalUnitPath' : organizationalUnitPath,
			'organizationalUnitName' : organizationalUnitName,
			'lambdaScanner'          : lambdaScanner,
			'CloudAccountCredentials': {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			}
		}
		self._request(method=Dome9APISDK._RequestMethods.PATCH, route=route, body=body)

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

	# doesn't exist in documentation
	def getAwsSecurityGroups(self):
		"""Get all security groups.

		Returns:
			Security groups.

		Raises:
			Dome9APIException: API command failed.
		"""

		return self._request(method=Dome9APISDK._RequestMethods.GET, route='view/awssecuritygroup/index')

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

		Dome9APISDK._checkIsUUID(cloudAccountId)

		route = 'cloudsecuritygroup/{}'.format(cloudAccountId)
		params = {
			'cloudAccountId': cloudAccountId,
			'regionId'      : regionId.value
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

		Dome9APISDK._checkIsUUID(cloudAccountId)

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

		Dome9APISDK._checkIsUUID(cloudAccountId)

		route = 'cloudaccounts/{}/SyncNow'.format(cloudAccountId)
		return self._request(method=Dome9APISDK._RequestMethods.POST, route=route)

	def setCloudSecurityGroupProtectionMode(self, securityGroupId: str, protectionMode: ProtectionModes) -> None:
		"""Change the protection mode for an AWS security group.

		Args:
			securityGroupId (str): AWS security group id (Dome9 internal ID / AWS security group ID).
			protectionMode (ProtectionModes): Details for the security group, including the protection mode. Only 'ProtectionMode' is required in this call (FullManage or ReadOnly).

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		# validate securityGroupId

		route = 'cloudsecuritygroup/{}/protection-mode'.format(securityGroupId)
		body = {
			'protectionMode': protectionMode
		}
		self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	def runAssessmentBundle(self, bundleId: int, cloudAccountId: str, cloudAccountType: CloudAccountTypes, name: Optional[str], description: Optional[str], isCft: Optional[bool],
	                        dome9CloudAccountId: Optional[str], externalCloudAccountId: Optional[str], region: Optional[Regions], cloudNetwork: Optional[str],
	                        rootName: Optional[str], params: Optional[List[Dict]], files: Optional[List[Dict]]) -> Dict[str, Any]:
		"""Run an assessment on a cloud environment using a bundle (V2).

		Args:
			bundleId (int): Bundle id.
			cloudAccountId (str): Account id on cloud provider (AWS, Azure, GCP).
			cloudAccountType (CloudAccountTypes): Cloud provider (AWS/Azure/GCP).
			name (str, optional): Bundle name. Defaults to None.
			description (str, optional): Bundle description. Defaults to None.
			isCft (bool, optional): Indicates request target is a CFT (template file). Defaults to None.
			dome9CloudAccountId (str, optional): Dome9 account id. Defaults to None.
			externalCloudAccountId (str, optional): Account id on cloud provider (AWS, Azure, GCP). Defaults to None.
			region (Regions, optional): Cloud region for the account. Defaults to None.
			cloudNetwork (str, optional): Cloud provider (AWS/Azure/GCP). Defaults to None.
			rootName (str, optional): -. Defaults to None.
			params (List[Dict], optional): -. Defaults to None.
			files (List[Dict], optional): -. Defaults to None.

		Returns:
			Assessment result (aggregates results from multiple tests).

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APISDK._checkIsNotNegative(bundleId)
		# validate cloudAccountId
		# validate dome9CloudAccountId
		# validate externalCloudAccountId
		# validate cloudNetwork
		# validate rootName
		# validate params
		# validate files

		route = 'assessment/bundleV2'
		body = {
			'id'                    : bundleId,
			'cloudAccountId'        : cloudAccountId,
			'cloudAccountType'      : cloudAccountType.value,
			'name'                  : name,
			'description'           : description,
			'isCft'                 : isCft,
			'dome9CloudAccountId'   : dome9CloudAccountId,
			'externalCloudAccountId': externalCloudAccountId,
			'region'                : region.value,
			'cloudNetwork'          : cloudNetwork,
			'cft'                   : {
				'rootName': rootName,
				'params'  : params,
				'files'   : files
			}
		}
		return self._request(method=Dome9APISDK._RequestMethods.POST, route=route, body=body)

	def getAccountBundles(self) -> List[Any]:
		"""Get all bundles.

		Returns:
			List of rule bundle results.

		Raises:
			Dome9APIException: API command failed.
		"""

		route = 'CompliancePolicy'
		return self._request(method=Dome9APISDK._RequestMethods.GET, route=route)

	def updateRuleBundleById(self, bundleId: int, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
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

		Dome9APISDK._checkIsNotNegative(bundleId)
		# validate rules

		route = 'CompliancePolicy'
		body = {
			'id'   : bundleId,
			'rules': rules
		}
		return self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def acquireAwsLease(self, cloudAccountId: str, securityGroupId: int, ip: str, portFrom: int, portTo: Optional[int] = None, protocol: Optional[Protocols] = None,
	                    duration: Optional[str] = None,
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

		Dome9APISDK._checkIsUUID(cloudAccountId)
		Dome9APISDK._checkIsNotNegative(securityGroupId)# doc says is string
		Dome9APISDK._checkIsIP(ip)
		Dome9APISDK._checkIsPort(portFrom)
		Dome9APISDK._checkIsPort(portTo, optional=True)
		Dome9APISDK._checkIsDuration(duration, optional=True)
		Dome9APISDK._checkIsNotNegative(accountId, optional=True)
		Dome9APISDK._checkIsEmail(user, optional=True)

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

	def getCloudSecurityGroupsInRegion(self, region: Regions, names: bool = False) -> Set[Union[str, int]]:
		"""Get all security groups in region.

		Args:
			region (Regions): The region.
			names (bool, optional): Should the group names be returned instead of ids. Defaults to False.

		Returns:
			Security groups.

		Raises:
			Dome9APIException: API command failed.
		"""

		groupId = 'name' if names else 'id'
		return {securityGroup[groupId] for securityGroup in self.getAwsSecurityGroups() if securityGroup['regionId'] == region.value}

	def getCloudSecurityGroupsOfVPC(self, vpcId: str, names: bool = False) -> Set[Union[str, int]]:
		"""Get all security groups of VPC.

		Args:
			vpcId (str): The VPC.
			names (bool, optional): Should the group names be returned instead of ids. Defaults to False.

		Returns:
			Security groups.

		Raises:
			Dome9APIException: API command failed.
		"""

		# validate vpcId

		groupId = 'name' if names else 'id'
		return {securityGroup[groupId] for securityGroup in self.getAwsSecurityGroups() if securityGroup['vpcId'] == vpcId}

	def getCloudSecurityGroupsOfAccount(self, accountId: int) -> Set[str]:
		"""Get all security groups of account.

		Args:
			accountId (int):

		Returns:
			Security groups.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APIClient._checkIsNotNegative(accountId)

		return {securityGroup['externalId'] for securityGroup in self.getAwsSecurityGroups() if securityGroup['awsAccountId'] == accountId}

	def setCloudRegionsProtectedMode(self, cloudAccountId: str, newGroupBehavior: NewGroupBehaviors, regions: Optional[Set[Regions]] = None) -> None:
		"""Update AWS cloud account region configurations.

		Args:
			cloudAccountId (str): Dome9 AWS account id (UUID) or the AWS external account number (12 digit number).
			newGroupBehavior (NewGroupBehaviors): The Protection Mode that Dome9 will apply to new security groups detected in the cloud account. ReadOnly New Security Groups will be included in Dome9 in Read-Only mode, without changes to any of the rules. FullManage New Security Groups will be included in Dome9 in Full Protection mode, without changes to any of the rules. Reset New Security Groups will be included in Dome9 in Full Protection mode, and all inbound and outbound rules will be cleared
			regions (Regions, optional): Dome9 representation value for the AWS region. Defaults to None.

		Raises:
			Dome9APIException: API command failed.
		"""

		# validate cloudAccountId

		tempAllUserRegions = self.getCloudAccountRegions(cloudAccountId=cloudAccountId)
		regionMap = {region.value: region for region in Regions}
		allUserRegions = {regionMap[region] for region in tempAllUserRegions}
		if regions is None:
			cloudAccountRegions = allUserRegions
		else:
			if not regions.issubset(allUserRegions):
				raise ValueError
			cloudAccountRegions = regions
		route = 'cloudaccounts/region-conf'
		for region in cloudAccountRegions:
			body = {
				'externalAccountNumber': cloudAccountId,
				'data'                 : {
					'region'          : region.value,
					'newGroupBehavior': newGroupBehavior.value
				}
			}
			self._request(method=Dome9APISDK._RequestMethods.PUT, route=route, body=body)

	def setCloudSecurityGroupsProtectionModeInRegion(self, region: Regions, protectionMode: ProtectionModes) -> None:
		"""Change the protection mode for all AWS security groups in region.

		Args:
			region (Regions):
			protectionMode (ProtectionModes):

		Raises:
			Dome9APIException: API command failed.
		"""

		securityGroups = self.getCloudSecurityGroupsInRegion(region=region)
		for securityGroupId in securityGroups:
			self.setCloudSecurityGroupProtectionMode(securityGroupId=securityGroupId, protectionMode=protectionMode)

	def setCloudSecurityGroupsProtectionModeOfVPC(self, vpcId: str, protectionMode: ProtectionModes) -> None:
		"""Change the protection mode for all AWS security groups of VPC.

		Args:
			vpcId (str):
			protectionMode (ProtectionModes):

		Raises:
			Dome9APIException: API command failed.
		"""

		# validate vpcId

		securityGroups = self.getCloudSecurityGroupsOfVPC(vpcId=vpcId)
		for securityGroupId in securityGroups:
			self.setCloudSecurityGroupProtectionMode(securityGroupId=securityGroupId, protectionMode=protectionMode)

	def updateOrganizationalUnitForCloudAccount(self, vendor: Vendors, cloudAccountId: str, organizationalUnitId: Optional[str] = None) -> None:
		"""Update the ID of the Organizational unit that this cloud account will be attached to. Use 'null' for root organizational unit.

		Args:
			vendor (Vendors): The vendor.
			cloudAccountId (str): Guid ID of the cloud account.
			organizationalUnitId (str): Guid ID of the Organizational Unit to attach to. Use null in order to attach to root Organizational Unit. Defaults to None.

		Raises:
			ValueError: Invalid input.
			Dome9APIException: API command failed.
		"""

		Dome9APIClient._checkIsUUID(cloudAccountId)
		Dome9APIClient._checkIsUUID(organizationalUnitId)

		if vendor == Vendors.AWS:
			self.updateOrganizationalUnitForAWSCloudAccount(cloudAccountId, organizationalUnitId)
		elif vendor == Vendors.AZURE:
			self.updateOrganizationalUnitForAzureCloudAccount(cloudAccountId, organizationalUnitId)
		else:
			raise NotImplementedError
