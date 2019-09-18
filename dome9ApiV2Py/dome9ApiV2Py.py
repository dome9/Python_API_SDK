#!/usr/bin/env python

from enum import Enum
from urllib.parse import urljoin
import json
import requests
from re import match
from requests import ConnectionError
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Union, Optional, List


class Method(Enum):
	GET = 'get'
	POST = 'post'
	PATCH = 'patch'
	PUT = 'put'
	DELETE = 'delete'


class Protocol(Enum):
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


class Region(Enum):
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


class RegionProtectionMode(Enum):
	FULL_MANAGE = 'FullManage'
	READ_ONLY = 'ReadOnly'
	RESET = 'Reset'


class SecGrpProtectionMode(Enum):
	FullManage = 'FullManage'
	ReadOnly = 'ReadOnly'


class OperationMode(Enum):
	READ = 'Read'
	MANAGED = 'Managed'


class Dome9ApiSDK(object):
	_ORIGIN = 'https://api.dome9.com/v2/'
	# UUID format '01234567-89ab-cdef-01234-567890123456'
	_UUID_REGEX = r'^[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}$'
	# Secret format '0123456789abcdefghijklmnopqrstuvwxyz'
	_SECRET_REGEX = '^[0-9a-z]+$'
	# HTTP URL format http://www.domain:80/page.html
	_HTTP_URL_REGEX = r'^(http)s?://(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,6}\.?|[a-zA-Z0-9-]{2,}\.?)|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/?|[/?]\S+)$'

	@staticmethod
	def getJson(path):
		with open(path) as jsonFile:
			return json.load(jsonFile)

	def __init__(self, id: str, secret: str, origin: str = _ORIGIN):

		# <- add docstring here

		if not match(Dome9ApiSDK._UUID_REGEX, id): raise ValueError
		if not match(Dome9ApiSDK._SECRET_REGEX, secret): raise ValueError
		if not match(Dome9ApiSDK._HTTP_URL_REGEX, origin): raise ValueError

		self._origin = origin
		self._clientAuth = HTTPBasicAuth(id, secret)

	def _request(self, method: Method, route: str, payload: Dict[str, Any] = {}) -> Dict[str, Any]:

		# <- add docstring here

		restHeader = {
			'Accept'      : 'application/json',
			'Content-Type': 'application/json'
		}
		url = urljoin(self._origin, route)
		try:
			response = getattr(requests, method.value)(url=url, params=payload, headers=restHeader, auth=self._clientAuth)
		except requests.ConnectionError as connectionError:
			raise ConnectionError(url + ' ' + str(connectionError))
		if response.status_code not in range(200, 299):
			exception = {
				'code'   : response.status_code,
				'message': response.reason,
				'content': response.content
			}
			raise Exception(exception)
		if response.content:
			try:
				jsonResponse = response.json()
				return jsonResponse
			except ValueError as valueError:
				exception = {
					'code'   : response.status_code,
					'message': str(valueError),
					'content': response.content
				}
				raise Exception(exception)

	def getAllUsers(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='user')

	def getCloudAccounts(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='CloudAccounts')

	def getCloudAccountID(self, id: Union[str, int]) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='CloudAccounts/{}'.format(id))

	def getCloudAccountRegions(self, id: Union[str, int]) -> Dict[str, Any]:

		# <- add docstring here

		cloudAccountID = self.getCloudAccountID(id=id)
		return {region['region'] for region in cloudAccountID['netSec']['regions']}

	def getRoles(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='role')

	def onBoardingAwsAccount(self, arn: str, secret: str, fullProtection: bool = False, allowReadOnly: bool = False, name: Optional[str] = None) -> Dict[str, Any]:

		# <- add docstring here

		route = 'CloudAccounts'
		data = {
			'name'          : name,
			'credentials'   : {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			},
			'fullProtection': fullProtection,
			'allowReadOnly' : allowReadOnly
		}
		return self.post(route=route, payload=json.dumps(data))

	def onBoardingAzureAccount(self, subscriptionID: str, tenantID: str, clientID: str, clientPassword: str, name: Optional[str] = None,
	                           operationMode: OperationMode = OperationMode.READ) -> Dict[str, Any]:

		# <- add docstring here

		data = {
			'name'          : name,
			'subscriptionId': subscriptionID,
			'tenantId'      : tenantID,
			'credentials'   : {
				'clientId'      : clientID,
				'clientPassword': clientPassword
			},
			'operationMode' : operationMode,
		}
		route = 'AzureCloudAccount'
		return self.post(route=route, payload=json.dumps(data))

	def updateAwsAccountCredentials(self, arn: str, secret: str, externalAccountNumber: Optional[str] = None, cloudAccountID: Optional[str] = None) -> Dict[str, Any]:

		# <- add docstring here

		data = {
			'data': {
				'arn'   : arn,
				'secret': secret,
				'type'  : 'RoleBased'
			}
		}
		if cloudAccountID:
			data['cloudAccountId'] = cloudAccountID
		if externalAccountNumber:
			data['externalAccountNumber'] = externalAccountNumber
		route = 'CloudAccounts/credentials'
		return self.put(route=route, payload=json.dumps(data))

	def updateOrganizationalUnitForAWSCloudAccount(self, cloudAccountID: str, organizationalUnitID: Optional[str] = None) -> Dict[str, Any]:

		# <- add docstring here

		data = {'organizationalUnitId': organizationalUnitID}

		route = 'cloudaccounts/{}/organizationalUnit'.format(cloudAccountID)
		return self.put(route=route, payload=json.dumps(data))

	def updateOrganizationalUnitForAzureCloudAccount(self, cloudAccountID: str, organizationalUnitID: Optional[str] = None) -> Dict[str, Any]:

		# <- add docstring here

		data = {'organizationalUnitId': organizationalUnitID}

		route = 'AzureCloudAccount/{}/organizationalUnit'.format(cloudAccountID)
		return self.put(route=route, payload=json.dumps(data))

	def updateRoleByID(self, roleID: int, roleName: str, access: List[str] = [], manage: List[str] = [], create: List[str] = [], view: List[str] = [],
	                   crossAccountAccess: List[str] = []) -> Dict[str, Any]:

		# <- add docstring here

		data = {
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
		return self.put(route=route, payload=json.dumps(data))

	def getRoleByID(self, roleID: int) -> Dict[str, Any]:

		# <- add docstring here

		route = 'Role/{}'.format(roleID)
		return self.get(route=route)

	'''def updateCloudAccountID(self, id, data):

		# <- add docstring here

		apiCall = self.patch(route='CloudAccounts/{}'.format(id), payload=data)
		return apiCall'''

	def getCloudTrail(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='CloudTrail')

	def getFlatOrganizationalUnits(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='organizationalunit/GetFlatOrganizationalUnits')

	def getAwsSecurityGroups(self) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='view/awssecuritygroup/index')

	'''def getCloudSecurityGroup(self, id: str) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='cloudsecuritygroup/{}'.format(id))'''

	def getAllEntityFetchStatus(self, cloudAccountId: str) -> Dict[str, Any]:

		# <- add docstring here

		return self.get(route='EntityFetchStatus?cloudAccountId={}'.format(cloudAccountId))

	def cloudAccountSyncNow(self, id: str) -> Dict[str, Any]:

		# <- add docstring here

		return self.post(route='cloudaccounts/{}/SyncNow'.format(id))

	def setCloudSecurityGroupProtectionMode(self, id: str, protectionMode: SecGrpProtectionMode) -> Dict[str, Any]:

		# <- add docstring here

		if protectionMode not in Dome9ApiSDK.SEC_GRP_PROTECTION_MODES:
			raise ValueError('Valid modes are: {}'.format(Dome9ApiSDK.SEC_GRP_PROTECTION_MODES))

		data = json.dumps({'protectionMode': protectionMode})
		route = 'cloudsecuritygroup/{}/protection-mode'.format(id)
		return self.post(route=route, payload=data)

	def runAssessmentBundle(self, assReq) -> Dict[str, Any]:# add individual arguments

		# <- add docstring here

		data = json.dumps(assReq)
		route = 'assessment/bundleV2'
		return self.post(route=route, payload=data)

	def getAccountBundles(self, outAsJson=False):
		apiCall = self.get(route='CompliancePolicy')
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateRuleBundleByID(self, ruleID, ruleSet, outAsJson=False):
		data = {'id': ruleID, 'rules': ruleSet}
		apiCall = self.put(route='CompliancePolicy', payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall
		
		
		
		
		
	'''
	#_URL = 'https://api.dome9.com/v2/accesslease/aws'
	# UUID format '01234567-89ab-cdef-01234-567890123456'
	_UUID_REGEX = r'^[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}$'
	# Secret format '0123456789abcdefghijklmnopqrstuvwxyz'
	_SECRET_REGEX = '^[0-9a-z]+$'
	# Duration format [D].H:M:S '1.0:0:0' '2:0:0'
	_DURATION_REGEX = r'^((0\.)|([1-9]\d*\.))?((\d)|(1\d)|(2[0-4])):((\d)|([1-5]\d)):((\d)|([1-5]\d))$'
	# IP format '192.168.0.10'
	_IP_REGEX = r'^(((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))$'
	# Email format 'abc@google.com'
	_EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
	
	@staticmethod
	def acquireAwsLease(id: str, secret: str, cloudAccountId: str, securityGroupId: int, ip: str, portFrom: int, portTo: int = None, protocol: str = 'ALL', duration: str = '1:0:0',
	                    region: str = None, accountId: int = None, name: str = None, user: str = None) -> Dict:
		"""Acquires an AWS lease

		Args:
			id (str): API key.
			secret (str): API secret.
			cloudAccountId (str): AWS account id.
			securityGroupId (int): Security Group affected by lease.
			ip (str): IP address that will be granted elevated access.
			portFrom (int): Lowest IP port in range for the lease.
			portTo (int): Highest IP port in range for the lease. Defaults to None.
			protocol (str): Network protocol to be used in the lease. Defaults to 'ALL'.
			duration (str): Duration of the lease ([D].H:M:S). Defaults to '1:0:0'.
			region (str): AWS region. Defaults to None.
			accountId (int): Account id. Defaults to None.
			name (str): Defaults to None.
			user (str): User for whom the lease was created. Defaults to None.

		"""

		Dome9ApiSDK.validateInput(accountId, cloudAccountId, duration, id, ip, portFrom, portTo, protocol, region, secret, securityGroupId, user)

		temp_data = {
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
		data = {key: temp_data[key] for key in temp_data if temp_data[key] is not None}
		data = json.dumps(data)
		auth = HTTPBasicAuth(id, secret)
		

	@staticmethod
	def validateInput(accountId, cloudAccountId, duration, id, ip, portFrom, portTo, protocol, region, secret, securityGroupId, user):
		if not match(Dome9ApiSDK._UUID_REGEX, id): raise ValueError
		if not match(Dome9ApiSDK._SECRET_REGEX, secret): raise ValueError
		if not match(Dome9ApiSDK._UUID_REGEX, cloudAccountId): raise ValueError
		if securityGroupId < 0: raise ValueError
		if not match(Dome9ApiSDK._IP_REGEX, ip): raise ValueError
		if portFrom < 0 or portFrom > 65535: raise ValueError
		if portTo is not None and (portTo < 0 or portTo > 65535): raise ValueError
		if protocol not in Dome9ApiSDK.PROTOCOLS: raise ValueError
		if not match(Dome9ApiSDK._DURATION_REGEX, duration): raise ValueError
		if region is not None and region not in Dome9ApiSDK.REGIONS: raise ValueError
		if accountId is not None and accountId < 0: raise ValueError
		if user is not None and not match(Dome9ApiSDK._EMAIL_REGEX, user): raise ValueError'''


'''import json
import requests
import urlparse
from requests import ConnectionError, auth


class Dome9ApiSDK(object):

	@staticmethod
	def getJson(path):
		with open(path) as jsonFile:
			return json.load(jsonFile)



	def getCloudAccounts(self, outAsJson=False):
		apiCall = self.get(route='CloudAccounts')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getCloudAccountID(self, ID, outAsJson=False):
		apiCall = self.get(route='CloudAccounts/{}'.format(ID))
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getCloudAccountRegions(self, ID, outAsJson=False):
		cloudAccID = self.getCloudAccountID(ID=ID)
		apiCall = [region['region'] for region in cloudAccID['netSec']['regions']]
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getRoles(self, outAsJson=False):
		apiCall = self.get(route='role')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def onBoardingAwsAccount(self,arn, secret, fullProtection=False, allowReadOnly=False, name=None, outAsJson=False):

		data = {
				"name":name,
				"credentials":{
					"arn":arn,
					"secret":secret,
					"type":"RoleBased"
				},
				"fullProtection":fullProtection,
				"allowReadOnly": allowReadOnly
				}

		route = 'CloudAccounts'
		apiCall = self.post(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def onBoardingAzureAccount(self, subscriptionID, tenantID, clientID, clientPassword, name=None, operationMode='Read', outAsJson=False):

		data = {
			"name": name,
			"subscriptionId": subscriptionID,
			"tenantId": tenantID,
			"credentials": {
				"clientId": clientID,
				"clientPassword": clientPassword
			},
			"operationMode": operationMode,
		}

		route = 'AzureCloudAccount'
		apiCall = self.post(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateAwsAccountCredentials(self, arn, secret, externalAccountNumber=None, cloudAccountID=None,  outAsJson=False):

		data = {
			 "data": {
			   "arn": arn,
			   "secret": secret,
			   "type": "RoleBased"
			 }
			}

		if cloudAccountID:
			data['cloudAccountId'] = cloudAccountID
		if externalAccountNumber:
			data['externalAccountNumber'] = externalAccountNumber

		route = 'CloudAccounts/credentials'
		apiCall = self.put(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateOrganizationalUnitForAWSCloudAccount(self,cloudAccountID, organizationalUnitID=None, outAsJson=False):

		data = {"organizationalUnitId": organizationalUnitID}

		route = 'cloudaccounts/{}/organizationalUnit'.format(cloudAccountID)
		apiCall = self.put(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateOrganizationalUnitForAzureCloudAccount(self,cloudAccountID, organizationalUnitID=None, outAsJson=False):

		data = {"organizationalUnitId": organizationalUnitID}

		route = 'AzureCloudAccount/{}/organizationalUnit'.format(cloudAccountID)
		apiCall = self.put(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateRoleByID(self, roleID, roleName, permissions, outAsJson=False):

		data = {
					"name": roleName,
					"permissions": permissions
				}

		route = 'Role/{}'.format(roleID)
		apiCall = self.put(route=route, payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def getRoleByID(self, roleID, outAsJson=False):

		route = 'Role/{}'.format(roleID)
		apiCall = self.get(route=route)
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateCloudAccountID(self, ID, data, outAsJson):
		apiCall = self.patch(route='CloudAccounts/{}'.format(ID), payload=data)
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getCloudTrail(self, outAsJson):
		apiCall = self.get(route='CloudTrail')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getFlatOrganizationalUnits(self, outAsJson):
		apiCall = self.get(route='organizationalunit/GetFlatOrganizationalUnits')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getAwsSecurityGroups(self, outAsJson=False):
		apiCall = self.get(route='view/awssecuritygroup/index')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getCloudSecurityGroup(self, ID, outAsJson=False):
		apiCall = self.get(route='cloudsecuritygroup/{}'.format(ID))
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getAllEntityFetchStatus(self, ID, outAsJson=False):
		apiCall = self.get(route='EntityFetchStatus?cloudAccountId={}'.format(ID))

		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def cloudAccountSyncNow(self, ID, outAsJson=False):
		apiCall = self.post(route='cloudaccounts/{}/SyncNow'.format(ID))
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def setCloudSecurityGroupProtectionMode(self, ID, protectionMode, outAsJson=False):
		if protectionMode not in Dome9ApiSDK.SEC_GRP_PROTECTION_MODES:
			raise ValueError('Valid modes are: {}'.format(Dome9ApiSDK.SEC_GRP_PROTECTION_MODES))

		data = json.dumps({ 'protectionMode': protectionMode })
		route = 'cloudsecuritygroup/{}/protection-mode'.format(ID)
		apiCall = self.post(route=route, payload=data)
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def runAssessmenBundle(self, assReq, outAsJson=False): # assessmentRequest
		data = json.dumps(assReq)
		route = 'assessment/bundleV2'
		apiCall = self.post(route=route, payload=data)
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

	def getAccountBundles(self, outAsJson=False):
		apiCall = self.get(route='CompliancePolicy')
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall

	def updateRuleBundleByID(self, ruleID, ruleSet, outAsJson=False):
		data = {'id': ruleID, 'rules': ruleSet}
		apiCall = self.put(route='CompliancePolicy', payload=json.dumps(data))
		if outAsJson:
			print(json.dumps(apiCall))

		return apiCall


class Dome9ApiClient(Dome9ApiSDK):

	def getCloudSecurityGroupsInRegion(self, region, names=False):
		groupID = 'name' if names else 'id'
		return [secGrp[groupID] for secGrp in self.getAwsSecurityGroups() if secGrp['regionId'] == region]

	def getCloudSecurityGroupsIDsOfVpc(self, vpcID):
		return [secGrp['id'] for secGrp in self.getAwsSecurityGroups() if secGrp['vpcId'] == vpcID]

	def getCloudSecurityGroupIDsOfVpc(self, vpcID):
		return [secGrp['id'] for secGrp in self.getAwsSecurityGroups() if secGrp['vpcId'] == vpcID]

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
			self.put(route='cloudaccounts/region-conf', payload=data)

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
'''
