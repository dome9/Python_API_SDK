#!/usr/bin/env python

import json
import requests
from re import match
from requests import ConnectionError
from requests.auth import HTTPBasicAuth
from typing import Dict


class Dome9ApiSDK(object):
	_URL = 'https://api.dome9.com/v2/accesslease/aws'
	# UUID format '01234567-89ab-cdef-01234-567890123456'
	_UUID_REGEX = r'^[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}$'
	# Secret format '0123456789abcdefghijklmnopqrstuvwxyz'
	_SECRET_REGEX = '^[0-9a-z]+$'
	REGIONS = {'us_east_1', 'us_west_1', 'eu_west_1', 'ap_southeast_1', 'ap_northeast_1', 'us_west_2', 'sa_east_1', 'az_1_region_a_geo_1', 'az_2_region_a_geo_1',
	            'az_3_region_a_geo_1', 'ap_southeast_2', 'mellanox_region', 'us_gov_west_1', 'eu_central_1', 'ap_northeast_2', 'ap_south_1', 'us_east_2', 'ca_central_1',
	            'eu_west_2', 'eu_west_3', 'eu_north_1', 'cn_north_1', 'cn_northwest_1', 'us_gov_east_1', 'westus', 'eastus', 'eastus2', 'northcentralus', 'westus2',
	            'southcentralus', 'centralus', 'usgovlowa', 'usgovvirginia', 'northeurope', 'westeurope', 'eastasia', 'southeastasia', 'japaneast', 'japanwest', 'brazilsouth',
	            'australiaeast', 'australiasoutheast', 'centralindia', 'southindia', 'westindia', 'canadaeast', 'westcentralus', 'chinaeast', 'chinanorth', 'canadacentral',
	            'germanycentral', 'germanynortheast', 'koreacentral', 'uksouth', 'ukwest', 'koreasouth'}
	# Duration format [D].H:M:S '1.0:0:0' '2:0:0'
	_DURATION_REGEX = r'^((0\.)|([1-9]\d*\.))?((\d)|(1\d)|(2[0-4])):((\d)|([1-5]\d)):((\d)|([1-5]\d))$'
	# IP format '192.168.0.10'
	_IP_REGEX = r'^(((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d)|([1-9]\d)|(1\d{2})|(2[0-4]\d)|(25[0-5]))$'
	# Email format 'abc@google.com'
	_EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
	PROTOCOLS = {'ALL', 'HOPOPT', 'ICMP', 'IGMP', 'GGP', 'IPV4', 'ST', 'TCP', 'CBT', 'EGP', 'IGP', 'BBN_RCC_MON', 'NVP2', 'PUP', 'ARGUS', 'EMCON', 'XNET', 'CHAOS', 'UDP', 'MUX',
	              'DCN_MEAS', 'HMP', 'PRM', 'XNS_IDP', 'TRUNK1', 'TRUNK2', 'LEAF1', 'LEAF2', 'RDP', 'IRTP', 'ISO_TP4', 'NETBLT', 'MFE_NSP', 'MERIT_INP', 'DCCP', 'ThreePC', 'IDPR',
	              'XTP', 'DDP', 'IDPR_CMTP', 'TPplusplus', 'IL', 'IPV6', 'SDRP', 'IPV6_ROUTE', 'IPV6_FRAG', 'IDRP', 'RSVP', 'GRE', 'DSR', 'BNA', 'ESP', 'AH', 'I_NLSP', 'SWIPE',
	              'NARP', 'MOBILE', 'TLSP', 'SKIP', 'ICMPV6', 'IPV6_NONXT', 'IPV6_OPTS', 'CFTP', 'SAT_EXPAK', 'KRYPTOLAN', 'RVD', 'IPPC', 'SAT_MON', 'VISA', 'IPCV', 'CPNX', 'CPHB',
	              'WSN', 'PVP', 'BR_SAT_MON', 'SUN_ND', 'WB_MON', 'WB_EXPAK', 'ISO_IP', 'VMTP', 'SECURE_VMTP', 'VINES', 'TTP', 'NSFNET_IGP', 'DGP', 'TCF', 'EIGRP', 'OSPFIGP',
	              'SPRITE_RPC', 'LARP', 'MTP', 'AX25', 'IPIP', 'MICP', 'SCC_SP', 'ETHERIP', 'ENCAP', 'GMTP', 'IFMP', 'PNNI', 'PIM', 'ARIS', 'SCPS', 'QNX', 'AN', 'IPCOMP', 'SNP',
	              'COMPAQ_PEER', 'IPX_IN_IP', 'VRRP', 'PGM', 'L2TP', 'DDX', 'IATP', 'STP', 'SRP', 'UTI', 'SMP', 'SM', 'PTP', 'ISIS', 'FIRE', 'CRTP', 'CRUDP', 'SSCOPMCE', 'IPLT',
	              'SPS', 'PIPE', 'SCTP', 'FC', 'RSVP_E2E_IGNORE', 'MOBILITY_HEADER', 'UDPLITE', 'MPLS_IN_IP', 'MANET', 'HIP', 'SHIM6', 'WESP', 'ROHC'}
	_HEADER = {
		'Accept'      : 'application/json',
		'Content-Type': 'application/json'
	}

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
		if user is not None and not match(Dome9ApiSDK._EMAIL_REGEX, user): raise ValueError

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
		try:
			response = requests.post(url=Dome9ApiSDK._URL, data=data, headers=Dome9ApiSDK._HEADER, auth=auth)

		except requests.ConnectionError as ex:
			raise ConnectionError(Dome9ApiSDK._URL, ex.message)

		jsonObject = None
		err = None

		if response.status_code in range(200, 299):
			try:
				if response.content:
					jsonObject = response.json()

			except Exception as ex:
				err = {
					'code'   : response.status_code,
					'message': ex.message,
					'content': response.content
				}
		else:
			err = {
				'code'   : response.status_code,
				'message': response.reason,
				'content': response.content
			}

		if err:
			raise Exception(err)

		return jsonObject


'''import json
import requests
import urlparse
from requests import ConnectionError, auth


class Dome9ApiSDK(object):
	REGION_PROTECTION_MODES = ['FullManage', 'ReadOnly', 'Reset']
	SEC_GRP_PROTECTION_MODES = ['FullManage', 'ReadOnly']

	@staticmethod
	def getJson(path):
		with open(path) as jsonFile:
			return json.load(jsonFile)

	def __init__(self, apiKeyID, apiSecret, apiAddress='https://api.dome9.com', apiVersion='v2'):
		self.apiKeyID = apiKeyID
		self.apiSecret = apiSecret
		self.apiAddress = apiAddress
		self.apiVersion = '/{}/'.format(apiVersion)
		self.baseAddress = self.apiAddress + self.apiVersion
		self.clientAuth = auth.HTTPBasicAuth(self.apiKeyID, self.apiSecret)
		self.restHeaders = {'Accept': 'application/json', 'Content-Type': 'application/json'}
		if not self.apiKeyID or not self.apiSecret:
			raise Exception('Cannot create api client instance without keyID and secret!')

# System methods
	def get(self, route, payload=None):
		return self.request('get', route, payload)

	def post(self, route, payload=None):
		return self.request('post', route, payload)

	def patch(self, route, payload=None):
		return self.request('patch', route, payload)

	def put(self, route, payload=None):
		return self.request('put', route, payload)

	def delete(self, route, payload=None):
		return self.request('delete', route, payload)

	def request(self, method, route, payload=None, isV2=True):
		res = None
		url = None
		try:
			url = urlparse.urljoin(self.baseAddress, route)
			if method == 'get':
				res = requests.get(url=url, params=payload, headers=self.restHeaders, auth=self.clientAuth)

			elif method == 'post':
				res = requests.post(url=url, data=payload, headers=self.restHeaders, auth=self.clientAuth)

			elif method == 'patch':
				res = requests.patch(url=url, json=payload, headers=self.restHeaders, auth=self.clientAuth)

			elif method == 'put':
				res = requests.put(url=url, data=payload, headers=self.restHeaders, auth=self.clientAuth)

			elif method == 'delete':
				res = requests.delete(url=url, params=payload, headers=self.restHeaders, auth=self.clientAuth)

		except requests.ConnectionError as ex:
			raise ConnectionError(url, ex.message)

		jsonObject = None
		err = None

		if res.status_code in range(200, 299):
			try:
				if res.content:
					jsonObject = res.json()

			except Exception as ex:
				err = {
					'code': res.status_code,
					'message': ex.message,
					'content': res.content
				}
		else:
			err = {
				'code': res.status_code,
				'message': res.reason,
				'content': res.content
		    }

		if err:
			raise Exception(err)
		return jsonObject

	# Dome9 Methods
	def getAllUsers(self, outAsJson=False):
		apiCall = self.get(route='user')
		if outAsJson:
			print(json.dumps(apiCall))
		return apiCall

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