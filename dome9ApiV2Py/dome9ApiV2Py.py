#!/usr/bin/env python
import json
import requests
import urlparse
from requests import ConnectionError, auth


class Dome9ApiSDK(object):
	REGION_PROTECTION_MODES = ['FullManage', 'ReadOnly', 'Reset']
	SEC_GRP_PROTECTION_MODES = ['FullManage', 'ReadOnly']
	
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

	def acquireAwsLease(self, cloudAccountId, securityGroupId, ip, portFrom, portTo=None, protocol=None, length=None, region=None, accountId=None, name=None, outAsJson=False):
		route = 'accesslease/aws'
		temp_data = {
			'cloudAccountId' : cloudAccountId,
			'securityGroupId': securityGroupId,
			'ip'             : ip,
			'portFrom'       : portFrom,
			'portTo'         : portTo,
			'protocol'       : protocol,
			'length'         : length,
			'region'         : region,
			'accountId'      : accountId,
			'name'           : name
		}
		data = {key: value for key, value in temp_data if value is not None}
		apiCall = self.post(route=route, payload=json.dumps(data))
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
