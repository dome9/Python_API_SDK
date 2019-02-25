#!/usr/bin/env python
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import range
from builtins import object
import json
import requests
from requests import ConnectionError, auth
import urllib.parse

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
    def _get(self, route, payload=None):
        return self._request('get', route, payload)

    def _post(self, route, payload=None):
        return self._request('post', route, payload)

    def _patch(self, route, payload=None):
        return self._request('patch', route, payload)

    def _put(self, route, payload=None):
        return self._request('put', route, payload)

    def _delete(self, route, payload=None):
        return self._request('delete', route, payload)

    def _request(self, method, route, payload=None, isV2=True):
        res = None
        url = None
        try:
            url = urllib.parse.urljoin(self.baseAddress, route)
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
        apiCall = self._get(route='user')
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getCloudAccounts(self, outAsJson=False):
        apiCall = self._get(route='CloudAccounts')
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getCloudAccountID(self, ID, outAsJson=False):
        apiCall = self._get(route='CloudAccounts/{}'.format(ID))
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getCloudAccountRegions(self, ID, outAsJson=False):
        cloudAccID = self.getCloudAccountID(ID=ID)
        apiCall = [region['region'] for region in cloudAccID['netSec']['regions']]
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def updateCloudAccountID(self, ID, data, outAsJson):
        apiCall = self._patch(route='CloudAccounts/{}'.format(ID), payload=data)
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getCloudTrail(self, outAsJson):
        apiCall = self._get(route='CloudTrail')
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getAwsSecurityGroups(self, outAsJson=False):
        apiCall = self._get(route='view/awssecuritygroup/index')
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getCloudSecurityGroup(self, ID, outAsJson=False):
        apiCall = self._get(route='cloudsecuritygroup/{}'.format(ID))
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def getAllEntityFetchStatus(self, ID, outAsJson=False):
        apiCall = self._get(route='EntityFetchStatus?cloudAccountId={}'.format(ID))

        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def cloudAccountSyncNow(self, ID, outAsJson=False):
        apiCall = self._post(route='cloudaccounts/{}/SyncNow'.format(ID))
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def setCloudSecurityGroupProtectionMode(self, ID, protectionMode, outAsJson=False):
        if protectionMode not in Dome9ApiSDK.SEC_GRP_PROTECTION_MODES:
            raise ValueError('Valid modes are: {}'.format(Dome9ApiSDK.SEC_GRP_PROTECTION_MODES))

        data = json.dumps({'protectionMode': protectionMode})
        route = 'cloudsecuritygroup/{}/protection-mode'.format(ID)
        apiCall = self._post(route=route, payload=data)
        if outAsJson:
            print(json.dumps(apiCall))
        return apiCall

    def runAssessmenBundle(self, assReq, outAsJson=False):  # assessmentRequest
        data = json.dumps(assReq)
        route = 'assessment/bundleV2'
        apiCall = self._post(route=route, payload=data)
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
            self._put(route='cloudaccounts/region-conf', payload=data)

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
