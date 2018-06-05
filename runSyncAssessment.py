#!/usr/bin/env python
from dome9ApiV2Py import Dome9ApiClient
import time
import datetime
from datetime import datetime as timeFunc
import uuid
import argparse
import json
import sys

class FetchEntityStatus(object):
	EMPTY_DATE = '0001-01-01T00:00:00Z'
	RUN_TIME_OUT = 40
	RUN_INTERVALS = 60
	SERVICES = [
		"AzurePublicIP",
		"AzureNetworkInterface",
		"GoogleCloudSubnet",
		"GoogleCloudInstance",
		"AzureVirtualMachine",
		"AwsRouteTables",
		"AwsInstance",
		"GoogleCloudFirewall",
		"Elb",
		"Efs",
		"AppLoadBalancer",
		"Subnet",
		"Kms",
		"AwsSecurityGroup",
		"KmsAlias",
		"AzureVirtualNetwork",
		"VpcEndpoint",
		"AwsInternetGateway",
		"Nacl",
		"DirectConnectVirtualInterface",
		"DirectConnectConnection",
		"IamPolicies",
		"ConfigurationRecorders",
		"AzureLoadBalancer",
		"AwsVpnGateway",
		"AzureSubnet",
		"LogGroups",
		"AwsElastiCacheStatus",
		"GoogleCloudNetwork",
		"VpcFlowLogs",
		"AzureResourceGroup",
		"VpcPeeringConnection",
		"IamCredentialReport",
		"MetricAlarms",
		"RedshiftCluster",
		"DbInstance",
		"CloudTrail",
		"IamAccountSummary",
		"IamGroups",
		"Vpc",
		"AcmCertificate",
		"NetworkInterface",
		"CloudFront",
		"DynamoDbTable",
		"AMI",
		"IamPasswordPolicy",
		"IamRole",
		"IamRoleAttachedPolices",
		"IamRoleInlinePolicies",
		"IamServerCertificate",
		"IamUser",
		"IamUserAttachedPolicies",
		"IamUserGroups",
		"IamUserInlinePolicies",
		"Lambda",
		"Kinesis",
		"Route53Domain",
		"Route53HostedZone",
		"VirtualMfaDevices",
		"WAFRegional"
	]
	NONE_REGION_NAME = "regionless"
	
	def __init__(self, inputArgs):
		
		self.cloudAccountID = inputArgs.cloudAccountID
		self.assessmentTemplateID = inputArgs.assessmentTemplateID
		self.assessmentRegion = inputArgs.assessmentRegion if inputArgs.assessmentRegion else None
		self.assessmentCloudAccountType = inputArgs.assessmentCloudAccountType if inputArgs.assessmentCloudAccountType else None
		
		self.d9client = Dome9ApiClient(apiKeyID=inputArgs.apiKeyID, apiSecret=inputArgs.secretKey)
		self.accountId = self.d9client.getCloudAccountID(self.cloudAccountID, outAsJson=True)['id']
		self.feachStatusList = []
		
	
	def getDifTime(self, currentTime, inputTime):
		inputFormatTime = ' '.join(inputTime.split('Z')[0].split('T'))
		try:
			inputTimeStamp = int(datetime.datetime.strptime(inputFormatTime, '%Y-%m-%d %H:%M:%S.%f').strftime("%s"))
		except:
			inputTimeStamp = int(datetime.datetime.strptime(inputFormatTime, '%Y-%m-%d %H:%M:%S').strftime("%s"))
		
		currentFormatTime = currentTime.split('.')[0]
		currentTimeStamp = int(datetime.datetime.strptime(currentFormatTime, '%Y-%m-%d %H:%M:%S').strftime("%s"))
		
		diftime = inputTimeStamp - currentTimeStamp
		return diftime
	
	def validateService(self, service):
		return True if service in FetchEntityStatus.SERVICES else False
	
	def isFetchFinished(self):
		for entity in self.feachStatusList:
			for entityID, entityObject in entity.iteritems():
				if not entityObject['isUpdated']:
					return False
		return True
	
	def getFetchFinishedCount(self):
		feachCount = 0
		for entity in self.feachStatusList:
			for entityID, entityObject in entity.iteritems():
				if entityObject['isUpdated']:
					feachCount += 1
		return feachCount
	
	def returnEntityStatusObject(self, entity, region):
		if not region:
			region = FetchEntityStatus.NONE_REGION_NAME
		return {'{}-{}'.format(entity, region): {
			'type': entity,
			'region': region,
			'isUpdated': False
		}}
	
	def buildFetchList(self):
		entityStatusList = self.d9client.getAllEntityFetchStatus(self.cloudAccountID)
		if not entityStatusList:
			sys.exit("Fetch status list is empty, exit.")
		for entityStatus in entityStatusList:
			if self.validateService(entityStatus['entityType']):
				entityObject = self.returnEntityStatusObject(entityStatus['entityType'], entityStatus['region'])
				self.feachStatusList.append(entityObject)
		return self.feachStatusList
	
	def updateFetchStatus(self, entityName, region):
		if not region:
			region = FetchEntityStatus.NONE_REGION_NAME
		for entity in self.feachStatusList:
			for entityObjectID, entityObject in entity.iteritems():
				entityID = '{}-{}'.format(entityName, region)
				if entityObjectID == entityID:
					entityObject['isUpdated'] = True
	
	def getUnUpdatedEntities(self):
		unUpdatedList = []
		for entity in self.feachStatusList:
			for entityObjectID, entityObject in entity.iteritems():
				if not entityObject['isUpdated'] and not entityObject['type'] in unUpdatedList:
					unUpdatedList.append(entityObject['type'])
		return unUpdatedList
					
					
	def isFetchUpdated(self, startedTime, runTime):
		if runTime == FetchEntityStatus.EMPTY_DATE:
			return False
		diferanceInMs = self.getDifTime(str(startedTime), runTime)
		return True if diferanceInMs >= 0 else False
	
	
	def runAssessmentBundle(self):
		bundle = {
			'id': self.assessmentTemplateID,
			'cloudAccountId': self.accountId,
			'requestId': str(uuid.uuid4())
		}
		
		if self.assessmentRegion:
			bundle['region'] = self.assessmentRegion
		if self.assessmentCloudAccountType:
			bundle['cloudAccountType'] = self.assessmentCloudAccountType
			
		call = self.d9client.runAssessmenBundle(bundle)
		return call
	
	def fetchAllEntityStatus(self):
		self.buildFetchList()
		print('Process sync now...')
		call = self.d9client.cloudAccountSyncNow(self.accountId, outAsJson=True)
		startedTime = timeFunc.utcnow()
		print('Waiting for entity to be update...')
		timeCount = 0
		while not self.isFetchFinished():
			apiEntityStatusList = self.d9client.getAllEntityFetchStatus(self.cloudAccountID)
			print(apiEntityStatusList)
			for apiEntityStatus in apiEntityStatusList:
				if self.validateService(apiEntityStatus['entityType']):
					isSuccessRun = self.isFetchUpdated(startedTime, apiEntityStatus['lastSuccessfulRun'])
					isFailedRun = self.isFetchUpdated(startedTime, apiEntityStatus['lastFailureRun'])
					if isSuccessRun or isFailedRun:
						self.updateFetchStatus(apiEntityStatus['entityType'], apiEntityStatus['region'])
			timeCount += 1
			if timeCount == FetchEntityStatus.RUN_TIME_OUT:
				print ("unupdated entities: {}".format(json.dumps(self.getUnUpdatedEntities())))
				break
			print ('{}: Entities Updated: {}/{}'.format(timeCount, self.getFetchFinishedCount(), len(self.feachStatusList)))
			time.sleep(FetchEntityStatus.RUN_INTERVALS)
		self.runAssessmentBundle()


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='')
	useExample = '--target AwsNetworkInterface_RegionDis_patcher_i-0ad1f21a0dd009cb7 --service microserviceApp --env stg or --target i-0ad1f21a0dd009cb7 '
	parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)
	parser.add_argument('--apiKeyID', required=True, type=str)
	parser.add_argument('--secretKey', required=True, type=str)
	parser.add_argument('--cloudAccountID', required=True, type=str)
	parser.add_argument('--assessmentTemplateID', required=True, type=str)
	parser.add_argument('--assessmentRegion', required=False, type=str)
	parser.add_argument('--assessmentCloudAccountType', required=False, choices=['AWS', 'AZURE', 'GCP'])
	
	args = parser.parse_args()
	print(timeFunc.utcnow())
	FetchEntityStatusObject = FetchEntityStatus(args)
	FetchEntityStatusObject.fetchAllEntityStatus()
	print(timeFunc.utcnow())
