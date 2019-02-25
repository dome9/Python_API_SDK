#!/usr/bin/env python
from __future__ import print_function
from builtins import str
from builtins import object
from dome9ApiV2Py import Dome9ApiClient
import time
import datetime
from datetime import datetime as timeFunc
import uuid
import argparse
import json
import sys
import calendar
import pytz


class FetchEntityStatus(object):
    EMPTY_DATE = '0001-01-01T00:00:00Z'
    RUN_TIME_OUT = 60
    RUN_INTERVALS = 10
    SERVICES = [
        "DynamoDbTable",
        "Ec2Images",
        "Inspector",
        "IamServerCertificate",
        "VirtualMfaDevices",
        "Kinesis",
        "NetworkInterface",
        "Route53Domain",
        "Route53HostedZone",
        "AcmCertificate",
        "S3Bucket",
        "CloudFront",
        "IamPasswordPolicy",
        "IamUser",
        "IamUserInlinePolicies",
        "IamUserAttachedPolicies",
        "IamUserGroups" ,
        "IamRole",
        "IamRoleAttachedPolices",
        "IamRoleInlinePolicies",
        "VPNConnection",
        "AwsSecurityGroup",
        "Lambda"
    ]
    NONE_REGION_NAME = "regionless"

    def __init__(self, inputArgs):
        self.feachStatusList = []
        self.assessmentTemplateID = inputArgs.assessmentTemplateID
        self.assessmentRegion = inputArgs.assessmentRegion if inputArgs.assessmentRegion else None
        self.assessmentCloudAccountType = inputArgs.assessmentCloudAccountType if inputArgs.assessmentCloudAccountType else None
        self.externalAccountNumber = inputArgs.externalAccountNumber if inputArgs.externalAccountNumber else None
        self.cloudAccountID = inputArgs.cloudAccountID if inputArgs.cloudAccountID else None

        if not self.cloudAccountID and not self.externalAccountNumber:
            sys("You must use on os the following: --cloudAccountId or --externalAccountNumber")

        self.d9client = Dome9ApiClient(apiKeyID=inputArgs.apiKeyID, apiSecret=inputArgs.secretKey)

        if self.externalAccountNumber:
            self.accountId = self.d9client.getCloudAccountID(self.externalAccountNumber)['id']
            self.assessmentCloudAccountType = "AWS"
        if self.cloudAccountID:
            self.accountId = self.cloudAccountID
            if not self.assessmentCloudAccountType:
                sys.exit("cloudAccountID require using: --assessmentCloudAccountType")

    def getDeltaInMillisec(self, nowUtcTimeInEpoc, apiDateTime):

        apiDate, apiTime = apiDateTime.split('T')
        apiYear, apiMonth, apiDay = apiDate.split('-')
        apiHour, apiMinutes, apiSecondsMilliseconds = apiTime.split(':')

        if len(apiSecondsMilliseconds.split('.')) == 1:
            apiSeconds = apiSecondsMilliseconds.split('Z')[0]
        else:
            apiSeconds = apiSecondsMilliseconds.split('.')[0]

        apiDateTimeConverted = timeFunc(int(apiYear), int(apiMonth), int(apiDay), int(apiHour), int(apiMinutes), int(apiSeconds), 0, pytz.UTC)

        apiInSeconds = int(calendar.timegm(apiDateTimeConverted.utctimetuple()))

        deltaInMillisec = apiInSeconds - nowUtcTimeInEpoc

        return deltaInMillisec

    def validateService(self, service):
        return True if service in FetchEntityStatus.SERVICES else False

    def isFetchFinished(self):
        for entity in self.feachStatusList:
            for entityID, entityObject in entity.items():
                if not entityObject['isUpdated']:
                    return False
        return True

    def getFetchFinishedCount(self):
        feachCount = 0
        for entity in self.feachStatusList:
            for entityID, entityObject in entity.items():
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
        entityStatusList = self.d9client.getAllEntityFetchStatus(self.accountId)
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
            for entityObjectID, entityObject in entity.items():
                entityID = '{}-{}'.format(entityName, region)
                if entityObjectID == entityID:
                    entityObject['isUpdated'] = True

    def getUnUpdatedEntities(self):
        unUpdatedList = []
        for entity in self.feachStatusList:
            for entityObjectID, entityObject in entity.items():
                if not entityObject['isUpdated'] and not entityObject['type'] in unUpdatedList:
                    unUpdatedList.append(entityObject['type'])
        return unUpdatedList

    def isFetchUpdated(self, nowUtcTimeInEpoc, apiTime):
        if apiTime == FetchEntityStatus.EMPTY_DATE:
            return False
        if self.getDeltaInMillisec(nowUtcTimeInEpoc, apiTime) > 0:
            return True

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

        call = self.d9client.runAssessmenBundle(bundle, outAsJson=True)
        return call

    def fetchAllEntityStatus(self):
        self.buildFetchList()
        print('Process sync now...')
        print ("waiting for entities types: {} \n--------------------------\n".format(json.dumps(self.getUnUpdatedEntities())))
        self.d9client.cloudAccountSyncNow(self.accountId, outAsJson=True)
        nowUTCTime = timeFunc.utcnow()
        nowUtcTimeInEpoc = int(calendar.timegm(nowUTCTime.utctimetuple()))
        print('{}Waiting for entity to be update...'.format(timeFunc.utcnow()))
        timeCount = 0
        while not self.isFetchFinished():
            apiEntityStatusList = self.d9client.getAllEntityFetchStatus(self.accountId)
            for apiEntityStatus in apiEntityStatusList:
                if self.validateService(apiEntityStatus['entityType']):
                    isSuccessRun = self.isFetchUpdated(nowUtcTimeInEpoc, apiEntityStatus['lastSuccessfulRun'])
                    isFailedRun = self.isFetchUpdated(nowUtcTimeInEpoc, apiEntityStatus['lastFailureRun'])
                    if isSuccessRun or isFailedRun:
                        self.updateFetchStatus(apiEntityStatus['entityType'], apiEntityStatus['region'])
            timeCount += 1
            if timeCount == FetchEntityStatus.RUN_TIME_OUT:
                print ("unupdated entities types: {}".format(json.dumps(self.getUnUpdatedEntities())))
                break
            print ('{}{}: Progress Update: {}/{}'.format(timeCount,timeFunc.utcnow(), self.getFetchFinishedCount(), len(self.feachStatusList)))
            print ("waiting for entities types: {} \n--------------------------\n".format(json.dumps(self.getUnUpdatedEntities())))

            time.sleep(FetchEntityStatus.RUN_INTERVALS)
        print("running bundle...")
        #self.runAssessmentBundle()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    useExample = '--target AwsNetworkInterface_RegionDis_patcher_i-0ad1f21a0dd009cb7 --service microserviceApp --env stg or --target i-0ad1f21a0dd009cb7 '
    parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)
    parser.add_argument('--apiKeyID', required=True, type=str)
    parser.add_argument('--secretKey', required=True, type=str)
    parser.add_argument('--externalAccountNumber', required=False, type=str)
    parser.add_argument('--cloudAccountID', required=False, type=str)
    parser.add_argument('--assessmentTemplateID', required=True, type=str)
    parser.add_argument('--assessmentRegion', required=False, type=str)
    parser.add_argument('--assessmentCloudAccountType', required=False, choices=['AWS', 'AZURE', 'GCP'])

    args = parser.parse_args()
    print(timeFunc.utcnow())
    FetchEntityStatusObject = FetchEntityStatus(args)
    FetchEntityStatusObject.fetchAllEntityStatus()
    print(timeFunc.utcnow())
