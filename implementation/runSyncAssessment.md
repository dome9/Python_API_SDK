# Run Sync Assessment


Table of Contents
=================
* [Tool Description](#tool-description)
* [Supported entities](#supported-entities)
  * [AWS entities](#aws-entities)
  * [Azure entites](#azure-entites)
  * [Google entites](#google-entites)
* [Setup Steps](#setup-steps)
  * [Prerequisites](#Prerequisites)
  * [Parameters](#Parameters)
* [Usage examples](#usage-examples)


# Tool Description
This tool verifies that an assessment run will be performed after the entites are most up to date.
The tool run SyncNow process, waiting for an answer for every supported entity and then checks all the other supported entities to be mostly up to date prior running an assessment.


# Supported entities
## AWS Entities

- DynamoDb (SyncNow supported)
- Ec2Images (SyncNow supported)
- Inspector (SyncNow supported)
- IamServerCertificate (SyncNow supported)
- VirtualMfaDevices (SyncNow supported)
- KinesisStream (SyncNow supported)
- NetworkInterface (SyncNow supported)
- Route53Domains (SyncNow supported)
- Route53HostedZones (SyncNow supported)
- AcmCertificate (SyncNow supported)
- S3Bucket (SyncNow supported)
- CloudFrontDistribution (SyncNow supported)
- IamPasswordPolicy (SyncNow supported)
- IamUsers (SyncNow supported)
- IamUserInlinePolicies (SyncNow supported)
- IamUserAttachedPolicies (SyncNow supported)
- IamUserGroups (SyncNow supported)
- RolesFetchJob (SyncNow supported)
- IamRoleAttachedPolicies (SyncNow supported)
- IamRoleInlinePolicies (SyncNow supported)
- AppLoadBalancer
- ElastiCacheStatus
- Instance
- InternetGateway
- RouteTables
- SecurityGroup
- VpnGateway
- CloudTrail
- ConfigurationRecorders
- DbInstance
- DirectConnectConnection
- DirectConnectVirtualInterface
- Efs
- Elb
- IamAccountSummary
- IamCredentialReport
- IamGroups
- IamPolicies
- IamUser
- Kms
- KmsAlias
- Lambda
- LogGroups
- MetricAlarms
- Nacl
- RedshiftCluster
- Subnet
- Vpc
- VpcEndpoint
- VpcFlowLogs
- VpcPeeringConnection
- WAFRegional

## Azure Entities

- LoadBalancer
- NetworkInterface
- PublicIP
- ResourceGroup
- Subnet
- VirtualMachine
- VirtualNetwork

## Google Entities

- GoogleCloudFirewall
- GoogleCloudInstance
- GoogleCloudNetwork
- GoogleCloudSubnet


# Setup Steps
## Prerequisites 

- Dome9 API keyID and secret 
- Installed python >= 2.7 
- Python modules:
    - time 
    - datetime
    - uuid
    - argparse
    - sys
    - dome9ApiV2Py

## Parameters

* apiKeyID (String): Dome9 API key
* secretKey (String): Dome9 secret key
* cloudAccountID (String): vendor cloud account id
* externalAccountNumber (String): AWS cloud account id
* assessmentTemplateID (integer): Assessment bundle id
* assessmentRegion (String, optional): Vendor region
* assessmentCloudAccountType (String, optional): Allowed paramaters:  'AWS', 'AZURE', 'GCP'


# Usage examples

**example to use AWS external account id:**
runSyncAssessment.py --assessmentTemplateID -4 --externalAccountNumber 123456789 --secretKey {secretKey} --apiKeyID {apiKeyID}

**example to use any vendor with dome9 cloud account id:**
runSyncAssessment.py --assessmentTemplateID -4 --cloudAccountID 123456789 --assessmentCloudAccountType AWS --secretKey {secretKey} --apiKeyID {apiKeyID}
