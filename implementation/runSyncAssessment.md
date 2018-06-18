# Run Sync Assessment


Table of Contents
=================
* [Tool Description](#tool-description)
  * [Script Flow](#script-flow)
* [Setup Steps](#setup-steps)
  * [Prerequisites](#Prerequisites)
  * [Parameters](#Parameters)
* [Usage examples](#usage-examples)
* [Supported entities](#supported-entities)
  * [AWS entities](#aws-entities)
  * [Azure entites](#azure-entites)
  * [Google entites](#google-entites)
* [Not Supported entities](#not-supported-entities)

# Tool Description
This runs an assessment bundle after first checking that all cloud environment entities are up-to-date.

## Script Flow
- The script validates at runtime that all entities are up-to-date. It uses  SyncNow for each of the entities that support SyncNow, to check they are up-to-date.
- It waits 15 minutes for the entities that don't support SyncNow to be updated.
- After checking the entities are up-to-date, it runs the compliance assessments for the specified bundle ID, for the given cloud account.

# Setup Steps
## Prerequisites 

- Dome9 APIkeyID and secret
- The script files should be in the same folder as the Dome9 Python_API_SDK 
- Python 2.7 or later
- Python modules:
    - time 
    - datetime
    - uuid
    - argparse
    - sys
    - dome9ApiV2Py

## Parameters

* **apiKeyID** (String): Dome9 API key
* **secretKey** (String): Dome9 secret key
* **cloudAccountID** (String): vendor cloud account id
* **externalAccountNumber** (String): AWS cloud account id
* **assessmentTemplateID** (integer): Assessment bundle id
* **assessmentRegion** (String, optional): Vendor region
* **assessmentCloudAccountType** (String, optional): Cloud provider ('AWS', 'AZURE', 'GCP')


# Usage examples

**example to use an AWS external account id:**
runSyncAssessment.py --assessmentTemplateID -4 --externalAccountNumber 123456789 --secretKey {secretKey} --apiKeyID {apiKeyID}

**example to use for any cloud vendor, with a Dome9 cloud account id:**
runSyncAssessment.py --assessmentTemplateID -4 --cloudAccountID 123456789 --assessmentCloudAccountType AWS --secretKey {secretKey} --apiKeyID {apiKeyID}

# Supported entities
These entities support SyncNow
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
- VPNConnection (SyncNow supported)
- WAFRegional (SyncNow supported)
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

# Unsupported entities
These entities, with a fetch time greater than 20 minutes, do not support SyncNow.

- AzureApplicationGateway
- AzureSqlServer
- AzureStorage
- AzureRedis
- AzureKeyVault
- AwsEcs
- AwsVolumesFetchJob
- IamCredentialReport
- Aws Tags on all supported entities
