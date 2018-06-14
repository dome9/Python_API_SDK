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
This tool verifies that an assessment run will be performed after the entites are most up to date.
The tool run SyncNow process, waiting for an answer for every supported entity and then checks all the other supported entities to be mostly up to date prior running an assessment.

## Script Flow
- The script is validating on runtime the up to date entities.
- Running SyncNow for all the supported entities to have the most up to date data.
- Waiting for 0 minutes to have the most up to date data.
- Running compliance assessments with the given bundle ID for the given cloud account.

# Setup Steps
## Prerequisites 

- Dome9 API keyID and secret
- Script location need to be in the same folder where the Dome9 Python_API_SDK exist
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

# Not Supported entities
Not supported entities related to all of the entities which their fetching time is higher then 20 minutes.

- AzureApplicationGateway
- AzureSqlServer
- AzureStorage
- AzureRedis
- AzureKeyVault
- AwsEcs
- AwsVolumesFetchJob
- IamCredentialReport
- Aws Tags on all supported entities
