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
This is a tool/ sample/ starting point that demonstrates a full workflow for ad-hoc assessment while guaranteeing fresh data in Dome9 caches. It is designed to be integrated in CI/CD pipelines where the Dome9 system is expected to assess a new (even ephemeral) environment or some new changes to production env.


## Script Flow
- The script starts with a Dome9 API 'SyncNow' command which instructs the system to start fetching new data from the cloud provider. Note that not all cloud entities respect this command as of now. See the list below for additonal details.
- It then uses the new 'EntityFetchStatus' API to reason about the fetch-status of the various entities. The scripts polls this API until all desired entity types (configurable types) were fetched later than the script's start time.
- The script can wait up to *RUN_TIME_OUT* minutes (default 15). If there are entities that were not updated yet it will print them to the console (as the script can reason about entities that do not yet support SyncNow this can possibly occur)
- After done waiting, the script will use the assessment API to perfrom ad-hoc assessment for the desired cloud account and policy (bundle).

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
* **cloudAccountID** (String): cloud account id (Dome9 internal ID) - must use this **OR** the *externalAccountNumber*
* **externalAccountNumber** (String): AWS cloud account number - must use this parameter **or** the *cloudAccountID*
* **assessmentTemplateID** (integer): Assessment bundle id
* **assessmentRegion** (String, optional): Vendor region
* **assessmentCloudAccountType** (String, optional): Cloud provider ('AWS', 'AZURE', 'GCP')


# Usage examples

**example to use an AWS external account id:**
runSyncAssessment.py --assessmentTemplateID -4 --externalAccountNumber 123456789 --secretKey {secretKey} --apiKeyID {apiKeyID}

**example to use for any cloud vendor, with a Dome9 cloud account id:**
runSyncAssessment.py --assessmentTemplateID -4 --cloudAccountID 123456789 --assessmentCloudAccountType AWS --secretKey {secretKey} --apiKeyID {apiKeyID}

# Supported entities
Note the entity types that supports 'SyncNow' capability. 
Please contact our support for additional entity types that you would like us to prioritize (adding SyncNow support for them)

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

# Unsupported entities by this script
These entities, with a fetch time greater than 20 minutes are not covered by this script (meaning the script is not waiting / checking the status of these entities)

- AzureApplicationGateway
- AzureSqlServer
- AzureStorage
- AzureRedis
- AzureKeyVault
- AwsEcs
- AwsVolumes
- IamCredentialReport
- Aws Tags on all supported entities


# One last thing...
I find it useful to review the entities fetch status in a CSV format using Excel.<br/> 
For this I use the `jq` utility and usually pipe it to a file (or to `grep`)
```bash
curl -u <Dome9API V2 Api Key ID>:<api secret> https://api.dome9.com/v2/EntityFetchStatus?externalAccountNumber=123456789 | jq -r '(map(keys) | add | unique) as $cols | map(. as $row | $cols | map($row[.])) as $rows | $cols, $rows[] | @csv'
```
