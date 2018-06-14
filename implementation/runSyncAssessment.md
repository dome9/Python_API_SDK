# Description
The Tool run sync now process, waiting to get status uodate for the suported entities in the list below and then it wil run bundle assessment.

**Entities support sync now:**

* AwsDynamoDb
* AwsEc2Images
* AwsInspector
* AwsIamServerCertificate
* AwsVirtualMfaDevices
* AwsKinesisStream
* AwsNetworkInterface
* AwsRoute53Domains
* AwsRoute53HostedZones
* AwsAcmCertificate
* AwsS3Bucket
* AwsCloudFrontDistribution
* AwsIamPasswordPolicy
* IamUsersFetchJob
* AwsIamUserInlinePolicies
* AwsIamUserAttachedPolicies
* AwsIamUserGroups
* IamRolesFetchJob
* AwsIamRoleAttachedPolicies
* AwsIamRoleInlinePolicies

**Entities without sync now supported**:
* AppLoadBalancer
* AwsElastiCacheStatus
* AwsInstance
* AwsInternetGateway
* AwsRouteTables
* AwsSecurityGroup
* AwsVpnGateway
* CloudTrail
* ConfigurationRecorders
* DbInstance
* DirectConnectConnection
* DirectConnectVirtualInterface
* Efs
* Elb
* IamAccountSummary
* IamCredentialReport
* IamGroups
* IamPolicies
* IamUser
* Kms
* KmsAlias
* Lambda
* LogGroups
* MetricAlarms
* Nacl
* RedshiftCluster
* Subnet
* Vpc
* VpcEndpoint
* VpcFlowLogs
* VpcPeeringConnection
* WAFRegional
* AzureLoadBalancer
* AzureNetworkInterface
* AzurePublicIP
* AzureResourceGroup
* AzureSubnet
* AzureVirtualMachine
* AzureVirtualNetwork
* GoogleCloudFirewall
* GoogleCloudInstance
* GoogleCloudNetwork
* GoogleCloudSubnet


# Example

**example to use AWS external account id:**
runSyncAssessment.py --assessmentTemplateID -4 --externalAccountNumber 123456789 --secretKey {secretKey} --apiKeyID {apiKeyID}

**example to use any vendor with dome9 cloud account id:**
runSyncAssessment.py --assessmentTemplateID -4 --cloudAccountID 123456789 --assessmentCloudAccountType AWS --secretKey {secretKey} --apiKeyID {apiKeyID}



# Prerequisite 

* Dome9 API keyID and secret 

* Installed python >= 2.7 

* Python modules:

    * time 

    * datetime

    * uuid

	* argparse

	* sys

	* dome9ApiV2Py

# Parameters

**apiKeyID:**

Description: Dome9 API key

Type: string

require: True

**secretKey:**

Description: Dome9 secret key

Type: string

require: True

**cloudAccountID:**

Description: vendor cloud account id

Type: string

require: require cloudAccountID or externalAccountNumber

**externalAccountNumber:**

Description: AWS cloud account id

Type: string

require: require cloudAccountID or externalAccountNumber


**assessmentTemplateID:**

Description: assessment bundle id

Type: number

require: True

**assessmentRegion:**

Description: Vendor region

Type: string

require: False

**assessmentCloudAccountType:**

require: False

Type: string

Allowed paramaters:  'AWS', 'AZURE', 'GCP'
