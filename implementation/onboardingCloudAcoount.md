# Run Sync Assessment


Table of Contents
=================
* [Tool Description](#tool-description)
* [Setup Steps](#setup-steps)
  * [Prerequisites](#Prerequisites)
  * [Parameters](#Parameters)
* [Usage examples](#usage-examples)

# Tool Description
This is a tool/ sample/ do the following:
- Onboarding to Aws, Azure
- Attach account to OU
- Attach view role to account
- Attach admin role to account

# Setup Steps
## Prerequisites 

- Dome9 APIkeyID and secret
- Python 2.7 or later
- Python modules:
    - dome9ApiV2Py
    - requests

## Parameters

* **dome9ApiKeyID** (String): Dome9 API key
* **dome9SecretKey** (String): Dome9 secret key
* **cloudVendorType** (String): type of cloud account vendor: aws, azure*
* **awsRoleArn** (String): The ARN of the Dome9-Connect role in your AWS account*
* **awsRoleSecret** (String): The external ID value used to create the role in your AWS account*
* **awsAllowReadOnly (String, optional) Default=True, set to True for Read-Only, and False for Full Protection*
* **awsFullProtection (String, optional) Default=False, set to True for to set the Security Groups in the account to Full-Protection in the course of onboarding, or False to leave them unchanged*
* **azureSubscriptionID (String, optional) Azure subscriptionID*
* **azureActiveDirectoryID (String, optional) Azure azureActiveDirectoryID\\tenantID*
* **azureApplicationID (String, optional) Azure azureApplicationID\clientID*
* **azureSecretKey (String, optional) Azure azureSecretKey\clientPassword*
* azureOperationMode (String, optional) Default=Read, Azure operationMode, allow Read or Manage*
* **dome9OuID** (String, optional): Organization Unit ID to attach cloud account*
* **dome9AccountName** (String, optional): Default=account-randomString , accountName display on Dome9 console*
* **dome9AdminRoleID** (String, optional): Dome9 role ID to get admin permission to the account*
* **dome9ViewRoleID** (String, optional): Dome9 role ID to get read permission to the account*


# Usage examples

**example to use an AWS:**
onboardingCloudAcoount.py --dome9ApiKeyID sdfsdfssdf --dome9SecretKey sdfsdfssdf --cloudVendorType aws --awsRoleArn arn:aws:iam::111111111:role/Dome9-Connect --awsRoleSecret sdfsdfsdff --dome9OuID e21b3e8b-e02f-46df-bd70-8ce65ca8a3a5 --dome9AccountName production --dome9AdminRoleID 118187 --dome9ViewRoleID 118203

**example to use an Azure:**
onboardingCloudAcoount.py --dome9ApiKeyID ddsfsdfsdf --dome9SecretKey sdfsdfssdf --cloudVendorType azure --azureSubscriptionID sdfsdfsdfsdfsd --azureActiveDirectoryID sdfsdsdfsdsdfsd --azureApplicationID sfsdfsdfsfdsdf --azureSecretKey sdfsfsfsfd --dome9OuID 92f9a334-bf29-48a5-9cf8-66a10efe51e6 --dome9AccountName production --dome9AdminRoleID 118881 --dome9ViewRoleID 118901 --azureOperationMode Manage
