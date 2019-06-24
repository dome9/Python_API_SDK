# Onboard accounts to Dome9


Table of Contents
=================
* [Tool Description](#tool-description)
* [Setup Steps](#setup-steps)
  * [Prerequisites](#Prerequisites)
  * [Parameters](#Parameters)
* [Usage examples](#usage-examples)

# What it does
This script does the following:
- Onboard  an Aws or Azure account to Dome9
- Attach the onboarded account to an OU
- Attach the view role to the account
- Attach the admin role to the account

# Setup 
## Prerequisites 

- Dome9 APIkeyID and secret
- Python 2.7 or later
- Python modules:
    - dome9ApiV2Py
    - requests

## Parameters

* **dome9ApiKeyID** (String): Dome9 API key
* **dome9SecretKey** (String): Dome9 secret key
* **cloudVendorType** (String): type of cloud account vendor: *aws, azure*
* **awsRoleArn** (String): the ARN of the Dome9-Connect role in your AWS account
* **awsRoleSecret** (String): the external ID value used to create the role in your AWS account
* **awsAllowReadOnly** (String, optional): set to True for *Read-Only*, and False for *Full Protection*; default is True 
* **awsFullProtection** (String, optional): set to True to set the Security Groups in the account to *Full-Protection* in the course of onboarding, or False to leave them unchanged; default is False
* **azureSubscriptionID** (String, optional): Azure subscriptionID
* **azureActiveDirectoryID** (String, optional): Azure azureActiveDirectoryID\\tenantID
* **azureApplicationID** (String, optional): Azure azureApplicationID\clientID
* **azureSecretKey** (String, optional): Azure azureSecretKey\clientPassword
* azureOperationMode** (String, optional): Azure operationMode, *Read* or *Manage*; default is Read, 
* **dome9OuID** (String, optional): Organization Unit ID to which cloud account will be attached
* **dome9AccountName** (String, optional): accountName account display name on Dome9 console, default is *account-randomString*
* **dome9AdminRoleID** (String, optional): Dome9 admin role ID to attach to the account
* **dome9ViewRoleID** (String, optional): Dome9 view (read) role ID to attach to the account


# Usage examples

**onboard  an AWS account:**

``` onboardCloudAccount.py --dome9ApiKeyID sdfsdfssdf --dome9SecretKey sdfsdfssdf --cloudVendorType aws --awsRoleArn arn:aws:iam::111111111:role/Dome9-Connect --awsRoleSecret sdfsdfsdff --dome9OuID e21b3e8b-e02f-46df-bd70-8ce65ca8a3a5 --dome9AccountName production --dome9AdminRoleID 118187 --dome9ViewRoleID 118203 ```

**onboard an Azure account:**

``` onboardCloudAcoount.py --dome9ApiKeyID ddsfsdfsdf --dome9SecretKey sdfsdfssdf --cloudVendorType azure --azureSubscriptionID sdfsdfsdfsdfsd --azureActiveDirectoryID sdfsdsdfsdsdfsd --azureApplicationID sfsdfsdfsfdsdf --azureSecretKey sdfsfsfsfd --dome9OuID 92f9a334-bf29-48a5-9cf8-66a10efe51e6 --dome9AccountName production --dome9AdminRoleID 118881 --dome9ViewRoleID 118901 --azureOperationMode Manage ```
