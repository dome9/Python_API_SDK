# Python_API_SDK

Dome9 Api Client - Python SDK

Author - Udi-Yehuda Tamar [devops@dome9.com](mailto:devops@dome9.com)

This SDK implements a Python wrapper for the Dome9 API V2.

# Classes

There are 2 API classes

Dome9ApiSDK - the backend implementation, used by the client class.

Dome9ApiClient - inherit from Dome9ApiSDK class + custom client methods

Both classes implement the same constructor.

# Prerequisites

* Dome9 API APIkey and secret

* Python v2.7 or later

* Python modules included in `requirements.txt`
    * Installable by running `pip install -r requirements.txt`

# Local imports

Save the Python SDK modules in the same folder as your Python modules.

Currently, the SDK supports only Dome9 API V2.

# Instance Params

There are two mandatory params

apiKeyID - Dome9 API key ID

apiSecret - Dome9 secret

# Instance Example

To create an instance of the client class:

```
#!/usr/bin/env python

from dome9ApiV2Py import Dome9ApiClient

d9client = Dome9ApiClient(apiKeyID='XXXXXXXXXXXXXXXX', apiSecret='XXXXXXXXXXXXXXXX')

call = d9client.setCloudRegionsProtectedMode(ID='056162705707', protectionMode='ReadOnly', regions=['sa_east_1'])

print(call)
```
In this example we are setting the region sa_east_1 to ReadOnly protection mode.

# Dome9 API Methods

## General guidelines

* All methods by default return a python object or no value

* outAsJson(bool) - optional param prints json (as string stdout) to the shell’s console.


## Dome9 Tools

These methods use the SDK methods (below) to perform complex operations

### ** Method setCloudRegionsProtectedMode

Task: set  protection mode for a cloud region. If regions are specified, it will apply to these regions, otherwise on all the user’s regions.

Params:

Mandatory: ID(str), protectionMode(str) select from: `ReadOnly`, `FullManage`, `Reset`

Optional: regions (list[])


### ** Method setCloudSecurityGroupsProtectionModeOfVpc

Task: set protection mode of all attached security groups in a specific VPC

Params:

Mandatory: vpcID(str), protectionMode(str) select one from: `ReadOnly`, `FullManage`

Optional: outAsJson


### ** Method setCloudSecurityGroupsProtectionModeInRegion

Task: set protection mode for all security groups in specific region

Params:

Mandatory: region(str), protectionMode(str) select one from: `ReadOnly`, `FullManage`

Optional:


### ** Method getCloudSecurityGroupByVpcName

Task: gets security groups attached to a VPC

Params:

Mandatory: vpcName(str)

Optional:

### ** Method getAllCloudSecurityGroupsInRegion

Task: get all security groups in a region

Params:

Mandatory: region(str), names(bool)[output list of names]

Optional:

### ** Method getAllSecurityGroupIDsOfVpc

Task: get all security group IDs for a specific VPC

Params:

 Mandatory: vpcID(str)

Optional:


## SDK Methods

### ** Method getAllUsers

Task: Return all dome9 users

Params:

Optional: outAsJson

### ** Method getCloudAccounts

Task: Return all cloud accounts  

Params:

Optional: outAsJson

### ** Method getCloudAccountID

Task: Return a specific cloud account

Params:

Mandatory: ID(str)

Optional: outAsJson

### ** Method getCloudAccountRegions

Task: Return all user’s available regions

Params:

Mandatory: ID(str)

Optional: outAsJson

### ** Method updateCloudAccountID

Task: update cloud account ID data

Params:

Mandatory: ID(str), data (object (dict))

Optional: outAsJson

### ** Method getCloudTrail

Task: Return CloudTrail info

Params:

Optional: outAsJson

### ** Method getAwsSecurityGroups

Task: get all AWS security groups

Params:

Mandatory:

Optional: outAsJson

### ** Method getAwsSecurityGroup

Task: get one AWS security group

Params:

Mandatory: ID(str)

Optional: outAsJson

### ** Method setCloudSecurityGroupProtectionMode

Task: set a single security group protection mode

Params:

Mandatory: ID(str), protectionMode(str)

Optional: outAsJson
