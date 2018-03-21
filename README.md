# Python_API_SDK

Dome9 Api Client - Python SDK 


Author - Udi-Yehuda Tamar udi@dome9.com 


Classes
Prerequisite
Local imports
Instance Params
Instance Sample
Api Methods
General guidelines
** Method getAllUsers
** Method getCloudAccounts
** Method getCloudAccountID
** Method getCloudAccountRegions
** Method updateCloudAccountID
** Method getCloudTrail
** Method setCloudRegionsProtectedMode
** Method getAwsSecurityGroups
** Method getAwsSecurityGroup
** Method setCloudSecurityGroupProtectionMode
** Method getCloudSecurityGroupByVpcName
** Method getAllCloudSecurityGroupsInRegion
** Method setAllCloudSecurityGroupsInRegion
** Method getAllSecurityGroupIDsOfVpc
** Method setVpcProtectionMode





Classes

There are 2 API classes 

Dome9ApiSDK - straight forward backend implementation 
Dome9ApiClient - inherit from Dome9ApiSDK class + custom client methods 

Both classes are implementing the same constructor.

Prerequisite 
Dome9 API keyID and secret 
Installed python >= 2.7 
Python modules:
json 
requests
urlparse
Local imports 
Currently we yet implemented python setup module for the SDK , so in order to use it the user must reform relative import of the module file.
Current SDK only supports Dome9 API V2.
Instance Params
There are 2 mandatory params

apiKeyID - dome9 Api key ID
apiSecret - dome9 secret 
Instance Sample


To create instanse just provide the requested params use the instance var to expose all the api methods 
In the following example we are setting sa_east_1 to ReadOnly protection mode , to see more options check the methods signatures  



#!/usr/bin/env python

from dome9ApiV2Py import Dome9ApiClient

d9client = Dome9ApiClient(                apiKeyID='XXXXXXXXXXXXXXXX',
                                 apiSecret='XXXXXXXXXXXXXXXX')

call = d9client.setCloudRegionsProtectedMode(ID='056162705707', protectionMode='ReadOnly', regions=['sa_east_1'])
print(call)

Api Methods 

General guidelines 

All methods by default are returning python object  or none value 
outAsJson(bool) - optional param prints json (as string stdout) to the shell’s console. 

** Method getAllUsers
Task: Return all dome9 users 
Params: 
Optional: outAsJson 

** Method getCloudAccounts
Task: Return all cloud accounts  
Params: 
Optional: outAsJson 

** Method getCloudAccountID
Task: Return specific cloud account 
Params: 
Mandatory: ID(str)
Optional: outAsJson 

** Method getCloudAccountRegions
Task: Return all user’s available regions 
Params: 
Mandatory: ID(str)
Optional: outAsJson 

** Method updateCloudAccountID
Task: update cloud account ID data 
Params: 
Mandatory: ID(str), data (object (dict))
Optional: outAsJson 

** Method getCloudTrail
Task: Return cloud trail info 
Params: 
Optional: outAsJson 

** Method setCloudRegionsProtectedMode
Task: set cloud region protection mode , providing regions param will effect the requested protection mode , by default method runs on all user’s regions.
Params: 
 Mandatory: ID(str), protectionMode(str) select one from: 'ReadOnly', 'FullManage', 'Reset'
Optional: regions (list[]) 
Class : Dome9ApiClient



** Method getAwsSecurityGroups
Task: gets all aws sec groups 
Params: 
 Mandatory: 
Optional: outAsJson


** Method getAwsSecurityGroup
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson

** Method setCloudSecurityGroupProtectionMode
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson

** Method getCloudSecurityGroupByVpcName
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson
Class : Dome9ApiClient




** Method getAllCloudSecurityGroupsInRegion
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson
Class : Dome9ApiClient




** Method setAllCloudSecurityGroupsInRegion
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson
Class : Dome9ApiClient




** Method getAllSecurityGroupIDsOfVpc
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson
Class : Dome9ApiClient



** Method setVpcProtectionMode
Task: gets one aws sec group
Params: 
 Mandatory: ID(str)
Optional: outAsJson
Class : Dome9ApiClient



