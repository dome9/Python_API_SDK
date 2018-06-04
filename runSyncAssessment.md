# Description
The Tool run sync now and wait for all entities to be updates, then it wil run you assessment.

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

apiKeyID

Description: Dome9 API key
require: True
 
secretKey

Description: Dome9 secret key
require: True

cloudAccountID

Description: vendor cloud account id
Type: string
require: True

assessmentTemplateID

Description: Dome9 API key
require: True

assessmentRegion
Description: Vendor region

require: False
Type: string

assessmentCloudAccountType
require: False
Allowd paramaters:  'AWS', 'AZURE', 'GCP'