# Description
The Tool run sync now and wait for all entities to be updates, then it wil run bundle assessment.

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

require: True

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
