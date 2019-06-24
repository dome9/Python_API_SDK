#!/usr/bin/env python
import argparse
import uuid
import sys
from dome9ApiV2Py import Dome9ApiClient


class OnBoardingCloudAccount(object):
	VENDOR_TYPES = ['aws', 'azure']
	AWS_ALLOW_READONLY = [True, False]
	AWS_FULL_PROTECTION = [True, False]
	AWS_SRL = '1'
	AZURE_OPERATION_MODE = ['READ', 'Manage']
	AZURE_SRL = '7'

	def __init__(self, args):
		self.args = args
		self.d9client = Dome9ApiClient(apiKeyID=args.dome9ApiKeyID, apiSecret=args.dome9ApiKeySecret)

	def onBoardingNewAccount(self):
		if self.args.cloudVendorType == 'aws':
			if not self.args.awsRoleArn or not self.args.awsRoleExternalID:
				sys.exit('Must specify roleArn and roleSecret\n example: --roleArn arn:aws:iam::111111111:role/Dome9-Connect --roleSecret sdf^87fsd987d')

			cloudAccountObject = self.d9client.onBoardingAwsAccount(arn=self.args.awsRoleArn, secret=self.args.awsRoleExternalID, name=self.args.dome9CloudAccountName, allowReadOnly=self.args.awsAllowReadOnly, fullProtection= self.args.awsFullProtection)

		elif self.args.cloudVendorType == 'azure':
			if not self.args.azureSubscriptionID or not self.args.azureActiveDirectoryID or not self.args.azureApplicationID or not self.args.azureSecretKey:
				sys.exit('Must specify subscriptionID, tenantID, clientID and clientPassword\n example:')

			cloudAccountObject = self.d9client.onBoardingAzureAccount(subscriptionID=self.args.azureSubscriptionID, name=self.args.dome9CloudAccountName, tenantID=self.args.azureActiveDirectoryID, clientID=self.args.azureApplicationID, clientPassword=self.args.azureSecretKey, operationMode=self.args.azureOperationMode)

		return cloudAccountObject['id']

	def mainProcess(self):
		print('Onboarding {} account'.format(self.args.cloudVendorType))
		cloudAccountID = self.onBoardingNewAccount()

		if self.args.dome9OuID:
			print('Attach cloudAccount {} to OU {}'.format(cloudAccountID, self.args.dome9OuID))
			self.d9client.updateOrganizationalUnitForCloudAccount(vendor=self.args.cloudVendorType, cloudAccountID=cloudAccountID, organizationalUnitID=self.args.dome9OuID)

		if self.args.cloudVendorType == 'aws':
			srl = '|'.join([OnBoardingCloudAccount.AWS_SRL, cloudAccountID])
		elif self.args.cloudVendorType == 'azure':
			srl = '|'.join([OnBoardingCloudAccount.AZURE_SRL, cloudAccountID])

		if self.args.dome9AdminRoleID:
			print('Grant admin permission to role {}'.format(self.args.dome9AdminRoleID))
			roleObject = self.d9client.getRoleByID(self.args.dome9AdminRoleID, outAsJson=True)
			permission = roleObject['permissions']
			managePermission = permission['manage']
			accessPermission = permission['access']
			createPermission = permission['create']
			viewPermission = permission['view']
			managePermission.append(srl)
			createPermission.append(srl)
			accessPermission.append(srl)
			viewPermission.append(srl)
			self.d9client.updateRoleByID(roleID=self.args.dome9AdminRoleID, permissions=permission, roleName=roleObject['name'])

		if self.args.dome9ViewRoleID:
			print('Grant view permission to role {}'.format(self.args.dome9ViewRoleID))
			roleObject = self.d9client.getRoleByID(self.args.dome9ViewRoleID, outAsJson=True)
			permission = roleObject['permissions']
			viewPermission = permission['view']
			viewPermission.append(srl)
			self.d9client.updateRoleByID(roleID=self.args.dome9ViewRoleID , permissions=permission,roleName=roleObject['name'])


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='')
	useExample = '''
	AWS:
	--dome9ApiKeyID sdfsdfssdf --dome9ApiKeySecret sdfsdfssdf --cloudVendorType aws --awsRoleArn arn:aws:iam::111111111:role/Dome9-Connect --awsRoleExternalID sdfsdfsdff --dome9OuID e21b3e8b-e02f-46df-bd70-8ce65ca8a3a5 --dome9CloudAccountName production --dome9AdminRoleID 118187 --dome9ViewRoleID 118203
	
	Azure:
	--dome9ApiKeyID ddsfsdfsdf --dome9ApiKeySecret sdfsdfssdf --cloudVendorType azure --azureSubscriptionID sdfsdfsdfsdfsd --azureActiveDirectoryID sdfsdsdfsdsdfsd --azureApplicationID sfsdfsdfsfdsdf --azureSecretKey sdfsfsfsfd --dome9OuID 92f9a334-bf29-48a5-9cf8-66a10efe51e6 --dome9CloudAccountName production --dome9AdminRoleID 118881 --dome9ViewRoleID 118901 --azureOperationMode Manage
	'''
	parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)
	parser.add_argument('--dome9ApiKeyID',          required=True,  type=str, help='(required) Dome9 Api key')
	parser.add_argument('--dome9ApiKeySecret',      required=True,  type=str, help='(required) Dome9 secret key')
	parser.add_argument('--cloudVendorType',        required=True,  type=str, choices=OnBoardingCloudAccount.VENDOR_TYPES, help='(required) type of cloud account vendor: aws, azure')
	parser.add_argument('--awsRoleArn',             required=False, type=str, help='The ARN of the Dome9-Connect role in your AWS account')
	parser.add_argument('--awsRoleExternalID',      required=False, type=str, help='The external ID value used to create the role in your AWS account')
	parser.add_argument('--awsAllowReadOnly',       required=False,  action='store_true',   help='switch parameter, use it for Read-Only, don\'t use it for Full Protection')
	parser.add_argument('--awsFullProtection',      required=False,  action='store_true',   help='switch parameter, use it for to set the Security Groups in the account to Full-Protection in the course of onboarding, or don\'t use it to leave them unchanged')
	parser.add_argument('--azureSubscriptionID',    required=False, type=str, help='Azure subscriptionID')
	parser.add_argument('--azureActiveDirectoryID', required=False, type=str, help='Azure azureActiveDirectoryID\\tenantID')
	parser.add_argument('--azureApplicationID',     required=False, type=str, help='Azure azureApplicationID\clientID')
	parser.add_argument('--azureSecretKey',         required=False, type=str, help='Azure azureSecretKey\clientPassword')
	parser.add_argument('--azureOperationMode',     required=False, type=str, default='Read', choices=OnBoardingCloudAccount.AZURE_OPERATION_MODE,  help='Default=Read, Azure operationMode, allow Read or Manage')
	parser.add_argument('--dome9CloudAccountName',  required=False, type=str, default='account-{}'.format(str(uuid.uuid4())[:8]), help='Default=account-randomString , accountName display on Dome9 console')
	parser.add_argument('--dome9OuID',              required=False, type=str, help='Organization Unit ID to attach cloud account')
	parser.add_argument('--dome9AdminRoleID',       required=False, type=str, help='Dome9 role ID to get admin permission to the account')
	parser.add_argument('--dome9ViewRoleID',        required=False, type=str, help='Dome9 role ID to get read permission to the account')


	arguments = parser.parse_args()
	TestD9Api = OnBoardingCloudAccount(arguments)
	TestD9Api.mainProcess()
