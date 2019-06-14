from dome9ApiV2Py import Dome9ApiClient
import argparse
import uuid
import sys

class OnBoardingCloudAccount(object):
	VENDOR_TYPES = ['aws', 'azure']
	AWS_ALLOW_READONLY = [True, False]
	AWS_FULL_PROTECTION = [True, False]
	AWS_SRL = '1'
	AZURE_OPERATION_MODE = ['READ', 'Manage']
	AZURE_SRL = '7'

	def __init__(self, args):
		self.args = args
		self.d9client = Dome9ApiClient(apiKeyID=args.apiKeyID, apiSecret=args.secretKey)

	def onBoardingNewAccount(self):
		if self.args.vendorType == 'aws':
			if not self.args.roleArn or not self.args.roleSecret:
				sys.exit('Must specify roleArn and roleSecret\n example: --roleArn arn:aws:iam::111111111:role/Dome9-Connect --roleSecret sdf^87fsd987d')

			cloudAccountObject = self.d9client.onBoardingAwsAccount(arn=self.args.roleArn, secret=self.args.roleSecret, name=self.args.accountName, allowReadOnly=self.args.allowReadOnly )

		elif self.args.vendorType == 'azure':
			if not self.args.subscriptionID or self.args.tenantID or self.args.clientID or self.args.clientPassword:
				sys.exit('Must specify subscriptionID, tenantID, clientID and clientPassword\n example:')

			cloudAccountObject = self.d9client.onBoardingAzureAccount(subscriptionId=self.args.subscriptionID, tenantID=self.args.tenantID, clientID=self.args.clientID, clientPassword=self.args.clientPassword, operationMode=self.args.operationMode, name=self.args.accountName)

		return cloudAccountObject['id']

	def mainProcess(self):
		print('Onboarding {} account'.format(self.args.vendorType))
		cloudAccountID = self.onBoardingNewAccount()

		if self.args.ouID:
			print('Attach cloudAccount {} to OU {}'.format(cloudAccountID, self.args.ouID))
			self.d9client.updateOrganizationalUnitForCloudAccount(cloudAccountID=cloudAccountID, organizationalUnitID=self.args.ouID)

		if self.args.vendorType == 'aws':
			srl = '|'.join([OnBoardingCloudAccount.AWS_SRL, cloudAccountID])
		elif self.args.vendorType == 'azure':
			srl = '|'.join([OnBoardingCloudAccount.AZURE_SRL, cloudAccountID])

		if self.args.adminRoleID:
			print('Grant admin permission to role {}'.format(self.args.adminRoleID))
			roleObject = self.d9client.getRoleByID(self.args.adminRoleID, outAsJson=True)
			permission = roleObject['permissions']
			managePermission = permission['manage']
			accessPermission = permission['access']
			createPermission = permission['create']
			viewPermission = permission['view']
			managePermission.append(srl)
			createPermission.append(srl)
			accessPermission.append(srl)
			viewPermission.append(srl)
			self.d9client.updateRoleByID(roleID=self.args.adminRoleID, permissions=permission, roleName=roleObject['name'])

		if self.args.viewRoleID:
			print('Grant view permission to role {}'.format(self.args.viewRoleID))
			roleObject = self.d9client.getRoleByID(self.args.viewRoleID, outAsJson=True)
			permission = roleObject['permissions']
			viewPermission = permission['view']
			viewPermission.append(srl)
			self.d9client.updateRoleByID(roleID=self.args.viewRoleID , permissions=permission,roleName=roleObject['name'])

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='')
	useExample = '--apiKeyID fsdfsdsdfsdf --secretKey sdfsdfs --vendorType aws --roleArn arn:aws:iam::111111111:role/Dome9-Connect --roleSecret sdf^87fsd987d --adminRoleID 118187 --userRoleID 118203'
	parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)
	parser.add_argument('--apiKeyID', required=True, type=str, help='Dome9 Api key')
	parser.add_argument('--secretKey', required=True, type=str, help='Dome9 secret key')
	parser.add_argument('--vendorType', required=True, type=str, choices=OnBoardingCloudAccount.VENDOR_TYPES, help='type of cloud account vendor: aws, azure')
	parser.add_argument('--roleArn', required=False, type=str, help='The ARN of the Dome9-Connect role in your AWS account')
	parser.add_argument('--roleSecret', required=False, type=str, help='The external ID value used to create the role in your AWS account')
	parser.add_argument('--allowReadOnly', required=False, default=True, choices=OnBoardingCloudAccount.AWS_ALLOW_READONLY, type=str, help='Default=True, set to True for Read-Only, and False for Full Protection')
	parser.add_argument('--fullProtection', required=False, default=False, choices=OnBoardingCloudAccount.AWS_FULL_PROTECTION, help='Default=False, set to True for to set the Security Groups in the account to Full-Protection in the course of onboarding, or False to leave them unchanged', type=str)
	parser.add_argument('--subscriptionID', required=False, type=str, help='Azure subscriptionID')
	parser.add_argument('--tenantID', required=False, type=str, help='Azure tenantID')
	parser.add_argument('--clientID', required=False, type=str, help='Azure clientID')
	parser.add_argument('--clientPassword', required=False, type=str, help='Azure clientPassword')
	parser.add_argument('--operationMode', required=False, default='Read', choices=OnBoardingCloudAccount.AZURE_OPERATION_MODE, type=str, help='Default=Read, Azure operationMode, allow Read or Manage')
	parser.add_argument('--accountName', required=False, default='account-{}'.format(str(uuid.uuid4())[:8]), type=str, help='Default=account-randomString , accountName display on Dome9 console')
	parser.add_argument('--ouID', required=False, type=str, help='Organization Unit ID to attach cloud account')
	parser.add_argument('--adminRoleID', required=False, type=str, help='Dome9 role ID to get admin permission to the account')
	parser.add_argument('--viewRoleID', required=False, type=str, help='Dome9 role ID to get read permission to the account')


	arguments = parser.parse_args()
	TestD9Api = OnBoardingCloudAccount(arguments)
	TestD9Api.mainProcess()
