#!/usr/bin/env python
import argparse
import uuid
import json
from dome9ApiV2Py import Dome9ApiClient


class UpdateRuleset(object):

	def __init__(self, args):
		self.args = args
		self.d9client = Dome9ApiClient(apiKeyID=args.dome9ApiKeyID, apiSecret=args.dome9ApiKeySecret)


	def mainProcess(self):
		print ('loading bundle from {}'.format(self.args.rulesetJsonPath))
		ruleBundleObject = self.d9client.getJson(self.args.rulesetJsonPath)
		print ('Updating bundle {}'.format(self.args.bundleID))
		self.d9client.updateRuleBundleByID(self.args.bundleID, ruleBundleObject)
		bundle = {
			'id': self.args.bundleID,
			'cloudAccountId': self.args.cloudAccountID,
			'requestId': str(uuid.uuid4())
		}
		print ('Running assessment bundle')
		bundleResult  = self.d9client.runAssessmenBundle(bundle)
		print ('bundle result is\n{}'.format(json.dumps(bundleResult)))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='')
	useExample = '--dome9ApiKeyID 111111-2222-3333-3333-3333333 --dome9ApiKeySecret qwerrtyy --rulesetJsonPath ruleset.json --bundleID 11111 --cloudAccountID 11111111111'

	parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)
	parser.add_argument('--dome9ApiKeyID',          required=True,  type=str, help='(required) Dome9 Api key')
	parser.add_argument('--dome9ApiKeySecret',      required=True,  type=str, help='(required) Dome9 secret key')
	parser.add_argument('--bundleID',      required=True,  type=str, help='(required) Dome9 bundle ID')
	parser.add_argument('--rulesetJsonPath',      required=True,  type=str, help='(required) Location for ruleset json file')
	parser.add_argument('--cloudAccountID',      required=True,  type=str, help='(required) Dome9 external account ID')

	arguments = parser.parse_args()
	TestD9Api = UpdateRuleset(arguments)
	TestD9Api.mainProcess()
