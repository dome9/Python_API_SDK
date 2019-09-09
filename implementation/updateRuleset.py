#!/usr/bin/env python
import argparse
import json
import uuid

from dome9ApiV2Py import Dome9ApiClient


class UpdateRuleset(object):

	def __init__(self, args):
		self.args = args
		self.d9Client = Dome9ApiClient(apiKeyID=args.dome9ApiKeyID, apiSecret=args.dome9ApiKeySecret)

	def createBundleRequest(self, requestId, cloudAccountID, bundleID):
		return {
			'id': bundleID,
			'cloudAccountId': cloudAccountID,
			'requestId': requestId
		}

	def updateBundle(self):
		print ('loading bundle from {}'.format(self.args.rulesetJsonPath))
		ruleBundleObject = self.d9Client.getJson(self.args.rulesetJsonPath)
		print ('Updating bundle {}'.format(self.args.bundleID))
		self.d9Client.updateRuleBundleByID(self.args.bundleID, ruleBundleObject)

	def runAssessment(self):
		requestId = str(uuid.uuid4())
		bundle = self.createBundleRequest(requestId, self.args.cloudAccountID, self.args.bundleID)
		print('Running assessment bundle {}'.format(requestId))
		bundleResult = self.d9Client.runAssessmenBundle(bundle)
		bundleResultStr = json.dumps(bundleResult)
		print('bundle result is\n{}'.format(bundleResultStr))

	def main(self):
		self.updateBundle()
		self.runAssessment()


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Given the bundleId and file with ruleset in Json format, updates the bundle and runs assessment')

	useExample = '--dome9ApiKeyID 111111-2222-3333-3333-3333333 --dome9ApiKeySecret qwerrtyy --rulesetJsonPath ruleset.json --bundleID 11111 --cloudAccountID 11111111111'
	parser.epilog = 'Example of use: {} {}'.format(__file__, useExample)

	parser.add_argument('--dome9ApiKeyID',     required=True, type=str, help='(required) Dome9 Api key')
	parser.add_argument('--dome9ApiKeySecret', required=True, type=str, help='(required) Dome9 secret key')
	parser.add_argument('--bundleID',          required=True, type=str, help='(required) Dome9 bundle ID')
	parser.add_argument('--rulesetJsonPath',   required=True, type=str, help='(required) Location for ruleset json file')
	parser.add_argument('--cloudAccountID',    required=True, type=str, help='(required) Dome9 external account ID')

	arguments = parser.parse_args()
	updateRuleset = UpdateRuleset(arguments)
	updateRuleset.main()
