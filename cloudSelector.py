from awsPlugin import *

class CloudSelector(AWSPlugin):

    def getCloudProviderCredentials(self, **details):
        if(CLOUD_PROVIDER_NAME == 'aws'):
            self.awsPlugin = AWSPlugin()
            return self.awsPlugin.assumeRoleforExternalUsers(details['roleArns'], details['roleSessionName'], details['user_access_key'], 
                                                                details['user_secret_key'], details['externalId'])
        else:
            return None

    def createCloudRole(self, **details):
        if CLOUD_PROVIDER_NAME == 'aws':
            self.awsPlugin = AWSPlugin()
            return self.awsPlugin.createRole(details['accountId'], 
                                                details['awsUserName'], 
                                                details['role'],
                                                details['policyARNs'],
                                                details['custom'])
        else:
            print("Unknown cloud provider")
            return None

    def deleteCustomCloudRole(self, **details):
        if CLOUD_PROVIDER_NAME == 'aws':
            self.awsPlugin = AWSPlugin()
            return self.awsPlugin.awsDeleteRole(details['roleARNs'],
                                                details['policyARNs'])
        else:
            print("Unknown cloud provider")
            return None