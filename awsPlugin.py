import boto3, json
from botocore.exceptions import ClientError
from settings import *

class AWSPlugin(object):

    def getIAMObj(self):
        return boto3.client('iam', aws_access_key_id=IAM_USER_ACCESS_KEY, aws_secret_access_key=IAM_USER_SECRET_KEY, region_name=REGION_NAME)


    def assumeRoleforExternalUsers(self, roleArns, roleSessionName, user_access_key, user_secret_key, externalId):
        try:
            client = boto3.client('sts', aws_access_key_id=user_access_key, aws_secret_access_key=user_secret_key, region_name=REGION_NAME)
            response = []
            for roleArn in roleArns:
                token = client.assume_role(RoleArn=roleArn, RoleSessionName=roleSessionName, DurationSeconds=TOKEN_DURATION, ExternalId=externalId)
                response.append(token['Credentials'])
            return response
        except Exception as e:
            print(e)
            return None  

    def createRole(self, *args):
        if args[4]:
            role_name = args[2]+"_role_for_"+args[0]
            userARN = "arn:aws:iam::"+args[0]+":user/"+args[1]
            description = 'This is a '+args[2]+' role for '+args[0]+' account.'
        else:
            role_name = args[0]
            userARN = args[1]
            description = 'This is a '+args[2]+' assume role'

        # Following trust relationship policy to provide access to assume this role by a particular IAM user from different AWS acccount
        trust_relationship_policy_another_iam_user = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": userARN
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        try:
            create_role_res = self.getIAMObj().create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_relationship_policy_another_iam_user),
                Description=description
            )
            print("Successfully created the role!")
            return self.awsAttachPoliciesToRole(role_name, args[3], create_role_res['Role']['Arn'])
        except ClientError as error:
            if error.response['Error']['Code'] == 'EntityAlreadyExists':
                 print('Role already exists... hence exiting from here')
                 return False, None
            else:
                print('Unexpected error occurred... Role could not be created')
                return False, None 

    def awsAttachPoliciesToRole(self, roleName, policies, roleARN):
        for policy_arn in policies:
            try:
                policy_attach_res = self.getIAMObj().attach_role_policy(
                    RoleName=roleName,
                    PolicyArn=policy_arn
                )
            except ClientError as error:
                print('Problem attaching policyARN '+policy_arn)
        return True, roleARN



'''
aws=AWSPlugin()
print(aws.assumeRoleforExternalUsers("arn:aws:iam::735455110910:role/AssumeNeurEDARole","Demo"))
'''

        