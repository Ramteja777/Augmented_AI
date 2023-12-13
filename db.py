import pymongo
from bson.objectid import ObjectId
#from bson import json_util
from settings import *

class DatabaseMain(object):

    def getDBObj(self):
        try:
            return pymongo.MongoClient(MONGO_SERVER_URL, MONGO_PORT)[DBNAME]
        except Exception:
            return None

    def findUserInfo(self, userId):
        try:
            if self.getDBObj() != None:
                print(userId)
                response = self.getDBObj()['IAMUserDetails'].find_one({"_id": ObjectId(userId)})
                if response and len(response):
                    return response
                else:
                    print("Invalid userId")
                    return None
            else:
                print("Unable to connect to database")
                return None
        except Exception as e:
            print(e)
            return None

    def findRoleData(self, **kwargs):
        if self.getDBObj() != None:
            roleResponse = self.getDBObj()['roleInfo'].find_one(kwargs)

            if roleResponse and len(roleResponse):
                userResponse = self.findUserInfo(roleResponse['IAMUserId'])
                if userResponse and len(userResponse):
                    response = {"roleARNs": roleResponse['roleARNs'], "externalId": roleResponse['externalId'],
                                    "roleSessionName": roleResponse['roleSessionName'], "IAMuserInfo": {
                                    "access_key": userResponse['access_key'], "secret_key": userResponse['secret_key']}}
                    return response
                else:
                    print("No data found")
                    return None
            else:
                print("No data found")
                return None
        else:
            print("Unable to connect to database")
            return None

    def findPolicyDetails(self, **kwargs):
        if self.getDBObj() != None:
            policyDetails = self.getDBObj()['policyDetails'].find_one(kwargs)
            if policyDetails and len(policyDetails):
                return [policyDetails]
            else:
                print("Unable to fetch policies")
                return []
        else:
            print("Unable to connect to database")
            return []

    def addCustomRole(self, username, roleARN, policyId):
        if self.getDBObj() != None:
            try:
                response = self.getDBObj()['customRoleDetails'].find_one({"username": username})
                if response == None:
                    self.getDBObj()['customRoleDetails'].insert_one({"username": username, "roleARN": roleARN, "policyId": policyId})
                    return True
                else:
                    print("Custom role for this user is already created")
                    return False
            except Exception as e:
                print("Database error")
                return False
        else:
            print("Unable to connect to the database")
            return False

    def getCustomRole(self, username):
        if self.getDBObj() != None:
            try:
                response = self.getDBObj()['customRoleDetails'].find_one({"username": username})
                if response != None and len(response):
                    return response
                else:
                    print("Custom role for this user doesn't exists")
                    return False
            except Exception as e:
                print("Database error")
                return False
        else:
            print("Unable to connect to the database")
            return False

    def deleteCustomRole(self, username):
        if self.getDBObj() != None:
            try:
                response = self.getDBObj()['customRoleDetails'].find_one({"username": username})
                if response != None and len(response):
                    self.getDBObj()['customRoleDetails'].delete_one({"username": username})
                    return True
                else:
                    print("Custom role for this user doesn't exists")
                    return False
            except Exception as e:
                print("Database error")
                return False
        else:
            print("Unable to connect to the database")
            return False

