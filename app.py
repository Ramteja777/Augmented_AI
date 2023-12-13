import os
import json
from flask import Flask, jsonify, request
from keycloakPlugin import *
from db import *
from cloudSelector import *
import requests
import mimetypes
import validators
import re
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.from_object('settings')

#SAMPLE API
@app.route('/')
def index():
    return "<h1>Hello world!<h1>"

#REGISTER API
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if request.headers.get('content-type') == "application/json":
            requestData = request.get_json()
            if requestData == None:
                message = "Please enter the details"
                responseData = {"status_code": 400, "status_message": message, "data":[]}
                return jsonify(responseData)
            else:
                try:
                    username = requestData['username']
                    firstname = requestData['firstName']
                    lastname = requestData['lastName']
                    role = requestData['role'].lower()
                    email = requestData['email']
                    password = requestData['password']
                    
                    hasaccount = requestData['hasaccount']
                    if hasaccount == True:
                        aws_accountid = requestData['personal_accountid']
                        aws_username = requestData['personal_username']
                    
                    
                except Exception as e:
                    msg = "Invalid Input"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)

                if not type(username) == "str" and type(firstname) == "str" and type(lastname) == "str" and type(role) == "str" and type(email) == "str" and type(password) == "str" and type(hasaccount) == "bool":
                    msg = "value type mismatch"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)
                
                if len(password)<6:
                    msg = "Password is too short"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)

                if role not in KEYCLOAK_ROLES:
                    msg = "Please enter the valid role"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)

                
                if len(username)<3:
                    msg = "Username is too short"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)

                if not username.isalnum() or " " in username:
                    msg = "Username should be alphanumeric, also no spaces"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)
                
                regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                if not (re.fullmatch(regex, email)):
                    msg = "Email is not valid"
                    responseData = {"status_code": 400, "status_message": msg, "data":[]}
                    return jsonify(responseData)

                pwd_hash = generate_password_hash(password)
                kc = keycloakPlugin()
                kcResponse, response_msg = kc.createUser(username, password, email, firstname, lastname, role)
                if kcResponse:
                    if hasaccount:
                        pc = DatabaseMain()
                        policyDetails = pc.findPolicyDetails(role = role.lower())
                        if len(policyDetails):
                            aws = CloudSelector()
                            cloudResponse, roleARN = aws.createCloudRole(accountId = aws_accountid, awsUserName = aws_username, role = role, policyARNs = policyDetails[0]['policies'], custom=True)
                            if cloudResponse:
                                pc.addCustomRole(username, roleARN, policyDetails[0]['_id'])
                                return jsonify({
                                "status_code" : 200,
                                "status_message" : "User is created",
                                "data" : [{
                                    "role" : roleARN
                                    }
                                    ]
                                })
                            else:
                                Delete_user = kc.deleteUser(username)
                                msg = "Failed to create the user"
                                responseData = {"status_code": 400, "status_message": msg, "data":[]}
                                return jsonify(responseData)
                        else:
                            msg = "There is no policy for this particular role"
                            responseData = {"status_code": 400, "status_message": msg, "data":[]}
                            return jsonify(responseData)
                    else:
                        msg = "User is successfully created"
                        responseData = {"status_code": 200, "status_message": msg, "data":[]}
                        return jsonify(responseData)
                else:
                    responseData = {"status_code": 400, "status_message": response_msg, "data":[]}
                    return jsonify(responseData)
        else:
            responseData = {"status_code": 400, "status_message": "Data is not in application/json format", "data":[]}
            return jsonify(responseData)

#LOGIN API
@app.route('/login', methods=['POST'])
def login():
    if request.headers.get('content-type') != 'application/json':
        message = "Invalid content type"
        responseData = {"status_code": 400, "status_message": message, "data":[]}
        return jsonify(responseData)

    if request.method == 'POST':
        requestData = request.get_json()
        if requestData == None:
            message = "No user credential provided"
            responseData = {"status_code": 400, "status_message": message, "data":[]}
            return jsonify(responseData)
        else:
            kcPlugin = keycloakPlugin()
            token = kcPlugin.getToken(requestData['username'], requestData['password'])
            if token:
                
                responseData = {"status_code": 200, "status_message": "success", "data":[{"access_token": token['access_token'], 
                            "refresh_token": token['refresh_token'], "expiry": token['expires_in']}]}
            else:
                responseData = {"status_code": 400, "status_message": "Invalid user credential", "data":[]}
            return jsonify(responseData)

#GETTING CLOUD ACCESS CREDENTIALS API
@app.route('/get_access_credentials')
def fetch_access_credentials():
    try:
        header = request.headers.get('Authorization')
        header_token = header.split(" ")[1]
    except Exception as e:
        print("Missing token in the request header")
        res = {"status_code": 400, "status_message": "Missing authorization token", "data": []}
        return jsonify(res)
    kcPlugin = keycloakPlugin()
    role = kcPlugin.decodeToken(header_token)
    if role:
        dbMain = DatabaseMain()
        dbResponse = dbMain.findRoleData(role=role)
        if dbResponse:
            cloud_selector = CloudSelector()
            cloudResponse = cloud_selector.getCloudProviderCredentials(roleArns=dbResponse['roleARNs'], roleSessionName=dbResponse['roleSessionName'], 
                                                                externalId=dbResponse['externalId'], user_access_key=dbResponse['IAMuserInfo']['access_key'], 
                                                                user_secret_key=dbResponse['IAMuserInfo']['secret_key'])
            if cloudResponse and len(cloudResponse):
                respData = []
                Data = ["arn:aws:iam::735455110910:role/service-role/StepFunctions-MyStateMachine-role-05a1da99", "arn:aws:iam::735455110910:role/service-role/Amazon_EventBridge_Invoke_Step_Functions_117901754"] 
                for i in range(len(cloudResponse)):
                    data = {"roleARN": Data[i], "access_key": cloudResponse[i]['AccessKeyId'], "secret_access_key": cloudResponse[i]['SecretAccessKey'],
                    "session_token": cloudResponse[i]['SessionToken'], "expiry_in": TOKEN_DURATION}
                    respData.append(data)
                res={"status_code": 200, "status_message": "success", "data": respData}
            else:
                res = {"status_code": 200, "status_message": "failed to fetch credentials", "data": []}
        else:
            res = {"status_code": 200, "status_message": "No such role has been created for your role", "data": []}
    else:
        res = {"status": 401, "status_message": "Invalid token", "data": []}
    return jsonify(res)

#REFRESH TOKEN API
@app.route('/refresh_token')
def fetch_refresh_token():
    dataresponse = request.get_json()
    if dataresponse != None:
        try:
            key = keycloakPlugin()
            token = key.refreshToken(dataresponse)
            if token:
                result = {"status_code": 200, "status_message": "success", "data":[{"access_token": token['access_token'], 
                            "refresh_token": token['refresh_token'], "expiry": token['expires_in']}]}
            else:
                result = {"status_code": 400, "status_message": "Invalid refresh token", "data": []}
        except Exception as e:
            print("Refresh token mismatch")
            result = {"status_code": 400, "status_message": "Unknown error", "data": []}
    else:
        result = {"status_code": 400, "status_message": "Missing refresh token", "data": []}
    return jsonify(result)

#GETTING KEYCLOAK ROLES API
@app.route('/get_keycloak_roles', methods=['GET'])  
def keycloakRoleDetails():
    try:
        header = request.headers.get('Authorization')
        header_token = header.split(" ")[1]
    except Exception as e:
        print("Missing token in the request header")
        res = {"status_code": 400, "status_message": "Missing authorization token", "data": []}
        return jsonify(res)
    kcPlugin = keycloakPlugin()
    role = kcPlugin.decodeToken(header_token)
    if role == "admin":
        Roles = kcPlugin.getClientRoles()
        responseData = []
        if len(Roles):
            for i in range(len(Roles)):          
                try:
                    rd = Roles[i]['name']
                except Exception:
                    rd = "NA"
                if rd in KEYCLOAK_ROLES :     
                    resp = rd
                    responseData.append(resp)
            msg = "Role details"
            responseData = {"status_code": 200, "status_message": msg, "data":responseData}
            return jsonify(responseData)
        else:
            msg = "No Roles Found"
            responseData = {"status_code": 400, "status_message": msg, "data":[]}
            return jsonify(responseData)
    else:
        msg = "Do not have permission to get users"
        responseData = {"status_code": 400, "status_message": msg, "data":[]}
        return jsonify(responseData)

#GETTING KEYCLOAK USERS API
@app.route('/get_users', methods=['GET'])  
def allUserDetails():
    try:
        header = request.headers.get('Authorization')
        header_token = header.split(" ")[1]
    except Exception as e:
        print("Missing token in the request header")
        res = {"status_code": 400, "status_message": "Missing authorization token", "data": []}
        return jsonify(res)
    kcPlugin = keycloakPlugin()
    role = kcPlugin.decodeToken(header_token)
    if role == "admin":
        users = kcPlugin.getUsers()
        responseData = []
        if len(users):
            for i in range(len(users)):
                try:
                    email = users[i]['email']
                except Exception:
                    email = "NA"
                try:
                    name = users[i]['firstName']+' '+users[i]['lastName']
                except Exception:
                    name = "NA"
                
                try:
                    role = kcPlugin.getUserRoles(users[i]['username'])
                except Exception:
                    role = "NA"
        
                resp = {"username": users[i]['username'], "email": email, "fullname": name, "role": role}
                responseData.append(resp)
            msg = "User details"
            responseData = {"status_code": 200, "status_message": msg, "data":responseData}
            return jsonify(responseData)
        else:
            msg = "No users found"
            responseData = {"status_code": 200, "status_message": msg, "data":responseData}
            return jsonify(responseData)
    else:
        msg = "Do not have permission to get users"
        responseData = {"status_code": 400, "status_message": msg, "data":[]}
        return jsonify(responseData)

#DELETING KEYCLOAK USERS API
@app.route('/delete_user', methods=['DELETE'])
def deleteUserDetails():
    try:
        header = request.headers.get('Authorization')
        header_token = header.split(" ")[1]
    except Exception as e:
        print("Missing token in the request header")
        res = {"status_code": 400, "status_message": "Missing authorization token", "data": []}
        return jsonify(res)
    kcPlugin = keycloakPlugin()
    role = kcPlugin.decodeToken(header_token)
    if role == "admin":
        try:
            username = request.args.get('username')
            if username == "":
                msg = "Please provide proper value"
                responseData = {"status_code": 400, "status_message": msg, "data":[]}
                return jsonify(responseData) 
        except Exception as e:
            msg = "Invalid Input"
            responseData = {"status_code": 400, "status_message": msg, "data":[]}
            return jsonify(responseData) 

        if username == None:
            msg = "Please provide the username to delete"
            responseData = {"status_code": 400, "status_message": msg, "data":[]}
            return jsonify(responseData)

        kd = keycloakPlugin()
        kdresponse, response_message = kd.deleteUserKeycloakDetails(username)
        
        if kdresponse == True:
            dbMain = DatabaseMain()
            roleResponse = dbMain.getCustomRole(username)
            if roleResponse:
                roleARN = roleResponse['roleARN']
                policyDetails = dbMain.findPolicyDetails(_id = roleResponse['policyId'])
                if len(policyDetails):
                    cloudSelector = CloudSelector()
                    cloudResponse = cloudSelector.deleteCustomCloudRole(roleARN=roleARN, policyARNs=policyDetails[0]['policies'])
                    if cloudResponse:
                        dbMain.deleteCustomRole(username)
                else:
                    print("Unable to find policies")
            else:
                print("User has no custom role")
            responseData = {"status_code": 200, "status_message": response_message, "data":[]}
            return jsonify(responseData)
        else:
            responseData = {"status_code": 400, "status_message": response_message, "data":[]}
            return jsonify(responseData)
    else:
        msg = "User do not have permission to delete"
        responseData = {"status_code": 400, "status_message": msg, "data":[]}
        return jsonify(responseData)
    


@app.errorhandler(405)
def doesnt_exist(e):
    return "The path for the desired url does not exist in this api", 405

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=False)