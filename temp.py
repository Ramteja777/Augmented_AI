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

                if not isinstance(username, str) and isinstance(firstname, str) and isinstance(lastname, str) and isinstance(role, str) and isinstance(email, str) and isinstance(password, str) and isinstance(hasaccount, bool):
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
                            if cloud
