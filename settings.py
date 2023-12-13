# Keycloak Info

KEYCLOAK_SERVER_URL = "http://localhost:8080/auth/"
ADMIN_USERNAME = "admin"
ADMIN_PASS = "admin"
REALM_NAME = "PythonDemo"
CLIENT_ID = "PythonKeycloak"
CLIENT_SECRET = "DkE0IIUNjBPgZEAVngthSgUf5hHfjF6k"
ALGORITHM = ['RS256']
AUDIENCE = "account"

#Mongo Info

MONGO_SERVER_URL = "127.0.0.1"
MONGO_PORT = 27017
DBNAME = "neuredadb"

#Cloud provider info

CLOUD_PROVIDER_NAME = "aws"
REGION_NAME = "ap-south-1"
TOKEN_DURATION = 900
ADMIN_ACCOUNT_ID = "735455110910"

#IAM user info details
IAM_USER_ACCESS_KEY = "AKIA2WPEKM37EETRSWP6"
IAM_USER_SECRET_KEY = "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"
ASSUMEROLEPOLICY = "arn:aws:iam::735455110910:policy/AssumeRolePolicy"

#Role details
KEYCLOAK_ROLES = ['developer', 'tester', 'admin']