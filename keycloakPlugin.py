from keycloak import KeycloakOpenID
from settings import *
import requests
import json

class keycloakPlugin(object):
    
    def get_oidc(self):
        return KeycloakOpenID(server_url=KEYCLOAK_SERVER_URL,
                                client_id=CLIENT_ID,
                                realm_name=REALM_NAME,
                                client_secret_key=CLIENT_SECRET)

    def getAdminToken(self):
        ADMIN_OBJ = {
        "client_id" : "admin-cli",
        "username" : "admin",
        "password" : "admin",
        "grant_type" : "password"
        }
        ADMIN_URL = KEYCLOAK_SERVER_URL+"realms/master/protocol/openid-connect/token"
        try:
            r = requests.post(ADMIN_URL, data=ADMIN_OBJ).json()
            access_token = r['access_token']
            return access_token
        except Exception as e:
            print("Invalid Token")
            return False
    
    def getToken(self,user,password):
        try:   
            token = self.get_oidc().token(user, password)
            return token         
        except Exception as e:
            #print(e.message)
            return False

    def decodeToken(self, access_token):

        if access_token == "":
            print("Missing access token value")
            return None
            
        KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + self.get_oidc().public_key() + "\n-----END PUBLIC KEY-----"
        import jwt

        try:
            response = jwt.decode(access_token, KEYCLOAK_PUBLIC_KEY, algorithms=ALGORITHM)
        except jwt.ExpiredSignatureError:
            print('Signature has expired.')
            res = None
        except jwt.DecodeError:
            print('Error decoding signature.')
            res = None
        except jwt.InvalidAudienceError:
            response = jwt.decode(access_token, KEYCLOAK_PUBLIC_KEY, algorithms=ALGORITHM, audience=AUDIENCE)
            res = response['resource_access']['PythonKeycloak']['roles'][0]
        return res

    def createUser(self, username, password, email_id, firstname, lastname, rolename):
        access_token = self.getAdminToken()
        URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users"
        OBJ = {
            "username" : username,
            "email" : email_id,
            "firstName" : firstname,
            "lastName" : lastname,
            "enabled": True,
            "credentials":[{"type":"password","value":password,"temporary":False}]
        }
        HEADERS_OBJ = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-type' : 'application/json'
        }
        try:
            r = requests.post(URL, json=OBJ, headers=HEADERS_OBJ)
            if r.status_code == 409:
                return False, "User already exists"
        except Exception as e:
            return False, "Unable to create the user"
        if r.status_code == 201:
            user_Id = self.getUserId(username, access_token)
            if user_Id:
                role_Id = self.getRoleInfo(rolename, access_token)
                if role_Id:
                    return self.mapRoleToUser(user_Id, role_Id, rolename, access_token)
                else:
                    return False, "Unable to fetch role info"
            else:
                return False, "Unable to fetch user info"
        else:
            return False, "Unknown error"


    def refreshToken(self, dataresponse):
        try:  
            token = self.get_oidc().refresh_token(dataresponse['refresh_token'])
            return token
        except Exception as e:
            return False

    def deleteUser(self, username):
        access_token = self.getAdminToken()
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        USER_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users?username="+username+"&exact=true"
        try:
            r = requests.delete(USER_URL, headers=HEADER_OBJ).json()
            return True
        except Exception as e:
            print("Unable to delete the user")
            return False

    def getUserId(self, username, access_token):
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        USER_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users?username="+username+"&exact=true"
        try:
            r = requests.get(USER_URL, headers=HEADER_OBJ).json()
            return r[0]['id']
        except Exception as e:
            print("Unable to fetch the user")
            return False

    def getRoleInfo(self, rolename, access_token):
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        ROLE_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/roles/"+rolename
        try:
            r = requests.get(ROLE_URL, headers=HEADER_OBJ).json()
            return r['id']
        except Exception as e:
            print("Unable to fetch the role")
            return False

    def mapRoleToUser(self, user_id, role_id, rolename, access_token):
        OBJ = [
            {
                "id" : role_id,
                "name" : rolename
            }
        ]

        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token),
            'Content-type' : 'application/json'
        }

        MAP_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users/"+user_id+"/role-mappings/realm"
        try:
            r = requests.post(MAP_URL, json=OBJ, headers=HEADER_OBJ)
            return True, "User is created Successfully"
        except Exception as e:
            return False, "Role is not added to the user"

    def getClientRoles(self):
        access_token = self.getAdminToken()
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        ROLE_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/roles"
        try:
            r = requests.get(ROLE_URL, headers = HEADER_OBJ).json()
            return r
        except Exception as e:
            return []

    def getUsers(self):
        access_token = self.getAdminToken()
        URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users"
        HEADERS_OBJ = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-type' : 'application/json'
        }
        try:
            r = requests.get(URL, headers=HEADERS_OBJ).json()
            if r:
                return r
            else:
                return []
        except Exception as e:
            return []

    def getUserRoles(self, username):
        access_token = self.getAdminToken()
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        USER_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users/?username="+username
        r=requests.get(USER_URL, headers=HEADER_OBJ).json()
        if r == []:
            return True, "No user exists with that name"
        else:
            userid = r[0]['id']
            ROLE_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users/"+userid+"/role-mappings"
            try:
                a = requests.get(ROLE_URL, headers=HEADER_OBJ).json()
                userrole = a['realmMappings'][0]['name']
                return userrole
            except Exception as e:
                return 'NA'

    def deleteUserKeycloakDetails(self, username):
        access_token = self.getAdminToken()
        HEADER_OBJ = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        USER_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users/?username="+username
        r=requests.get(USER_URL, headers=HEADER_OBJ).json()
        if r == []:
            return True, "No user exists with that name"
        else:
            userid = r[0]['id']
            DEL_URL = KEYCLOAK_SERVER_URL+"admin/realms/PythonDemo/users/"+userid
            try:
                a = requests.delete(DEL_URL, headers=HEADER_OBJ)
                return True, "User deleted successfully"
            except Exception as e:
                return False, "User not deleted"
            
            
    @staticmethod
    def check_token(self, access_token):
        oidc = self.get_oidc()
        token_info = oidc.introspect(access_token)
        if token_info.get('active'):
            return True
        return False