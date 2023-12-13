import unittest
import requests

class TestMethods(unittest.TestCase):
    API_URL = "http://localhost:5000"
    REGISTER_URL = "{}/register".format(API_URL)
    LOGIN_URL = "{}/login".format(API_URL)
    REFRESH_TOKEN_URL = "{}/refresh_token".format(API_URL)
    GET_CREDITIONALS_URL = "{}/get_access_credentials".format(API_URL)
    USERS_URL = "{}/get_users".format(API_URL)
    DELETE_URL = "{}/delete_user?username=".format(API_URL)
    ROLE_KEYCLOAK_URL = "{}/get_keycloak_roles".format(API_URL)
    token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlNXlrUXY1RG1lVG9rdlNXMTNoZWRjam9FMmtuZkN5UTRkZDZUandTOHNNIn0.eyJleHAiOjE2Mzk5OTE1MzUsImlhdCI6MTYzOTk5MDkzNSwianRpIjoiM2E5NWE1ZjAtNzA4NS00NGYwLWExZjktOGUzMjFkOGY1M2Y4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL1B5dGhvbkRlbW8iLCJzdWIiOiJiZmVlZjhhNS04ODQ2LTQyOTItYjEwNi1lMWVmMDFmYTZhNjgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJQeXRob25LZXljbG9hayIsInNlc3Npb25fc3RhdGUiOiI2NDYzODQ2Ny1iZDYwLTRkMzAtYmViNC0zYmNmNDY2ZDJlZTkiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiQWRtaW4iXX0sInJlc291cmNlX2FjY2VzcyI6eyJQeXRob25LZXljbG9hayI6eyJyb2xlcyI6WyJhZG1pbiJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjY0NjM4NDY3LWJkNjAtNGQzMC1iZWI0LTNiY2Y0NjZkMmVlOSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjEifQ.h2jRC6G58PnPlsbaPCWTMSC6J87xZlD5P-yeXDYgSWjumkeGkGedixZNcK5kei2j1s_xEi16TApH7gJwhDvAuKeuzooIGycJnA8ZWWjECunsaBlI5mXpQIf4-qs7uQs60uNsKJJ7B2dI9NSTn9NyDa9V9JqFmn31CjBI6_DQMVN_fxxSNHa-WM5OkUC0HDWbAOkQUVetSm4AWXdD8CTCB9EDzKnCFeZk33PN2VDjkqOz6IaJtuLT5JbyZ4b84H-kwTH6xpmTCq0IgFLzICnES4axrBUDZqJxEgm3ma0KZmmvq3xrjG5Y4UGa0VwDzJCve3jbvVtEjIHMkLaO7xe_sg"
    
    REGISTER_OBJ = {
        "username": "user25",
        "firstName": "user25",
        "lastName": "user25",
        "role": "Developer",
        "email": "user25@gmail.com",
        "password": "password",
        "hasaccount": False,
        #"personal_accountid": "735455110910",
        #"personal_username": "Demo_user"
    }
    
    LOGIN_OBJ = {
        "username": "manohar",
        "password": "manohar"
    }
    
    REFRESH_TOKEN_OBJ = {
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZGQwYzg5S03MzBhLTRmN2UtOTlhYS0xNTI4NGRiZTBmNjcifQ.eyJleHAiOjE2Mzg0MjQ5ODgsImlhdCI6MTYzODQyMzE4OCwianRpIjoiYzBhNjE5MzMtZjQ2Ni00YzNmLTlmZDctMTRhZTNiY2Q4ODJkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL1B5dGhvbkRlbW8iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvUHl0aG9uRGVtbyIsInN1YiI6ImIwNzczZTI2LTljYjYtNDc4NS1hM2I3LTMxMjZhY2RhYjEwMSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJQeXRob25LZXljbG9hayIsInNlc3Npb25fc3RhdGUiOiI5NmUwNzcyZS1jMDU5LTQ4MjMtODBiNS0wNTA4NTEyYmNiMmUiLCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiI5NmUwNzcyZS1jMDU5LTQ4MjMtODBiNS0wNTA4NTEyYmNiMmUifQ.kpT62_eZ8LrhT-NaLbJSXopgD2D3SYb6qviWOhbJQhA"
        
    }

    HEADERS_OBJ = {
        'Authorization': 'Bearer {}'.format(token)
    }

    def test_register(self):
        r = requests.post(TestMethods.REGISTER_URL, json=TestMethods.REGISTER_OBJ)
        print(r.content)
        self.assertEqual(r.status_code, 200)
    
    def test_login(self):
        r = requests.post(TestMethods.LOGIN_URL, json=TestMethods.LOGIN_OBJ)
        print(r.content)
        self.assertEqual(r.status_code, 200)       
    
    def test_fetch_access_credentials(self):
        r = requests.get(TestMethods.GET_CREDITIONALS_URL, headers=TestMethods.HEADERS_OBJ)
        print(r.content)
        self.assertEqual(r.status_code, 200)

    def test_fetch_refresh_token(self):
        r = requests.get(TestMethods.REFRESH_TOKEN_URL, json=TestMethods.REFRESH_TOKEN_OBJ)
        #print(r.content)
        self.assertEqual(r.status_code, 200)

    def test_get_users(self):
        r = requests.get(TestMethods.USERS_URL, headers=TestMethods.HEADERS_OBJ)
        self.assertEqual(r.status_code, 200)

    def test_get_keycloak_roles(self):
        r = requests.get(TestMethods.ROLE_KEYCLOAK_URL, headers=TestMethods.HEADERS_OBJ)
        self.assertEqual(r.status_code, 200)

    def test_delete_user(self):
        r = requests.delete(TestMethods.DELETE_URL, headers=TestMethods.HEADERS_OBJ)
        self.assertEqual(r.status_code, 200)

if __name__ == '__main__':
    unittest.main()