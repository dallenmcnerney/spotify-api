import requests as re
import base64
import json
from urllib import parse

''' 
    Spotify API documentation:
        https://developer.spotify.com/documentation/general/guides/authorization-guide/
    
    Authorization code flow:
        1) Have your application request authorization; the user logs in and authorizes access
            a) GET https://accounts.spotify.com/authorize
            b) Required: 
                client_id - When you register your application, Spotify provides you a Client ID.
                response_type - Set to 'code'.
                redirect_uri = The URI to redirect to after the user grants or denies permission. This must be set in 
                    Spotify dashboard.
            c) Optional:
                state: strongly recommended to ensure that incoming connection is result of authentication request
                scope: space-separated list of scopes. authorization will be granted to public only if left as none
                show-dialog: false is default. whether or not user has to approve app again
                
'''


class SpotifyAuthorizationCode(object):
    def __init__(self):
        self.auth = 'auth.json'
        self.token = 'api_token.json'
        self.code = 'code.json'
        self.client_id = ''
        self.secret_key = ''
        self.read_auth()
        self.api_token = ''
        self.refresh_token = ''
        self.get_api_token()
        self.code_key = ''
        self.get_code_key()
        self.url_authorize = 'https://accounts.spotify.com/authorize'
        self.url_token = 'https://accounts.spotify.com/api/token'
        self.url_redirect = 'http://localhost:8888/callback/'
        self.scope = 'user-read-recently-played'
        self.authorization_header = self.create_authorization_header()

    # Read local auth.json file to pass client id and secret key
    def read_auth(self):
        with open(self.auth, 'r') as file:
            authentication = json.load(file)
        self.client_id = authentication['client_id']
        self.secret_key = authentication['secret_key']

    # Generate Basic Authorization header with 64-bit encoded authorization to pass in post requests
    def create_authorization_header(self):
        authorization = (self.client_id + ':' + self.secret_key).encode('ascii')
        authorization_base64 = base64.b64encode(authorization).decode('ascii')
        header = {'Authorization': 'Basic ' + authorization_base64}
        return header

    # Generate authorization url to be passed through browser. Redirect url will contain code for api token generation
    def generate_authorization_code(self):
        data = {'client_id': self.client_id,
                'response_type': 'code',
                'redirect_uri': self.url_redirect,
                'scope': self.scope}
        url_parameters = parse.urlencode(data)
        url_authorization = self.url_authorize + '?' + url_parameters
        return url_authorization

    # Get code stored in code.json file
    def get_code_key(self):
        with open(self.code, 'r') as file:
            api_token = json.load(file)
        self.code_key = api_token['code']

    # Using code from authorization url, generate local API token JSON file
    def generate_api_token(self):
        data = {'redirect_uri': self.url_redirect,
                'code': self.code,
                'grant_type': 'authorization_code',
                'scope': self.scope}
        response = re.post(self.url_token, data=data, headers=self.authorization_header)
        self.response_status(response)
        api_token = response.json()
        with open('api_token.json', 'w') as file:
            file.write(json.dumps(api_token))

    # Pass API token from local api_token.json
    def get_api_token(self):
        with open(self.token, 'r') as file:
            api_token = json.load(file)
        self.api_token = api_token['access_token']
        try:
            self.refresh_token = api_token['refresh_token']
        except KeyError:
            self.refresh_token = ''
            print('No refresh token in token JSON file')

    # API token has a timeout, so this uses local API token JSON file to refresh API token
    def refresh_api_token(self):
        data = {'refresh_token': self.refresh_token, 'grant_type': 'refresh_token'}
        response = re.post('https://accounts.spotify.com/api/token', data=data,
                           headers=self.authorization_header)
        self.response_status(response)
        new_token = response.json()
        with open(self.token, 'r') as file:
            api_token = json.load(file)
        api_token['access_token'] = new_token['access_token']
        with open(self.token, 'w') as file:
            file.write(json.dumps(api_token))
        self.api_token = new_token['access_token']

    # Check status of response
    def response_status(self, response):
        if response.status_code == 200:
            return True
        elif response.status_code == 401 and 'expired' in response.text:
            self.refresh_api_token()
            return False
        else:
            print('Error', str(response.status_code))
            print(response.reason)
            print(response.text['error_description'])
            exit()


class SpotifyApi:
    def __init__(self, authentication_object):
        self.authentication = authentication_object
        if not authentication_object.api_token:
            raise AttributeError

    # https://developer.spotify.com/documentation/web-api/reference/player/get-recently-played/
    def recently_played(self):
        url = 'https://api.spotify.com/v1/me/player/recently-played'
        header = {'Authorization': 'Bearer ' + self.authentication.api_token}
        response = re.get(url=url, headers=header)
        if not self.authentication.response_status(response):
            response = re.get(url=url, headers=header)
        tracks = response.json()
        return tracks


def main():
    auth = SpotifyAuthorizationCode()
    spotify = SpotifyApi(auth)
    return spotify.recently_played()


if __name__ == "__main__":
    main()

# TODO additional error handling
# TODO write retrieved data to file
# TODO additional documentation
