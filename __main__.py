import requests as re
import base64
import json
from selenium import webdriver

''' 
    Spotify API documentation:
        https://developer.spotify.com/documentation/general/guides/authorization-guide/
    
    Request authorization:
        1) POST https://accounts.spotify.com/api/token
        2) REQUIRED: grant_type Set it to client_credentials.
        3) REQUIRED Base 64 encoded string that contains the 
            client ID and client secret key. The field must have the format: 
                Authorization: Basic <base64 encoded client_id:client_secret>
'''


def get_client_credentials_token(json_file):
    with open(json_file, 'r') as file:
        authentication = json.load(file)
    authorization = (authentication['client_id'] + ':' + authentication['secret_key']).encode('ascii')
    authorization_base64 = base64.b64encode(authorization).decode('ascii')
    header = {'Authorization': 'Basic ' + authorization_base64}
    url_token = 'https://accounts.spotify.com/api/token'
    token_parameters = {'grant_type': 'client_credentials'}
    token = re.post(url=url_token, data=token_parameters, headers=header).json()
    return token


def get_implicit_token(json_file):
    url = request_url(json_file)
    token = web_request_token(url)


def request_url(json_file):
    with open(json_file, 'r') as file:
        authentication = json.load(file)
    client_id = authentication['client_id']
    auth_url = 'https://accounts.spotify.com/authorize'
    response_type = 'token'
    redirect_uri = 'http://localhost:8888/callback/'
    scope = 'user-read-recently-played'
    url = auth_url + '?' + 'client_id=' + client_id + \
                  '&redirect_uri=' + redirect_uri + '&scope=' + scope + \
                  '&response_type=' + response_type
    return url


def web_request_token(url):
    driver = webdriver.Chrome()
    driver.get(url)

    # Todo: Use controls to run run through selenium browser results
    # response = driver.current_url
    # access_token = response[response.find('access_token'):response.find('&token')].split('=')[1]
    # return access_token

get_implicit_token('auth.json')


def recently_played(access_token):
    url = 'https://api.spotify.com/v1/me/player/recently-played'
    header = {'Authorization': 'Bearer ' + access_token}
    tracks = re.get(url=url, headers=header).json()
    return tracks
