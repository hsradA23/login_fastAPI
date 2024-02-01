import pytest

import re
import requests
import json
from random import choices
from string import ascii_letters

uname = ''.join(choices(ascii_letters, k=10))
passw = ''.join(choices(ascii_letters, k=10))
new_passw = ''.join(choices(ascii_letters, k=10))

def test_user_creation():
    url = "http://localhost:8000/auth/register"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    assert response.text == '{"detail":"User created successfully, Go to the login page"}'

def test_duplicate_user_creation():
    url = "http://localhost:8000/auth/register"

    payload = json.dumps({
    "username": uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    assert response.text == '{"detail":"Username already taken"}'

def test_valid_user_login():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    r_json = response.json()
    assert 'token' in r_json
    assert 'detail' not in response

def test_incorrect_pass_login():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": "134"
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload).json()
    assert 'detail' in response
    assert 'token' not in response

def test_incorrect_user_login():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname[:-1],
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload).json()
    assert 'detail' in response
    assert 'token' not in response

def test_valid_jwt_renew():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    r_json = response.json()
    token = r_json['token']
    headers['Authorization'] = 'Bearer '+ token

    url = "http://localhost:8000/auth/refresh_token"
    response = requests.request("GET", url, headers=headers)
    r_json = response.json()
    assert 'token' in r_json
    assert 'detail' not in r_json


def test_invalid_jwt_renew():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    r_json = response.json()
    token = r_json['token']
    headers['Authorization'] = 'Bearer '+ token[:-1]

    url = "http://localhost:8000/auth/refresh_token"
    response = requests.request("GET", url, headers=headers)
    r_json = response.json()
    assert 'token' not in r_json
    assert 'detail' in r_json



def test_no_jwt_renew():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    r_json = response.json()

    url = "http://localhost:8000/auth/refresh_token"
    response = requests.request("GET", url, headers=headers)
    r_json = response.json()
    assert 'token' not in r_json
    assert 'detail' in r_json


def test_reset_password():
    url = "http://localhost:8000/auth/reset_password"

    payload = json.dumps({
    "username": uname,
    "password": passw,
    "new_password": new_passw
    })
    headers = {
    'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload).json()
    assert response['detail'] ==  'Password updated successfully'

    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    r_json = response.json()
    assert 'token' not in r_json
    assert 'detail' in r_json


    payload = json.dumps({
    "username":uname,
    "password": new_passw
    })

    response = requests.request("POST", url, headers=headers, data=payload)
    r_json = response.json()
    assert 'token' in r_json
    assert 'detail' not in r_json



def test_reset_password_invalid_pass():
    url = "http://localhost:8000/auth/reset_password"

    payload = json.dumps({
    "username": uname,
    "password": passw,
    "new_password": new_passw
    })
    headers = {
    'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload).json()
    assert response['detail'] ==  'Incorrect password'


def test_reset_password_invalid_username():
    url = "http://localhost:8000/auth/reset_password"

    payload = json.dumps({
    "username": uname[:-1],
    "password": passw,
    "new_password": new_passw
    })
    headers = {
    'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload).json()
    assert response['detail'] ==  'Username not found'

def test_user_locks():
    url = "http://localhost:8000/auth/login"

    payload = json.dumps({
    "username":uname,
    "password": passw
    })
    headers = {
    'Content-Type': 'application/json'
    }

    for _ in range(6):
        response = requests.request("POST", url, headers=headers, data=payload)


    response = requests.request("POST", url, headers=headers, data=payload).json()

    assert response['detail'] == 'Your account has been locked due to multiple failed login attempts'
