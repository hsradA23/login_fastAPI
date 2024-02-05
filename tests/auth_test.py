import logging

from fastapi import status
from string import ascii_letters
from random import choices

from pytest_mock import mocker

from test_main import client

def get_random_password():
    return ''.join(choices(ascii_letters, k=10))


uname = get_random_password()
passw = get_random_password()
test_headers ={}



logger = logging.getLogger(__name__)

def test_create_user(mocker):
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/register',
                    json={'username' :uname, 'password' : passw}
                    )

    m = r.json()
    assert r.status_code == status.HTTP_200_OK
    assert m['detail'] == 'User created successfully, Go to the login page'

def test_user_login(mocker):
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/login',
                    json={'username' :uname, 'password' : passw}
                    )

    logger.info(r.json())
    assert r.status_code == status.HTTP_200_OK
    assert 'token' in r.json()

def test_user_login_incorrect_user(mocker):
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/login',
                    json={'username' :uname[:-1], 'password' : passw}
                    )
    r_json = r.json()
    logger.info(r.json())
    assert r.status_code == status.HTTP_404_NOT_FOUND
    assert r_json['detail'] == 'User not found'

def test_user_login_incorrect_pass(mocker):
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/login',
                    json={'username' :uname, 'password' : passw[:-1]}
                    )
    r_json = r.json()
    logger.info(r.json())
    assert r.status_code == status.HTTP_403_FORBIDDEN
    assert r_json['detail'].startswith('Incorrect password')

def test_renew_jwt(mocker):
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/login',
                    json={'username' :uname, 'password' : passw}
                    )

    token = r.json()['token']
    test_headers['Authorization'] = 'Bearer ' + token
    r = client.get('/auth/refresh_token',
                    headers=test_headers,
    )
    assert r.status_code == status.HTTP_200_OK
    assert 'token' in r.json()
    token = r.json()['token']
    test_headers['Authorization'] = 'Bearer ' + token


def test_renew_jwt_invalid(mocker):
    invalid_headers = test_headers.copy()
    invalid_headers['Authorization'] = invalid_headers['Authorization'][:-1]
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.get('/auth/refresh_token',
                    headers=invalid_headers,
    )
    assert r.status_code == status.HTTP_403_FORBIDDEN
    assert 'token' not in r.json()

def test_reset_password(mocker):
    global passw, uname
    new_passw = get_random_password()
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/reset_password',
                    headers=test_headers,
                    json={'password' : passw, 'new_password': new_passw}
    )
    r_json = r.json()
    assert r.status_code == status.HTTP_200_OK
    assert r_json['detail'] == 'Password updated successfully'
    passw = new_passw


def test_reset_password_invalid_pass(mocker):
    global passw, uname
    new_passw = get_random_password()
    mock_client = mocker.patch("fastapi.Request.client")
    mock_client.host = '127.0.0.1'
    r = client.post('/auth/reset_password',
                    headers=test_headers,
                    json={'password' : "incorrectPassword", 'new_password': new_passw}
    )
    r_json = r.json()
    assert r.status_code == status.HTTP_403_FORBIDDEN
    assert r_json['detail'] == 'Incorrect password'
    passw = new_passw