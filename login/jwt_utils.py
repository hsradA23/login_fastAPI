import jwt
from datetime import datetime, timedelta
from fastapi.exceptions import HTTPException
from fastapi import status
from os import environ

JWT_SECRET = environ.get('JWT_SECRET', 'secret')
JWT_EXPIRATION_MIN = int(environ.get('JWT_EXPIRATION_MIN', '15'))

credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

def generate_jwt(username: str):
    payload = {
        'sub' : username,
        'exp': datetime.utcnow()+timedelta(minutes=JWT_EXPIRATION_MIN),
        'nbf': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def get_playload_from_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms='HS256')