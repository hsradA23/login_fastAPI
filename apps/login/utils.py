from .jwt_utils import get_playload_from_token
from models.auth import User, UserData
from datetime import datetime
from sqlmodel import Session, select
from fastapi import HTTPException, status, Depends
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError

from database.utils import get_passhash
from database.engine import engine

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

def get_validated_user(userData: UserData):
    with Session(engine) as session:
        users = session.exec(select(User).where(User.username == userData.username))
        user = users.first()

        # User does not exist
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
        
        #User is locked
        if user.is_locked():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User is temporarily locked.')

        # Password Incorrect
        if (user.password != get_passhash(userData.password)):
            user.last_failed_attempt = datetime.utcnow()
            session.add(user)
            session.commit()
            remaining_attempts = user.remaining_attempts()

            raise HTTPException(detail='Account temporarily locked.', status_code=status.HTTP_403_FORBIDDEN)

        return user


def get_token_data(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        data = get_playload_from_token(token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login token has expired. You need to log in again.')
    except InvalidSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login session is invalid. You need to log in again.')
    return data


def get_loggedin_user(data: Annotated[dict, Depends(get_token_data)]):
    with Session(engine) as session:
        return session.exec(select(User).where(User.username == data['sub'])).first()