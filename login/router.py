from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, status, Request , Response, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError

from database.utils import get_postges_engine, get_sqlite_engine, create_db_and_tables, get_passhash
from models.auth import User, UserData, LoginLogs, LoginLogsCreate, ResetPasswordModel
from .jwt_utils import generate_jwt, get_playload_from_token

login_router = APIRouter()
engine = get_sqlite_engine()
# engine = get_postges_engine()
create_db_and_tables(engine=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

@login_router.post('/login')
def handle_login(userData: UserData, response: Response, request: Request):
    with Session(engine) as session:
        users = session.exec(select(User).where(User.username == userData.username))
        user = users.first()

        # User does not exist
        if not user:
            response.status_code = status.HTTP_404_NOT_FOUND
            return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
        
        #User is locked
        if user.is_locked():
            return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User is locked due to multiple invalid login attempts')
        
        # Password incorrect
        if (user.password != get_passhash(userData.password)):
            user.failed_attempts += 1
            session.add(user)
            session.commit()
            remaining_attempts = user.remaining_attempts()

            return HTTPException(detail=f'Incorrect password, you have {remaining_attempts} attempt{"" if remaining_attempts == 1 else "s" } left.',
                                 status_code=status.HTTP_403_FORBIDDEN)

        # Checking if password was changed recently
        if user.password_change_needed():
            return RedirectResponse('reset_password', status_code=status.HTTP_303_SEE_OTHER) 

        # Valid Login
        if user.failed_attempts > 0:
            user.failed_attempts = 0
            session.add(user)

        # Checks if the user IP is valid
        try:
            login = LoginLogsCreate(user_id=user.id, ip=request.client.host )
        except:
            return HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        login = LoginLogs.model_validate(login)
        session.add(login)
        session.commit()

        return {'token':generate_jwt(user.username)}

# Placeholder page
@login_router.get('/reset_password')
def get_reset():
    return 'RESET PAGE HERE'

@login_router.post('/reset_password')
def handle_reset(userData: ResetPasswordModel, response: Response):
    with Session(engine) as session:
        users = session.exec(select(User).where(User.username == userData.username))
        user = users.first()
        # Username is incorrect
        if not user:
            return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Username not found')
        
        #User is locked
        if user.is_locked():
            return HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail='Your account has been locked due to multiple failed login attempts')
        
        # Password incorrect
        if (user.password != get_passhash(userData.password)):
            return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Incorrect Password')
        
        
        # Current details are valid, Changing password
        user.password = get_passhash(userData.new_password)
        user.password_changed = datetime.utcnow()
        session.add(user)
        session.commit()
        return {'detail' : 'Password updated successfully'}


@login_router.post('/register')
def handle_register(userData: UserData, response: Response):
    with Session(engine) as session:
        # Check if user already exists
        user = session.exec(select(User).where(User.username == userData.username)).first()
        if user:
            return HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Username already taken')

        user = User(username=userData.username, password=get_passhash(userData.password))
        session.add(user)
        session.commit()
        response.status_code = status.HTTP_201_CREATED
        return {'detail':'User created successfully, Go to the login page'}


@login_router.get('/refresh_token')
def refresh_token(token: Annotated[str, Depends(oauth2_scheme)], response:Response):
    '''
    Takes a token from the request, validates it and sends back a new token
    '''
    try:
        token_payload = get_playload_from_token(token)
    except ExpiredSignatureError:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login token has expired.')
    except:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login token is not valid')

    return {'token':generate_jwt(username=token_payload['sub'])}


# DEBUG FUNCTION - checks if the token is valid
@login_router.get('/check_login')
def secure_endpoint(token: Annotated[str, Depends(oauth2_scheme)], response : Response):
    '''
    Checks if user is logged in.
    '''
    try:
        get_playload_from_token(token)
    except ExpiredSignatureError:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login token has expired. You need to log in again.')
    except InvalidSignatureError:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='The login session is invalid. You need to log in again.')

    return 'Logged In'