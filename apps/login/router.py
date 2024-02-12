from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, status, Request , Response, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlmodel import Session

from database.utils import get_passhash
from database.engine import engine
from models.auth import User, UserData, LoginLogs, LoginLogsCreate, ResetPasswordModel
from .jwt_utils import generate_jwt
from .utils import get_token_data, get_validated_user, get_loggedin_user

from fastapi.security import OAuth2PasswordBearer

login_router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

@login_router.post('/login')
def handle_login(user: Annotated[User, Depends(get_validated_user)], request: Request ):
    with Session(engine) as session:
        if user.password_change_needed():
            return RedirectResponse('reset_password', status_code=status.HTTP_303_SEE_OTHER) 

        # Valid Login
        if user.failed_attempts > 0:
            user.failed_attempts = 0
            session.add(user)

        # Checks if the user IP is valid
        try:
            login = LoginLogsCreate(user_id=user.id, ip=request.client.host)
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
def handle_reset(userInput: ResetPasswordModel,
                  user : Annotated[User, Depends(get_loggedin_user)]):
    with Session(engine) as session:
        if get_passhash(userInput.password) != user.password:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Incorrect password')
        # Current details are valid, Changing password
        user.password = get_passhash(userInput.new_password)
        user.password_changed = datetime.utcnow()
        session.add(user)
        session.commit()
        return {'detail' : 'Password updated successfully'}


@login_router.get('/refresh_token')
def refresh_token(data: Annotated[str, Depends(get_token_data)], response:Response):
    '''
    Takes a token from the request, validates it and sends back a new token
    '''
    return {'token':generate_jwt(username=data['sub'])}


# DEBUG FUNCTION - checks if the token is valid
@login_router.get('/check_login')
def secure_endpoint(user: Annotated[User, Depends(get_loggedin_user)], response : Response):
    '''
    Checks if user is logged in.
    '''
    return 'Logged In as ' + user.username