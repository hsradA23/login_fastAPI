from sqlmodel import SQLModel, Field
from pydantic import BaseModel, IPvAnyAddress, BaseModel, field_validator
from typing import Optional
from datetime import datetime, timedelta
from os import environ

MAX_INCORRECT_ATTEMPTS = int(environ.get('MAX_INCORRECT_ATTEMPTS', '5'))
MAX_PASSWORD_MONTHS = int(environ.get('MAX_PASSWORD_MONTHS', '6'))
INCORRECT_LOGIN_TIMEOUT_SECONDS = int(environ.get('INCORRECT_LOGIN_TIMEOUT_SECONDS ', '10'))

class UserData(BaseModel):
    username: str
    password: str

class User(UserData, SQLModel, table=True):
    id: int = Field(primary_key=True, default=None)
    password_changed: datetime = Field(default=datetime.utcnow(), nullable=False)
    failed_attempts: int = Field(default=0)
    last_failed_attempt: datetime = Field(default=None , nullable=True)

    def is_locked(self):
        if self.last_failed_attempt:
            return datetime.utcnow() - self.last_failed_attempt < timedelta(seconds=INCORRECT_LOGIN_TIMEOUT_SECONDS)
        else:
            return False

    def remaining_attempts(self):
        return MAX_INCORRECT_ATTEMPTS - self.failed_attempts + 1

    def password_change_needed(self):
        d = datetime.utcnow() - self.password_changed
        return d.days > 30*6 # Change password after 6 months

class LoginLogsCreate(SQLModel):
    user_id: int =  Field(foreign_key='user.id')
    ip : str
    time : datetime = Field(default=datetime.utcnow())
    
    @field_validator("ip")
    def validate_ip_addr(cls, ip):
        IPvAnyAddress(value=ip) # Raises an error if the IP is invalid
        return ip


class LoginLogs(LoginLogsCreate, table=True):
    id: Optional[int] = Field(primary_key=True, default=None)

class ResetPasswordModel(BaseModel):
    password : str
    new_password : str