from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from os import environ

MAX_INCORRECT_ATTEMPTS = int(environ.get('MAX_INCORRECT_ATTEMPTS', '5'))
MAX_PASSWORD_MONTHS = int(environ.get('MAX_PASSWORD_MONTHS', '6'))

class Users(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, default=None)
    username: str = Field(unique=True)
    password: str
    password_changed: datetime = Field(default=datetime.utcnow(), nullable=False)
    failed_attempts: int = Field(default=0)

    def is_locked(self):
        return self.failed_attempts >= MAX_INCORRECT_ATTEMPTS

    def remaining_attempts(self):
        return MAX_INCORRECT_ATTEMPTS - self.failed_attempts + 1

    def password_change_needed(self):
        d = datetime.utcnow() - self.password_changed
        return d.days > 30*6 # Change password after 6 months

class LoginLogs(SQLModel, table=True):
    id:int =  Field(primary_key=True)
    user_id: int =  Field(foreign_key='users.id')
    ip: str
    time : datetime = Field(default=datetime.utcnow())

class ResetPasswordModel(SQLModel, table=False):
    username : str
    password : str
    new_password : str