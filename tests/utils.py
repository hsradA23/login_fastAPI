from sqlmodel import Session

from models.auth import User
from database.engine import engine

from string import ascii_letters
from random import choices

from database.utils import get_passhash

def get_random_string():
    return ''.join(choices(ascii_letters, k=10))


def create_user():
    with Session(engine) as session:
        username = get_random_string()
        password = get_random_string()
        hash = get_passhash(password)

        user = User(username=username, password=hash)
        session.add(user)
        session.commit()

        return (username, password)




