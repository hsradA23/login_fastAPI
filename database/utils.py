from sqlmodel import SQLModel, create_engine
from hashlib import md5
from os import environ

def get_passhash(password):
    return md5(password.encode('utf-8')).hexdigest()


def get_sqlite_engine():
    sqlite_file_name = "database.db"
    sqlite_url = f"sqlite:///{sqlite_file_name}"
    connect_args = {"check_same_thread": False}
    engine = create_engine(sqlite_url, connect_args=connect_args)
    return engine


def get_postges_engine():
    engine = create_engine(environ['POSTGRES_URL'], echo=True)
    return engine


def create_db_and_tables(engine):
    SQLModel.metadata.create_all(engine)

