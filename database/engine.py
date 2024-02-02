from sqlmodel import SQLModel, create_engine
from os import environ

def __get_sqlite_engine():
    sqlite_file_name = "database.db"
    sqlite_url = f"sqlite:///{sqlite_file_name}"
    connect_args = {"check_same_thread": False}
    engine = create_engine(sqlite_url, connect_args=connect_args)
    return engine


def __get_postges_engine():
    engine = create_engine(environ['POSTGRES_URL'], echo=True)
    return engine


def __create_db_and_tables(engine):
    SQLModel.metadata.create_all(engine)


engine = __get_sqlite_engine()
# engine = get_postges_engine()
__create_db_and_tables(engine=engine)