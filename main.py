from fastapi import FastAPI
from apps.login.router import login_router
import uvicorn
import logging
from os import environ
import sys, getopt

from middleware.logging import LoggingMiddleware
from scripts.create_user import create_user

if environ.get('JWT_SECRET', ''):
    logging.info('Environment variables loaded.')
else:
    logging.warning('Environment variables were not loaded, using defaults.')



app = FastAPI()
app.add_middleware(LoggingMiddleware)

app.include_router(login_router, prefix='/auth')

if __name__ == "__main__":
    if(len(sys.argv) > 1 and sys.argv[1] == 'createuser'):
        create_user()
    
    else:
        uvicorn.run(app=app, host='0.0.0.0', port=8000, log_config='log_conf.yaml')