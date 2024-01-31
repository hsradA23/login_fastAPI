from fastapi import FastAPI
from login.loginRouter import login_router
import uvicorn
from os import environ

if environ.get('JWT_SECRET', ''):
    print('Environment variables loaded.')
else:
    print('Environment variables were not loaded, using defaults.')



app = FastAPI()
app.include_router(login_router, prefix='/auth')

if __name__ == "__main__":
    uvicorn.run(app=app, host='0.0.0.0', port=8000)