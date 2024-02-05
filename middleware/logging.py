from datetime import datetime
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging 

logger = logging.getLogger('api.logger')

class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app,
    ):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        time = datetime.utcnow()
        response = await call_next(request)
        path = request.url.path
        client_host = request.client.host
        status_code = response.status_code
        logger.info(f"Path: {path}, Client IP: {client_host}, Status Code: {status_code}")
        return response