import base64
from fastapi import Depends, FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.docs import get_swagger_ui_html
from starlette.responses import RedirectResponse, Response, JSONResponse
from starlette.requests import Request

from loguru import logger

from internal.auth import COOKIE_DOMAIN_NAME, API_PORT, JWT_ACCESS_TOKEN_EXPIRE_MINUTES
from internal.auth import Token, BasicAuth
from internal.auth import basic_auth, create_access_token, authenticate_user, get_current_active_user
from endpoints import testme, user_info

import uvicorn
from uvicorn_loguru_integration import run_uvicorn_loguru

logger.info(f'setting cookie domain name to {COOKIE_DOMAIN_NAME}, '
            f'must use this in browser, ie http://{COOKIE_DOMAIN_NAME}:{API_PORT}/login_basic')


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get('/')
async def homepage():
    return 'Welcome to the API!'


@app.post('/token', response_model=Token)
async def route_login_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(username=form_data.username, uid=form_data.password, netaddr=request.client.host)
    if not user:
        raise HTTPException(status_code=400, detail='Incorrect username or password')
    access_token = create_access_token(data=dict(sub=form_data.username))
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/login_basic')
async def login_basic(request: Request, auth: BasicAuth = Depends(basic_auth)):
    if not auth:
        response = Response(headers={'WWW-Authenticate': 'Basic'}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode('ascii')
        username, _, password = decoded.partition(':')
        user = authenticate_user(username=username, uid=password, netaddr=request.client.host)
        if not user:
            raise HTTPException(status_code=400, detail='Incorrect username or password')

        access_token = create_access_token(data=dict(sub=username))
        token = jsonable_encoder(access_token)

        response = RedirectResponse(url='/docs')
        response.set_cookie(
            'Authorization',
            value=f'Bearer {token}',
            domain=COOKIE_DOMAIN_NAME,
            httponly=True,
            max_age=60 * JWT_ACCESS_TOKEN_EXPIRE_MINUTES,  # lifetime of cookie in seconds
            expires=60 * JWT_ACCESS_TOKEN_EXPIRE_MINUTES,  # number of seconds until cookie expires
        )
        logger.debug(f'login_basic sending {JWT_ACCESS_TOKEN_EXPIRE_MINUTES} min cookie')
        return response

    except:
        response = Response(headers={'WWW-Authenticate': 'Basic'}, status_code=401)
        return response


@app.get('/logout')
async def route_logout_and_remove_cookie():
    response = RedirectResponse(url='/')
    response.delete_cookie('Authorization', domain=COOKIE_DOMAIN_NAME)
    return response


# require auth for docs
@app.get('/openapi.json', include_in_schema=False, dependencies=[Depends(get_current_active_user)])
async def get_open_api_endpoint():
    return JSONResponse(get_openapi(title='JK API', version='0.1', routes=app.routes))


@app.get('/docs', include_in_schema=False, dependencies=[Depends(get_current_active_user)])
async def get_documentation():
    return get_swagger_ui_html(openapi_url='/openapi.json', title='docs')


app.include_router(testme.router)
app.include_router(user_info.router)

if __name__ == "__main__":
    run_uvicorn_loguru(
        uvicorn.Config(
            "main:app",
            host="0.0.0.0",
            port=API_PORT,
            log_level="debug",
            reload=False,
        )
    )
