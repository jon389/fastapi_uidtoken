from typing import Optional
import base64
from passlib.context import CryptContext
from datetime import datetime, timedelta
from secrets import token_bytes

import jwt
from jwt import PyJWTError

from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm, OAuth2
from fastapi.security.base import SecurityBase, SecurityBaseModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from fastapi.logger import logger

from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse
from starlette.requests import Request

from testdb import db

JWT_ALGORITHM = 'HS256'
JWT_SECRET_KEY = bytes.hex(token_bytes(32))
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
COOKIE_DOMAIN_NAME = 'desk4.home'


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str = None


class User(BaseModel):
    User: str
    UID: str = None
    Timestamp: datetime = None
    full_name: str = None
    email: str = None
    label: str = None


class UserInDB(User):
    # hashed_password: str
    disabled: bool = False
    Machine: str = None
    NetAddress: str = None


class OAuth2PasswordBearerCookie(OAuth2):
    def __init__(
            self,
            tokenUrl: str,
            scheme_name: str = None,
            scopes: dict = None,
            auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={'tokenUrl': tokenUrl, 'scopes': scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        header_scheme, header_param = get_authorization_scheme_param(request.headers.get('Authorization'))
        cookie_scheme, cookie_param = get_authorization_scheme_param(request.cookies.get('Authorization'))

        if header_scheme.lower() == 'bearer':
            authorization = True
            scheme = header_scheme
            param = header_param

        elif cookie_scheme.lower() == 'bearer':
            authorization = True
            scheme = cookie_scheme
            param = cookie_param

        else:
            authorization = False

        if not authorization or scheme.lower() != 'bearer':
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail='Not authenticated'
                )
            else:
                return None
        return param


class BasicAuth(SecurityBase):
    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.model = SecurityBaseModel(type='http')
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get('Authorization')
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != 'basic':
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail='Not authenticated'
                )
            else:
                return None
        return param


basic_auth = BasicAuth(auto_error=False)

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl='/token')

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str) -> Optional[UserInDB]:
    for row in db.query("SELECT * FROM UserTokens "
                       f"WHERE UPPER([User]) LIKE '%{username.upper()}' "
                        "ORDER BY Timestamp DESC"):
        return UserInDB(**row)

    logger.info(f'get_user failed: username: {username}')


def authenticate_user(username: str, uid: str, netaddr: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user:
        return None
    if not (user.UID == uid and user.NetAddress == netaddr and
            user.Timestamp + timedelta(days=7) > datetime.utcnow()):
        logger.info(f'authenticate_user failed: username: {username}, UID: {uid}, NetAddress: {netaddr}'
                    f', DB UID: {user.UID}, DB NetAddress: {user.NetAddress}, DB UID Timestamp: {user.Timestamp}')
        return None
    return user


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    return jwt.encode(
        {**data, 'exp': datetime.utcnow() + (expires_delta if expires_delta is not None
                                             else timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))},
        JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail='Could not validate credentials')
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])  # will raise error if token expired
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')
    return current_user


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


@app.get('/logout')
async def route_logout_and_remove_cookie():
    response = RedirectResponse(url='/')
    response.delete_cookie('Authorization', domain=COOKIE_DOMAIN_NAME)
    return response


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
            raise HTTPException(status_code=400, detail='Incorrect email or password')

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
        return response

    except:
        response = Response(headers={'WWW-Authenticate': 'Basic'}, status_code=401)
        return response


@app.get('/openapi.json', include_in_schema=False)
async def get_open_api_endpoint(current_user: User = Depends(get_current_active_user)):
    return JSONResponse(get_openapi(title='JK API', version='0.1', routes=app.routes))


@app.get('/docs', include_in_schema=False)
async def get_documentation(current_user: User = Depends(get_current_active_user)):
    return get_swagger_ui_html(openapi_url='/openapi.json', title='docs')


@app.get('/me', response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# @app.get('/users/me/items/')
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{'item_id': 'Foo', 'owner': current_user.username}]


@app.get('/test')
async def testme(current_user: User = Depends(get_current_active_user)):
    return {'this': 100}


import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=18078)