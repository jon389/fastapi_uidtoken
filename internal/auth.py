from typing import Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from secrets import token_bytes

import jwt
from jwt import PyJWTError

from pydantic import BaseModel

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2
from fastapi.security.base import SecurityBase, SecurityBaseModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from starlette.status import HTTP_403_FORBIDDEN
from starlette.requests import Request

from loguru import logger
from internal.testdb import db

JWT_ALGORITHM = 'HS256'
JWT_SECRET_KEY = bytes.hex(token_bytes(32))
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
COOKIE_DOMAIN_NAME = 'desk4.home'
API_PORT = 18078
DB_UID_TIMESTAMP_EXPIRES = timedelta(days=7)


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


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str) -> Optional[UserInDB]:
    try:
        for row in db.query("SELECT * FROM UserTokens "
                           f"WHERE UPPER([User]) LIKE '%{username.upper()}' "
                            "ORDER BY Timestamp DESC"):
            return UserInDB(**row)
    except:
        pass

    logger.info(f'get_user failed to find user {username=}')


def authenticate_user(username: str, uid: str, netaddr: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user:
        return None

    # extra check that UID & netaddr match, and timestamp isn't too old
    if not (user.UID == uid and user.NetAddress == netaddr and
            user.Timestamp + DB_UID_TIMESTAMP_EXPIRES > datetime.utcnow()):
        logger.debug(f'authenticate_user failed: {username=}, UID: {uid}, NetAddress: {netaddr}'
                     f', DB UID: {user.UID}, DB NetAddress: {user.NetAddress}, DB UID Timestamp: {user.Timestamp}')
        return None

    logger.debug(f'authenticate_user success: {username=}, UID: {uid}, NetAddress: {netaddr}'
                 f', DB UID: {user.UID}, DB NetAddress: {user.NetAddress}, DB UID Timestamp: {user.Timestamp}')
    return user


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    return jwt.encode(
        payload={**data,
                 'exp': datetime.utcnow() + (expires_delta
                                             if expires_delta is not None
                                             else timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))},
        key=JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=HTTP_403_FORBIDDEN,
                                          detail='Could not validate credentials')

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


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')
    return current_user
