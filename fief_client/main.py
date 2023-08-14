from fastapi import Depends, FastAPI
from fastapi.security import OAuth2AuthorizationCodeBearer
from fief_client import FiefAccessTokenInfo, FiefAsync
from fief_client.integrations.fastapi import FiefAuth

# https://docs.fief.dev/
# https://docs.fief.dev/integrate/python/fastapi/

fief = FiefAsync(
    "http://localhost:8000",
    "zWwRnbXZjpDi_azO19tI4EWCrpchtOuo__8yZGger74",
    "-dmHFrDOXJnGzEmpIHuchziPYei_7UWeCn8UOraNUqU",
)

scheme = OAuth2AuthorizationCodeBearer(
    "http://localhost:8000/authorize",
    "http://localhost:8000/api/token",
    scopes={"openid": "openid", "offline_access": "offline_access"},
    auto_error=False,
)

auth = FiefAuth(fief, scheme)

app = FastAPI()


@app.get("/user")
async def get_user(
    access_token_info: FiefAccessTokenInfo = Depends(
        auth.authenticated(permissions=["castles:read"])
    ),
):
    return access_token_info
