from fastapi import Depends, FastAPI
from fastapi.security import OAuth2AuthorizationCodeBearer
from fief_client import FiefAccessTokenInfo, FiefAsync
from fief_client.integrations.fastapi import FiefAuth

# https://docs.fief.dev/

fief = FiefAsync(
    "http://localhost:8081",
    "K4R0Zd1oSLVFN-uXp5Rx07T-drBAFr7lugbcGxIg3gs",
    "rKfRI-_hTZyjKpbNVkmHoNH1RhwYqwWhS4Nt58f3dkE",
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
