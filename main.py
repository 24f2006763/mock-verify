from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError

app = FastAPI()

# Your assigned IdP values
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-u8ex85k6.apps.exam.local"

# Request schema matching {"token": "<JWT string>"}
class VerifyRequest(BaseModel):
    token: str

@app.post("/verify")
def verify_token(payload: VerifyRequest):
    try:
        # PyJWT checks signature, exp, iss, and aud automatically
        claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        # Valid token response structure matching the grader requirements
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud")
        }
        
    except (InvalidTokenError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError):
        # On any validation error, return 401 Unauthorized with valid: false
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )