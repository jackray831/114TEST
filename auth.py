from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# 假資料
fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7 # 新增：Refresh Token 有效期 (通常較長，例如 7 天)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    # 加入 type 欄位以區分 token 種類
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 新增：建立 Refresh Token 的函式
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    # 加入 type 欄位，標記這是 refresh token
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # 1. 產生 Access Token
    access_token = create_access_token(
        data={"sub": user["username"]}
    )
    
    # 2. 產生 Refresh Token (新增)
    refresh_token = create_refresh_token(
        data={"sub": user["username"]}
    )

    # 設定 Access Token Cookie
    response.set_cookie(
        key="jwt",
        value=access_token,
        httponly=True,
        samesite="lax"
    )
    
    # 設定 Refresh Token Cookie (新增)
    # 這裡將 refresh token 也存入 cookie，路徑可以設為 /refresh 以增加安全性，這裡簡化處理
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,  # 防止 JavaScript 讀取，防止 XSS 攻擊
        samesite="lax"
    )

    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }

@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    token_to_verify = token if token else jwt_cookie
    
    if not token_to_verify:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    # 驗證 Access Token
    try:
        payload = jwt.decode(token_to_verify, SECRET_KEY, algorithms=[ALGORITHM])
        # 檢查這是否真的是 access token (避免使用者拿 refresh token 來存取 API)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {"message": f"Hello, {username}! You are authenticated."}

# 新增：Refresh Token 功能端點
@app.post("/refresh")
def refresh(response: Response, refresh_token: Optional[str] = Cookie(None)):
    """
    使用 Refresh Token 換取新的 Access Token
    """
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        # 解碼驗證 Refresh Token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # 檢查這是否真的是 refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
            
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        # 驗證通過，發發新的 Access Token
        new_access_token = create_access_token(data={"sub": username})
        
        # 更新 Cookie 中的 Access Token
        response.set_cookie(
            key="jwt",
            value=new_access_token,
            httponly=True,
            samesite="lax"
        )
        
        return {"access_token": new_access_token, "token_type": "bearer"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")