import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import json
import time

import os

AUTH_KEY_FILE = "data/auth.key"

def get_auth_key():
    if os.path.exists(AUTH_KEY_FILE):
        with open(AUTH_KEY_FILE, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(AUTH_KEY_FILE, "wb") as f:
        f.write(key)
    return key

FERNET_KEY = get_auth_key()
fernet = Fernet(FERNET_KEY)

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def is_password_strong(password: str) -> bool:
    
    if len(password) < 8:
        return False
    has_digit = any(c.isdigit() for c in password)
    has_letter = any(c.isalpha() for c in password)
    return has_digit and has_letter

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire.timestamp()})
    
    json_data = json.dumps(to_encode).encode('utf-8')
    encrypted_token = fernet.encrypt(json_data)
    
    return encrypted_token.decode('utf-8')

def decode_access_token(token: str):
    try:
        decrypted_data = fernet.decrypt(token.encode('utf-8'))
        payload = json.loads(decrypted_data.decode('utf-8'))
        
        if payload.get("exp") < time.time():
            return None
            
        return payload
    except Exception:
        return None

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(totp_secret, username):
    return pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="PDXStorage")

def generate_qr_code_base64(uri):
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def verify_totp(totp_secret, code):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)