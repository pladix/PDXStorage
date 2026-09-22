import os
import json
import time
import re
import datetime
import shutil
import urllib.parse
import zipfile
import tempfile
from starlette.background import BackgroundTask
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Response, Cookie, Header, Request, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import secrets

import hmac
import hashlib

API_HMAC_SECRET = "pdx_sec_shield_2026_x89a"
pdx_seen_nonces = {}
revoked_tokens = set()

USER_QUOTA_BYTES = 20 * 1024 * 1024 * 1024
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from backend.database import get_db, User, File, Chunk, FileChunkMapping, delete_file_and_cleanup_chunks
from backend.auth import (
    get_password_hash, verify_password, create_access_token, decode_access_token,
    generate_totp_secret, get_totp_uri, generate_qr_code_base64, verify_totp,
    is_password_strong
)
from backend.antibot import process_bot_challenge, validate_human_token
from backend.storage import save_chunk, read_chunk
from pydantic import BaseModel

app = FastAPI(
    title="PDXStorage",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    if is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    elif request.url.hostname in ["localhost", "127.0.0.1"]:
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "connect-src 'self' ws: wss: https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "frame-ancestors 'none';"
    )
    return response

@app.middleware("http")
async def verify_pdx_signature_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
        
    path = request.url.path
    needs_sign = False
    
    if path in ["/token", "/token/2fa", "/register"]:
        needs_sign = True
    elif path.startswith("/api/") and path not in ["/api/csrf-token", "/api/core/_hx99_auth"]:
        if not (request.method == "GET" and (path.endswith("/download") or path == "/api/files/download-zip")):
            needs_sign = True
    elif path.startswith("/2fa/"):
        needs_sign = True
        
    if needs_sign:
        ts_str = request.headers.get("X-PDX-Timestamp")
        nonce = request.headers.get("X-PDX-Nonce")
        sig = request.headers.get("X-PDX-Sign")
        
        if not ts_str or not nonce or not sig:
            return Response(
                content=json.dumps({"detail": "Assinatura de segurança ausente ou inválida."}),
                status_code=403,
                media_type="application/json"
            )
            
        try:
            ts = int(ts_str)
        except ValueError:
            return Response(
                content=json.dumps({"detail": "Carimbo temporal de segurança inválido."}),
                status_code=403,
                media_type="application/json"
            )
            
        now_ms = int(time.time() * 1000)
        if abs(now_ms - ts) > 60000:
            return Response(
                content=json.dumps({"detail": "Assinatura de segurança expirada."}),
                status_code=403,
                media_type="application/json"
            )
            
        now = time.time()
        if nonce in pdx_seen_nonces:
            return Response(
                content=json.dumps({"detail": "Tentativa de repetição de requisição rejeitada (Nonce já utilizado)."}),
                status_code=403,
                media_type="application/json"
            )
            
        pdx_seen_nonces[nonce] = now
        if len(pdx_seen_nonces) > 5000:
            cutoff = now - 120
            for k in list(pdx_seen_nonces.keys()):
                if pdx_seen_nonces[k] < cutoff:
                    del pdx_seen_nonces[k]
                    
        message = f"{path}:{ts_str}:{nonce}"
        expected = hmac.new(API_HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return Response(
                content=json.dumps({"detail": "Assinatura criptográfica de integridade inválida."}),
                status_code=403,
                media_type="application/json"
            )
            
    return await call_next(request)

def is_valid_ws_origin(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin and host:
        parsed = urllib.parse.urlparse(origin)
        if parsed.netloc and parsed.netloc.lower() != host.lower():
            return False
    return True

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    return Response(
        content=json.dumps({"detail": "Recurso não encontrado."}),
        status_code=404,
        media_type="application/json"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserCreate(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class RetentionRequest(BaseModel):
    retention_days: int

class CyclicStorageRequest(BaseModel):
    cyclic_storage: bool

class DeleteAccountRequest(BaseModel):
    password: str

login_attempts = {}

def check_login_rate_limit(client_ip: str, username: str):
    key = f"{client_ip}:{username}"
    now = time.time()
    record = login_attempts.get(key)
    if record:
        if now < record.get("locked_until", 0):
            wait_time = int(record["locked_until"] - now)
            raise HTTPException(
                status_code=429,
                detail=f"Muitas tentativas consecutivas incorretas. Bloqueado temporariamente por {wait_time}s."
            )
        if now - record.get("last_attempt", 0) > 300:
            login_attempts.pop(key, None)

def record_login_failure(client_ip: str, username: str):
    key = f"{client_ip}:{username}"
    now = time.time()
    record = login_attempts.get(key, {"failures": 0, "last_attempt": now, "locked_until": 0})
    record["failures"] += 1
    record["last_attempt"] = now
    if record["failures"] >= 5:
        record["locked_until"] = now + 300
    login_attempts[key] = record

def clear_login_failures(client_ip: str, username: str):
    key = f"{client_ip}:{username}"
    login_attempts.pop(key, None)

refresh_rate_limits = {}

def check_refresh_rate_limit(client_ip: str, username: str, current_token: str):
    key = f"{client_ip}:{username}"
    now = time.time()
    record = refresh_rate_limits.get(key, {"count": 0, "window_start": now, "last_refresh": 0, "last_token": current_token})

    if now - record["window_start"] > 600:
        record["count"] = 0
        record["window_start"] = now

    record["count"] += 1
    
    if record["count"] > 30:
        raise HTTPException(
            status_code=429,
            detail="Muitas solicitações de renovação de sessão detectadas. Aguarde antes de tentar novamente."
        )

    if now - record.get("last_refresh", 0) < 60 and record.get("last_token"):
        refresh_rate_limits[key] = record
        return record["last_token"]

    record["last_refresh"] = now
    refresh_rate_limits[key] = record
    return None

def check_and_clean_retention(user: User, db: Session):
    
    if user.retention_days and user.retention_days > 0:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=user.retention_days)
        expired_files = db.query(File).filter(File.user_id == user.id, File.created_at < cutoff).all()
        for f in expired_files:
            delete_file_and_cleanup_chunks(db, f)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if token in revoked_tokens:
        raise HTTPException(status_code=401, detail="Sessão revogada ou finalizada. Faça login novamente.")
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessão expirada ou token inválido")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Esta conta foi suspensa pelo administrador.")
    return user

def verify_csrf_token(x_csrf_token: str = Header(None, alias="X-CSRF-Token"), csrf_token: str = Cookie(None)):
    if not x_csrf_token or not csrf_token or x_csrf_token != csrf_token:
        raise HTTPException(status_code=403, detail="Acesso Violado: Falsificação CSRF detectada (Missing or Invalid Token)")
    return True

@app.get("/api/csrf-token")
def get_csrf_token(response: Response):
    token = secrets.token_urlsafe(32)
    response.set_cookie(key="csrf_token", value=token, httponly=True, samesite="strict", max_age=3600)
    return {"csrf_token": token}

@app.post("/api/core/_hx99_auth")
def verify_human(payload: dict, request: Request):
    client_ip = request.client.host
    csrf_token = request.cookies.get("csrf_token") or payload.get("_csrf")
    token = process_bot_challenge(payload, client_ip, csrf_token)
    return {"_htk": token}

def require_human(x_human_token: str = Header(None, alias="X-Human-Token")):
    return validate_human_token(x_human_token)

@app.post("/register")
def register(user_data: UserCreate, db: Session = Depends(get_db), csrf_valid: bool = Depends(verify_csrf_token), human_valid: bool = Depends(require_human)):
    username = user_data.username.strip()
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=400, detail="O nome de usuário deve ter entre 3 e 32 caracteres.")
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        raise HTTPException(status_code=400, detail="O nome de usuário contém caracteres inválidos.")
    if not is_password_strong(user_data.password):
        raise HTTPException(status_code=400, detail="A senha deve conter no mínimo 8 caracteres, com letras e números.")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Este nome de usuário já está em uso.")
    
    new_user = User(
        username=username,
        password_hash=get_password_hash(user_data.password)
    )
    db.add(new_user)
    db.commit()
    token = create_access_token(data={"sub": new_user.username})
    return {"message": "Usuário criado com sucesso!", "access_token": token}

@app.post("/api/refresh-token")
def refresh_session_token(
    request: Request,
    user: User = Depends(get_current_user),
    raw_token: str = Depends(oauth2_scheme)
):
    client_ip = request.client.host
    cached_token = check_refresh_rate_limit(client_ip, user.username, raw_token)
    if cached_token:
        return {
            "access_token": cached_token,
            "token_type": "bearer",
            "message": "Sessão já ativa e recente."
        }
    new_token = create_access_token(data={"sub": user.username})
    key = f"{client_ip}:{user.username}"
    if key in refresh_rate_limits:
        refresh_rate_limits[key]["last_token"] = new_token
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "message": "Sessão renovada com sucesso!"
    }

@app.post("/api/logout")
def logout_user(raw_token: str = Depends(oauth2_scheme)):
    revoked_tokens.add(raw_token)
    return {"message": "Sessão encerrada com sucesso."}

class VerifyLogin2FA(BaseModel):
    challenge_token: str
    code: str

@app.post("/token")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), csrf_valid: bool = Depends(verify_csrf_token), human_valid: bool = Depends(require_human)):
    client_ip = request.client.host
    username = form_data.username.strip()

    check_login_rate_limit(client_ip, username)

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        record_login_failure(client_ip, username)
        raise HTTPException(status_code=401, detail="Credenciais de acesso incorretas.")
    
    clear_login_failures(client_ip, username)

    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Esta conta foi suspensa pelo administrador.")

    if user.totp_secret:
        challenge_token = create_access_token(
            data={"sub": user.username, "purpose": "2fa_challenge"},
            expires_delta=datetime.timedelta(minutes=5)
        )
        return {
            "require_2fa": True,
            "challenge_token": challenge_token,
            "message": "Autenticação em 2 etapas requerida para este usuário."
        }

    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "require_2fa": False}

@app.post("/token/2fa")
def login_2fa(request: Request, data: VerifyLogin2FA, db: Session = Depends(get_db)):
    client_ip = request.client.host
    payload = decode_access_token(data.challenge_token)
    if not payload or payload.get("purpose") != "2fa_challenge":
        raise HTTPException(status_code=401, detail="Sessão de verificação 2FA expirada. Faça login novamente.")
    
    username = payload.get("sub")
    check_login_rate_limit(client_ip, f"2fa_{username}")
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=401, detail="Usuário inválido ou 2FA não configurado.")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Esta conta foi suspensa pelo administrador.")
        
    if not verify_totp(user.totp_secret, data.code.strip()):
        record_login_failure(client_ip, f"2fa_{username}")
        raise HTTPException(status_code=401, detail="Código 2FA incorreto ou expirado.")
        
    clear_login_failures(client_ip, f"2fa_{username}")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "require_2fa": False}

@app.get("/2fa/setup")
def setup_2fa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.totp_secret:
        return {"message": "2FA já configurado"}
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.username)
    qr_base64 = generate_qr_code_base64(uri)
    return {"secret": secret, "qr_code": qr_base64}

class Verify2FA(BaseModel):
    secret: str
    code: str

@app.post("/2fa/verify")
def verify_and_enable_2fa(data: Verify2FA, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if verify_totp(data.secret, data.code):
        user.totp_secret = data.secret
        db.commit()
        return {"message": "2FA ativado com sucesso!"}
    raise HTTPException(status_code=400, detail="Código 2FA inválido")

@app.get("/api/user/profile")
def get_user_profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    check_and_clean_retention(user, db)
    files = db.query(File).filter(File.user_id == user.id).all()
    total_bytes = sum(f.total_size for f in files) if files else 0
    return {
        "username": user.username,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "has_2fa": bool(user.totp_secret),
        "retention_days": user.retention_days or 0,
        "cyclic_storage": bool(user.cyclic_storage),
        "total_files": len(files),
        "total_storage_bytes": total_bytes,
        "quota_bytes": user.custom_quota_bytes if (user.custom_quota_bytes and user.custom_quota_bytes > 0) else USER_QUOTA_BYTES
    }

@app.get("/api/user/storage-quota")
def get_storage_quota(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    check_and_clean_retention(user, db)
    files = db.query(File).filter(File.user_id == user.id).all()
    user_used = sum(f.total_size for f in files) if files else 0
    total_disk, used_disk, free_disk = shutil.disk_usage("data")
    quota_bytes = user.custom_quota_bytes if (user.custom_quota_bytes and user.custom_quota_bytes > 0) else USER_QUOTA_BYTES
    used_percent = min(100.0, round((user_used / quota_bytes) * 100, 2))
    return {
        "quota_bytes": quota_bytes,
        "used_bytes": user_used,
        "free_bytes": max(0, quota_bytes - user_used),
        "used_percent": used_percent,
        "server_free_bytes": free_disk,
        "cyclic_storage": bool(user.cyclic_storage)
    }

@app.post("/api/user/cyclic-storage")
def set_cyclic_storage(data: CyclicStorageRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.cyclic_storage = data.cyclic_storage
    db.commit()
    msg = "Armazenamento Cíclico ativado! Arquivos antigos serão reciclados automaticamente ao atingir 20GB." if data.cyclic_storage else "Armazenamento Cíclico desativado."
    return {"message": msg, "cyclic_storage": user.cyclic_storage}

@app.post("/api/user/change-password")
def change_password(data: ChangePasswordRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Senha atual incorreta.")
    if not is_password_strong(data.new_password):
        raise HTTPException(status_code=400, detail="A nova senha deve ter no mínimo 8 caracteres com letras e números.")
    user.password_hash = get_password_hash(data.new_password)
    db.commit()
    return {"message": "Senha alterada com sucesso!"}

@app.post("/api/user/retention")
def set_retention_policy(data: RetentionRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.retention_days < 0 or data.retention_days > 365:
        raise HTTPException(status_code=400, detail="Período de retenção inválido.")
    user.retention_days = data.retention_days
    db.commit()
    check_and_clean_retention(user, db)
    return {"message": "Política de auto-limpeza atualizada com sucesso!", "retention_days": user.retention_days}

@app.delete("/api/user/files/wipe")
def wipe_all_user_files(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    files = db.query(File).filter(File.user_id == user.id).all()
    count = len(files)
    for f in files:
        delete_file_and_cleanup_chunks(db, f)
    return {"message": f"{count} arquivo(s) excluído(s) com sucesso!"}

@app.delete("/api/user/delete-account")
def delete_account(data: DeleteAccountRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Senha de confirmação incorreta.")
    files = db.query(File).filter(File.user_id == user.id).all()
    for f in files:
        delete_file_and_cleanup_chunks(db, f)
    db.delete(user)
    db.commit()
    return {"message": "Conta e todos os dados associados foram excluídos com sucesso!"}

@app.delete("/api/files/{file_id}")
def delete_file(file_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_file = db.query(File).filter(File.id == file_id, File.user_id == user.id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    delete_file_and_cleanup_chunks(db, db_file)
    return {"message": "Arquivo excluído com sucesso!"}

@app.get("/api/files")
def get_files(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    check_and_clean_retention(user, db)
    files = db.query(File).filter(File.user_id == user.id).order_by(File.created_at.desc()).all()
    return [{"id": f.id, "filename": f.filename, "size": f.total_size, "created_at": f.created_at.isoformat() if f.created_at else None} for f in files]

@app.get("/api/files/{file_id}/download")
def download_file_stream(
    file_id: int,
    token: str = Query(None),
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    raw_token = token
    if not raw_token and authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ")[1]
        
    if not raw_token:
        raise HTTPException(status_code=401, detail="Token de autorização não informado.")
    if raw_token in revoked_tokens:
        raise HTTPException(status_code=401, detail="Sessão revogada.")
    payload = decode_access_token(raw_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessão expirada ou inválida.")
        
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado.")
        
    db_file = db.query(File).filter(File.id == file_id, File.user_id == user.id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
        
    mappings = sorted(db_file.chunks, key=lambda m: m.sequence_order)
    
    def iter_file():
        for m in mappings:
            yield read_chunk(m.chunk.chunk_hash)
            
    quoted_filename = urllib.parse.quote(db_file.filename)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_filename}; filename=\"{db_file.filename}\"",
        "Content-Length": str(db_file.total_size)
    }
    return StreamingResponse(iter_file(), media_type="application/octet-stream", headers=headers)

class BatchDeleteRequest(BaseModel):
    file_ids: list[int]

@app.post("/api/files/batch-delete")
def batch_delete_files(
    payload: BatchDeleteRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not payload.file_ids:
        raise HTTPException(status_code=400, detail="Nenhum arquivo selecionado.")
    files = db.query(File).filter(File.id.in_(payload.file_ids), File.user_id == user.id).all()
    count = 0
    for db_file in files:
        delete_file_and_cleanup_chunks(db, db_file)
        count += 1
    return {"message": f"{count} arquivo(s) excluído(s) com sucesso!", "deleted_count": count}

@app.get("/api/files/download-zip")
def download_files_zip(
    ids: str = Query(None),
    token: str = Query(None),
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    raw_token = token
    if not raw_token and authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ")[1]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Token de autorização não informado.")
    if raw_token in revoked_tokens:
        raise HTTPException(status_code=401, detail="Sessão revogada.")
    payload = decode_access_token(raw_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessão expirada ou inválida.")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado.")

    query = db.query(File).filter(File.user_id == user.id)
    if ids:
        try:
            target_ids = [int(x.strip()) for x in ids.split(",") if x.strip().isdigit()]
            if target_ids:
                query = query.filter(File.id.in_(target_ids))
            else:
                raise HTTPException(status_code=400, detail="Lista de identificadores vazia ou inválida.")
        except Exception:
            raise HTTPException(status_code=400, detail="Formato de identificadores inválido.")
    
    files = query.order_by(File.created_at.desc()).all()
    if not files:
        raise HTTPException(status_code=404, detail="Nenhum arquivo correspondente encontrado para compactação.")

    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    temp_zip_path = temp_zip.name
    temp_zip.close()

    try:
        used_names = {}
        with zipfile.ZipFile(temp_zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for db_file in files:
                fname = db_file.filename
                if fname in used_names:
                    used_names[fname] += 1
                    name_part, ext_part = os.path.splitext(fname)
                    arc_name = f"{name_part} ({used_names[fname]}){ext_part}"
                else:
                    used_names[fname] = 0
                    arc_name = fname

                mappings = sorted(db_file.chunks, key=lambda m: m.sequence_order)
                with zf.open(arc_name, mode="w") as dest:
                    for m in mappings:
                        chunk_bytes = read_chunk(m.chunk.chunk_hash)
                        dest.write(chunk_bytes)
    except Exception as e:
        if os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass
        raise HTTPException(status_code=500, detail="Falha ao processar arquivos para compactação.")

    zip_filename = f"pdx_backup_{int(time.time())}.zip" if not ids else f"pdx_selecionados_{int(time.time())}.zip"
    quoted_name = urllib.parse.quote(zip_filename)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_name}; filename=\"{zip_filename}\""
    }
    return FileResponse(
        path=temp_zip_path,
        media_type="application/zip",
        headers=headers,
        background=BackgroundTask(os.remove, temp_zip_path)
    )

MAX_FILE_SIZE = 250 * 1024 * 1024

@app.websocket("/ws/upload")
async def websocket_upload(websocket: WebSocket, db: Session = Depends(get_db)):
    if not is_valid_ws_origin(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    try:
        auth_msg = await websocket.receive_json()
        token = auth_msg.get("token")
        payload = decode_access_token(token)
        if not payload:
            await websocket.send_json({"error": "Autenticação falhou"})
            await websocket.close()
            return
            
        user = db.query(User).filter(User.username == payload.get("sub")).first()
        if not user:
            await websocket.send_json({"error": "Usuário não encontrado"})
            await websocket.close()
            return
        if user.is_blocked:
            await websocket.send_json({"error": "Sua conta foi suspensa pelo administrador."})
            await websocket.close()
            return
        
        meta_msg = await websocket.receive_json()
        raw_filename = meta_msg.get("filename", "unnamed_file")
        total_size = meta_msg.get("total_size", 0)
        total_chunks = meta_msg.get("total_chunks", 0)

        base_name = os.path.basename(raw_filename)
        safe_filename = re.sub(r'[^\w\.\-\_ ]', '_', base_name).strip()
        if not safe_filename:
            safe_filename = f"file_{int(time.time())}"

        if total_size > MAX_FILE_SIZE:
            await websocket.send_json({"error": "O arquivo excede o limite máximo permitido de 250MB."})
            await websocket.close()
            return

        if total_chunks <= 0 or total_chunks > 1000:
            await websocket.send_json({"error": "Estrutura de fragmentação inválida."})
            await websocket.close()
            return
        
        user_files = db.query(File).filter(File.user_id == user.id).all()
        current_used = sum(f.total_size for f in user_files) if user_files else 0

        user_quota = user.custom_quota_bytes if (user.custom_quota_bytes and user.custom_quota_bytes > 0) else USER_QUOTA_BYTES
        if current_used + total_size > user_quota:
            if user.cyclic_storage:
                oldest_files = db.query(File).filter(File.user_id == user.id).order_by(File.created_at.asc()).all()
                for old_f in oldest_files:
                    if current_used + total_size <= user_quota:
                        break
                    current_used -= old_f.total_size
                    delete_file_and_cleanup_chunks(db, old_f)
            else:
                quota_gb_str = f"{user_quota / (1024**3):.0f}GB"
                await websocket.send_json({
                    "error": f"Limite de {quota_gb_str} atingido. Ative o Armazenamento Cíclico no seu perfil ou libere espaço manualmente."
                })
                await websocket.close()
                return

        db_file = File(user_id=user.id, filename=safe_filename, total_size=total_size)
        db.add(db_file)
        db.commit()
        db.refresh(db_file)
        
        for i in range(total_chunks):
            chunk_data = await websocket.receive_bytes()
            chunk_hash = save_chunk(chunk_data)
            
            db_chunk = db.query(Chunk).filter(Chunk.chunk_hash == chunk_hash).first()
            if not db_chunk:
                db_chunk = Chunk(chunk_hash=chunk_hash, size=len(chunk_data))
                db.add(db_chunk)
                db.commit()
                db.refresh(db_chunk)
                
            mapping = FileChunkMapping(file_id=db_file.id, chunk_id=db_chunk.id, sequence_order=i)
            db.add(mapping)
            db.commit()
            
            await websocket.send_json({"progress": (i + 1) / total_chunks})
            
        await websocket.send_json({"status": "completed"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print("Erro WS:", e)
        await websocket.send_json({"error": "Falha no upload"})

@app.websocket("/ws/download")
async def websocket_download(websocket: WebSocket, db: Session = Depends(get_db)):
    if not is_valid_ws_origin(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    try:
        auth_msg = await websocket.receive_json()
        token = auth_msg.get("token")
        file_id = auth_msg.get("file_id")
        
        payload = decode_access_token(token)
        if not payload:
            await websocket.send_json({"error": "Autenticação falhou"})
            await websocket.close()
            return
            
        user = db.query(User).filter(User.username == payload.get("sub")).first()
        if not user:
            await websocket.send_json({"error": "Usuário não encontrado"})
            await websocket.close()
            return
        
        db_file = db.query(File).filter(File.id == file_id, File.user_id == user.id).first()
        if not db_file:
            await websocket.send_json({"error": "Arquivo não encontrado"})
            await websocket.close()
            return
            
        await websocket.send_json({"filename": db_file.filename, "total_size": db_file.total_size})
        
        for mapping in db_file.chunks:
            chunk_data = read_chunk(mapping.chunk.chunk_hash)
            await websocket.send_bytes(chunk_data)
            
        await websocket.close()
    except WebSocketDisconnect:
        pass

ADMIN_SECRET_PASSWORD = "pladixisback2026@"
admin_failed_attempts = {}

class AdminLoginRequest(BaseModel):
    password: str

class AdminQuotaRequest(BaseModel):
    quota_gb: float

def require_admin(token: str = Depends(oauth2_scheme)):
    if token in revoked_tokens:
        raise HTTPException(status_code=401, detail="Sessão administrativa revogada.")
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso administrativo restrito.")
    return True

@app.post("/api/admin/login")
def admin_login(request: Request, data: AdminLoginRequest):
    client_ip = request.client.host
    now = time.time()
    if client_ip in admin_failed_attempts:
        attempts, last_time = admin_failed_attempts[client_ip]
        if attempts >= 5 and now - last_time < 300:
            wait_sec = int(300 - (now - last_time))
            raise HTTPException(status_code=429, detail=f"Muitas tentativas incorretas. Aguarde {wait_sec} segundos.")
        elif now - last_time >= 300:
            admin_failed_attempts.pop(client_ip, None)

    if data.password != ADMIN_SECRET_PASSWORD:
        attempts, _ = admin_failed_attempts.get(client_ip, (0, now))
        admin_failed_attempts[client_ip] = (attempts + 1, now)
        raise HTTPException(status_code=401, detail="Senha administrativa incorreta.")

    admin_failed_attempts.pop(client_ip, None)
    token = create_access_token(data={"sub": "admin", "role": "admin"}, expires_delta=datetime.timedelta(hours=8))
    return {"access_token": token, "token_type": "bearer", "message": "Acesso administrativo concedido."}

@app.get("/api/admin/stats")
def get_admin_stats(admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    blocked_users = db.query(User).filter(User.is_blocked == True).count()
    active_users = total_users - blocked_users
    total_files = db.query(File).count()
    
    all_files = db.query(File.total_size).all()
    total_used_bytes = sum(f[0] for f in all_files) if all_files else 0
    
    total_chunks = db.query(Chunk.size).all()
    total_chunk_bytes = sum(c[0] for c in total_chunks) if total_chunks else 0
    
    total_disk, used_disk, free_disk = shutil.disk_usage("data")
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "blocked_users": blocked_users,
        "total_files": total_files,
        "total_used_bytes": total_used_bytes,
        "total_chunk_bytes": total_chunk_bytes,
        "server_free_bytes": free_disk,
        "server_total_bytes": total_disk
    }

@app.get("/api/admin/users")
def get_admin_users(admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id.desc()).all()
    result = []
    for u in users:
        u_files = db.query(File).filter(File.user_id == u.id).all()
        used = sum(f.total_size for f in u_files) if u_files else 0
        quota = u.custom_quota_bytes if (u.custom_quota_bytes and u.custom_quota_bytes > 0) else USER_QUOTA_BYTES
        result.append({
            "id": u.id,
            "username": u.username,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "is_blocked": bool(u.is_blocked),
            "quota_bytes": quota,
            "used_bytes": used,
            "files_count": len(u_files),
            "retention_days": u.retention_days,
            "cyclic_storage": bool(u.cyclic_storage)
        })
    return result

@app.post("/api/admin/users/{user_id}/toggle-block")
def admin_toggle_block(user_id: int, admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_blocked = not bool(user.is_blocked)
    db.commit()
    status_text = "bloqueado" if user.is_blocked else "desbloqueado"
    return {"message": f"Usuário {user.username} {status_text} com sucesso!", "is_blocked": user.is_blocked}

@app.post("/api/admin/users/{user_id}/quota")
def admin_set_quota(user_id: int, data: AdminQuotaRequest, admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    if data.quota_gb <= 0 or data.quota_gb > 10000:
        raise HTTPException(status_code=400, detail="Cota deve ser maior que 0 e até 10.000 GB.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.custom_quota_bytes = int(data.quota_gb * 1024 * 1024 * 1024)
    db.commit()
    return {"message": f"Cota de {user.username} atualizada para {data.quota_gb:.1f} GB!", "custom_quota_bytes": user.custom_quota_bytes}

@app.get("/api/admin/users/{user_id}/files")
def admin_get_user_files(user_id: int, admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    files = db.query(File).filter(File.user_id == user_id).order_by(File.created_at.desc()).all()
    return [{
        "id": f.id,
        "filename": f.filename,
        "size": f.total_size,
        "created_at": f.created_at.isoformat() if f.created_at else None
    } for f in files]

@app.delete("/api/admin/files/{file_id}")
def admin_delete_file(file_id: int, admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    filename = file.filename
    delete_file_and_cleanup_chunks(db, file)
    return {"message": f"Arquivo '{filename}' excluído com sucesso pelo administrador!"}

@app.get("/api/admin/files/{file_id}/download")
def admin_download_file(
    file_id: int,
    token: str = Query(None),
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    raw_token = token
    if not raw_token and authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ")[1]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Token não fornecido.")
    if raw_token in revoked_tokens:
        raise HTTPException(status_code=401, detail="Sessão administrativa revogada.")
    payload = decode_access_token(raw_token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso administrativo restrito.")
    
    db_file = db.query(File).filter(File.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    
    mappings = sorted(db_file.chunks, key=lambda m: m.sequence_order)
    def iter_file():
        for m in mappings:
            yield read_chunk(m.chunk.chunk_hash)
    
    quoted_filename = urllib.parse.quote(db_file.filename)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_filename}; filename=\"{db_file.filename}\"",
        "Content-Length": str(db_file.total_size)
    }
    return StreamingResponse(iter_file(), media_type="application/octet-stream", headers=headers)

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, admin_valid: bool = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    username = user.username
    files = db.query(File).filter(File.user_id == user_id).all()
    for f in files:
        delete_file_and_cleanup_chunks(db, f)
    db.delete(user)
    db.commit()
    return {"message": f"Usuário '{username}' e todos os seus arquivos foram excluídos com sucesso!"}

@app.get("/admin", include_in_schema=False)
def serve_admin():
    return FileResponse("frontend/admin.html")

@app.get("/admin.html", include_in_schema=False)
def redirect_admin_html():
    return RedirectResponse(url="/admin")

@app.get("/login", include_in_schema=False)
def serve_login():
    return FileResponse("frontend/login.html")

@app.get("/login.html", include_in_schema=False)
def redirect_login_html():
    return RedirectResponse(url="/login")

@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    return FileResponse("frontend/index.html")

@app.get("/index.html", include_in_schema=False)
def redirect_index_html():
    return RedirectResponse(url="/dashboard")

@app.get("/", include_in_schema=False)
def serve_root():
    return RedirectResponse(url="/dashboard")

app.mount("/", StaticFiles(directory="frontend"), name="frontend")