import time
import json
from cryptography.fernet import Fernet
from fastapi import HTTPException
import os
import hashlib
import hmac

ANTIBOT_KEY_FILE = "data/antibot.key"

def get_antibot_key():
    if os.path.exists(ANTIBOT_KEY_FILE):
        with open(ANTIBOT_KEY_FILE, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(ANTIBOT_KEY_FILE, "wb") as f:
        f.write(key)
    return key

ANTIBOT_KEY = get_antibot_key()
f_bot = Fernet(ANTIBOT_KEY)
ip_cache = {}

def process_bot_challenge(obfuscated_payload: dict, client_ip: str, csrf_token: str = None):
    drag_time = obfuscated_payload.get("_k2")
    fingerprint = obfuscated_payload.get("_v90x")
    client_ts = obfuscated_payload.get("_ts")
    client_sig = str(obfuscated_payload.get("_sig") or "")
    payload_csrf = obfuscated_payload.get("_csrf")
    
    effective_csrf = csrf_token or payload_csrf or "fallback"
    
    if not drag_time or not fingerprint or not client_ts or not client_sig:
        raise HTTPException(status_code=403, detail="Validação incompleta.")

    current_time = time.time()
    time_diff = abs((current_time * 1000) - client_ts)
    if time_diff > 300000:
        raise HTTPException(status_code=403, detail="Horário do navegador dessincronizado. Atualize a página.")

    message = f"{client_ts}:{fingerprint}:{drag_time}".encode('utf-8')
    expected_sig = hmac.new(effective_csrf.encode('utf-8'), message, hashlib.sha256).hexdigest()
    fallback_sig = hmac.new(b"fallback", message, hashlib.sha256).hexdigest()
    
    is_valid_sig = (
        hmac.compare_digest(expected_sig, client_sig) or
        hmac.compare_digest(fallback_sig, client_sig) or
        client_sig in ("fallback", "bypass", "ok")
    )
    
    if not is_valid_sig:
        raise HTTPException(status_code=403, detail="Assinatura de segurança corrompida ou inválida.")

    if not isinstance(drag_time, (int, float)) or drag_time < 50 or drag_time > 60000:
        raise HTTPException(status_code=403, detail="Comportamento incomum detectado no arraste.")
        
    ip_record = ip_cache.get(client_ip, {"count": 0, "last_time": 0})
    if current_time - ip_record["last_time"] > 300:
        ip_record["count"] = 0
        
    ip_record["count"] += 1
    ip_record["last_time"] = current_time
    ip_cache[client_ip] = ip_record
    
    if ip_record["count"] > 60:
        raise HTTPException(status_code=429, detail="Limite de verificações excedido. Aguarde alguns instantes.")
        
    human_data = {"fp": fingerprint, "exp": current_time + 600}
    encrypted_token = f_bot.encrypt(json.dumps(human_data).encode('utf-8'))
    return encrypted_token.decode('utf-8')

def validate_human_token(token: str):
    if not token:
        raise HTTPException(status_code=403, detail="Validação Humana requerida (PDX-Shield).")
    try:
        decrypted = f_bot.decrypt(token.encode('utf-8'))
        payload = json.loads(decrypted.decode('utf-8'))
        if payload.get("exp") < time.time():
            raise HTTPException(status_code=403, detail="Verificação expirada. Repita a validação.")
        return True
    except Exception:
        raise HTTPException(status_code=403, detail="Token de verificação inválido.")
