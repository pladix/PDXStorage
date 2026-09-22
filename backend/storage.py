import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "data/master.key"

def get_master_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

MASTER_KEY = get_master_key()
aesgcm = AESGCM(MASTER_KEY)

CHUNKS_DIR = "data/chunks"
os.makedirs(CHUNKS_DIR, exist_ok=True)

def calculate_hash(data: bytes) -> str:
    
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def encrypt_chunk(data: bytes) -> bytes:
    
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_chunk(encrypted_data: bytes) -> bytes:
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def save_chunk(chunk_data: bytes) -> str:
    
    chunk_hash = calculate_hash(chunk_data)
    chunk_path = os.path.join(CHUNKS_DIR, chunk_hash)
    
    if os.path.exists(chunk_path):
        return chunk_hash
        
    encrypted_data = encrypt_chunk(chunk_data)
    with open(chunk_path, "wb") as f:
        f.write(encrypted_data)
        
    return chunk_hash

def read_chunk(chunk_hash: str) -> bytes:
    
    chunk_path = os.path.join(CHUNKS_DIR, chunk_hash)
    if not os.path.exists(chunk_path):
        raise FileNotFoundError(f"Chunk {chunk_hash} não encontrado no disco.")
        
    with open(chunk_path, "rb") as f:
        encrypted_data = f.read()
        
    return decrypt_chunk(encrypted_data)

def delete_physical_chunk(chunk_hash: str):
    
    chunk_path = os.path.join(CHUNKS_DIR, chunk_hash)
    if os.path.exists(chunk_path):
        try:
            os.remove(chunk_path)
        except OSError:
            pass