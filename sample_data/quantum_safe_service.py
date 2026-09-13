import hashlib
from Crypto.Cipher import AES

def process_secure_payload(data: bytes, key_256bit: bytes):
    # Quantum-Safe Symmetric Cipher: AES-256 with Galois/Counter Mode (GCM)
    cipher = AES.new(key_256bit, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Quantum-Safe Hashing: SHA-256 / SHA-3
    data_hash = hashlib.sha3_256(data).hexdigest()
    
    return ciphertext, tag, cipher.nonce, data_hash