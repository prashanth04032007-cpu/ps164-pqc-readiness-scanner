import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import ecdsa

# 1. Critical Risk / P0: RSA-2048 Key Generation (Vulnerable to Shor's Algorithm)
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key

# 2. Critical Risk / P0: ECDSA Digital Signature (Vulnerable to Quantum Attack)
def sign_with_ecdsa(message: bytes):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    signature = sk.sign(message)
    return signature

# 3. High Risk / P1: Weak/Broken Hashing (MD5)
def insecure_md5(data: str):
    return hashlib.md5(data.encode()).hexdigest()

# 4. Medium Risk / P2: Legacy Hashing (SHA-1)
def legacy_sha1(data: str):
    return hashlib.sha1(data.encode()).hexdigest()

# 5. Low Risk / Quantum-Resistant: AES-256 Symmetric Encryption (Grover's speedup mitigated by key length)
def encrypt_aes_256(key: bytes, data: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

# 6. Quantum-Resistant Hashing: SHA-256
def secure_sha256(data: str):
    return hashlib.sha256(data.encode()).hexdigest()