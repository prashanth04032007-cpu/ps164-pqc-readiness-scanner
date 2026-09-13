import hashlib
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

def process_transaction(payload):
    # Vulnerable 3DES encryption
    cipher = DES3.new(b'1234567890123456', DES3.MODE_ECB)
    
    # Vulnerable RSA key size
    key = RSA.generate(1024)
    
    # Vulnerable hash function
    hash_val = hashlib.md5(payload.encode()).hexdigest()
    
    return cipher, key, hash_val