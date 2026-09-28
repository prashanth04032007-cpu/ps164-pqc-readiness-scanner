from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib

rsa_key = RSA.generate(2048)

aes_key = b"0123456789abcdef0123456789012345"
cipher = AES.new(aes_key)

sha256_value = hashlib.sha256(b"test").hexdigest()

sha1_value = hashlib.sha1(b"legacy").hexdigest()
