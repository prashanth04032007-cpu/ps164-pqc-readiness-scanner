from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib

key = RSA.generate(2048)

cipher = AES.new(b'0123456789abcdef0123456789012345')

digest = hashlib.sha256(b"hello").hexdigest()

old_digest = hashlib.sha1(b"legacy").hexdigest()
