"""
source_scanner.py
Scans source files across Java, Python, C/C++, Go, and JS for cryptographic APIs. (PS-164)
"""
import re

PATTERNS = {
    "java": [
        (r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']', "key_establishment", "Java JCA Cipher"),
        (r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']', "hashing", "Java JCA MessageDigest"),
        (r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']', "digital_signature", "Java JCA Signature"),
    ],
    "python": [
        (r'RSA\.generate\s*\(', "key_establishment", "Python PyCryptodome RSA"),
        (r'Crypto\.PublicKey\.RSA', "key_establishment", "Python PyCryptodome RSA"),
        (r'hashes\.SHA256\s*\(', "hashing", "Python Cryptography SHA256"),
        (r'hashes\.SHA1\s*\(', "hashing", "Python Cryptography SHA1"),
        (r'AES\.new\s*\(', "data_encryption", "Python PyCryptodome AES"),
        (r'hashlib\.sha256\s*\(', "hashing", "Python hashlib SHA256"),
        (r'hashlib\.sha1\s*\(', "hashing", "Python hashlib SHA1"),
        (r'hashlib\.md5\s*\(', "hashing", "Python hashlib MD5"),
        (r'rsa\.newkeys\s*\(', "key_establishment", "Python rsa library"),
        (r'ecdsa\.SigningKey', "digital_signature", "Python ecdsa library"),
    ],
    "c": [
        (r'RSA_generate_key|RSA_new', "key_establishment", "OpenSSL C API"),
        (r'AES_set_encrypt_key', "data_encryption", "OpenSSL AES API"),
        (r'SHA1_Init|SHA256_Init', "hashing", "OpenSSL SHA API"),
    ],
    "go": [
        (r'rsa\.GenerateKey', "key_establishment", "Go crypto/rsa"),
        (r'aes\.NewCipher', "data_encryption", "Go crypto/aes"),
        (r'sha256\.New', "hashing", "Go crypto/sha256"),
    ]
}

def scan_source_file(filename: str, content_str: str) -> list:
    findings = []
    lines = content_str.splitlines()
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    lang_map = {
        'java': 'java',
        'py': 'python',
        'c': 'c', 'cpp': 'c', 'h': 'c',
        'go': 'go'
    }
    lang = lang_map.get(ext, 'python' if ext == 'py' else 'java')
    rules = PATTERNS.get(lang, PATTERNS['python'])

    for line_num, line_text in enumerate(lines, start=1):
        matched = False
        for pattern, purpose, method in rules:
            match = re.search(pattern, line_text, re.IGNORECASE)
            if match:
                algo = "RSA-2048"
                upper_line = line_text.upper()
                if "AES" in upper_line:
                    algo = "AES-256"
                elif "SHA-256" in upper_line or "SHA256" in upper_line:
                    algo = "SHA-256"
                elif "SHA-1" in upper_line or "SHA1" in upper_line:
                    algo = "SHA-1"
                elif "MD5" in upper_line:
                    algo = "MD5"
                elif "ECDSA" in upper_line:
                    algo = "ECDSA-P256"

                findings.append({
                    "asset_id": f"src_{filename.replace('/', '_')}_{line_num}",
                    "file": filename,
                    "line": line_num,
                    "asset_type": "algorithm",
                    "algorithm": algo,
                    "purpose": purpose,
                    "detection_method": method,
                    "confidence": 0.95,
                    "snippet": line_text.strip()
                })
                matched = True
                break
                
        # Fallback keyword scan if no specific regex matched but crypto keywords exist
        if not matched:
            upper_line = line_text.upper()
            for kw, algo_name, purpose_type in [
                ("RSA", "RSA-2048", "key_establishment"),
                ("AES", "AES-256", "data_encryption"),
                ("SHA1", "SHA-1", "hashing"),
                ("MD5", "MD5", "hashing"),
                ("ECDSA", "ECDSA-P256", "digital_signature")
            ]:
                if kw in upper_line and not line_text.strip().startswith("#"):
                    findings.append({
                        "asset_id": f"src_{filename.replace('/', '_')}_{line_num}",
                        "file": filename,
                        "line": line_num,
                        "asset_type": "algorithm",
                        "algorithm": algo_name,
                        "purpose": purpose_type,
                        "detection_method": f"Keyword heuristic ({kw})",
                        "confidence": 0.80,
                        "snippet": line_text.strip()
                    })
                    break

    return findings