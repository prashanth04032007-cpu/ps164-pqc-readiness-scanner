"""
binary_scanner.py
Scans compiled binaries (.so, .dll, .exe, .jar) for embedded cryptographic strings and symbols.
"""
import re

BINARY_SIGNATURES = [
    (rb'RSA_generate_key', "RSA-2048", "key_establishment", "OpenSSL RSA Symbol"),
    (rb'EC_KEY_new_by_curve_name', "ECDSA-P256", "digital_signature", "OpenSSL EC Symbol"),
    (rb'AES_set_encrypt_key', "AES-256", "data_encryption", "OpenSSL AES Symbol"),
    (rb'SHA1_Init', "SHA-1", "hashing", "OpenSSL SHA-1 Symbol"),
    (rb'SHA256_Init', "SHA-256", "hashing", "OpenSSL SHA-256 Symbol"),
    (rb'MD5_Init', "MD5", "hashing", "OpenSSL MD5 Symbol"),
    (rb'ED25519', "Ed25519", "digital_signature", "Ed25519 String"),
    (rb'ML-KEM', "ML-KEM-768", "key_establishment", "PQC ML-KEM String"),
    (rb'KYBER', "ML-KEM-768", "key_establishment", "Kyber PQC String"),
]

def scan_binary_file(filename: str, content_bytes: bytes) -> list:
    findings = []
    
    for pattern, algo, purpose, method in BINARY_SIGNATURES:
        if re.search(pattern, content_bytes, re.IGNORECASE):
            findings.append({
                "asset_id": f"bin_{filename.replace('/', '_')}_{algo}",
                "file": filename,
                "line": 1,
                "asset_type": "binary_symbol",
                "algorithm": algo,
                "purpose": purpose,
                "detection_method": method,
                "confidence": 0.85,
                "snippet": f"Embedded symbol/signature matched: {pattern.decode('latin1', errors='ignore')}"
            })
            
    return findings