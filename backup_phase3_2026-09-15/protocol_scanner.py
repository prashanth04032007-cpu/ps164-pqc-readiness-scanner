"""
protocol_scanner.py
Parses protocol and server configuration files for TLS versions and cipher suites.
"""
import re

PROTOCOL_RULES = [
    # Weak TLS / SSL versions
    (r'TLSv1\.0|SSLv3|SSLv2', "RSA-2048", "key_establishment", "Legacy/Insecure Protocol Version"),
    # Weak or vulnerable ciphers
    (r'RC4-|3DES-|DES-|RC4_SHA', "3DES", "data_encryption", "Legacy Symmetric Cipher"),
    (r'RSA-EXPORT|EXPORT', "RSA-2048", "key_establishment", "Export-grade RSA Cipher"),
    (r'ECDHE-RSA-|DHE-RSA-', "RSA-2048", "key_establishment", "Classical Hybrid Key Exchange"),
    (r'AES128-GCM|AES256-GCM', "AES-256", "data_encryption", "AES-GCM Cipher Suite"),
]

def scan_protocol_file(filename: str, content_str: str) -> list:
    findings = []
    lines = content_str.splitlines()
    
    for line_num, line_text in enumerate(lines, start=1):
        if line_text.strip().startswith('#'):
            continue
            
        for pattern, algo, purpose, method in PROTOCOL_RULES:
            if re.search(pattern, line_text, re.IGNORECASE):
                findings.append({
                    "asset_id": f"proto_{filename.replace('/', '_')}_{line_num}",
                    "file": filename,
                    "line": line_num,
                    "asset_type": "protocol_config",
                    "algorithm": algo,
                    "purpose": purpose,
                    "detection_method": method,
                    "confidence": 0.90,
                    "snippet": line_text.strip()
                })
                break  # avoid duplicate hits on the same line
                
    return findings