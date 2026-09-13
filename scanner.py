import re

def scan_file(content_text, filename):
    findings = []
    lines = content_text.split('\n')
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    # 1. Certificate Files (.pem, .crt)
    if ext in ['pem', 'crt']:
        if "BEGIN CERTIFICATE" in content_text:
            findings.append({
                "file": filename,
                "asset_type": "certificate",
                "algorithm": "X.509 Certificate (RSA/ECC)",
                "line": 1,
                "snippet": "PEM Certificate Payload",
                "quantum_status": "Vulnerable"
            })
        return findings

    # 2. Dependency Manifest Files
    if filename.lower() in ['requirements.txt', 'pom.xml', 'package.json'] or ext in ['txt', 'xml', 'json']:
        dep_patterns = {
            r"pycryptodome": ("PyCryptodome Library", "Vulnerable"),
            r"bouncycastle|bcprov": ("Bouncy Castle PKI Provider", "Vulnerable"),
            r"openssl": ("OpenSSL Crypto Suite", "Vulnerable"),
            r"liboqs": ("Open Quantum Safe (liboqs)", "Quantum-Safe")
        }
        for line_num, line in enumerate(lines, 1):
            for pattern, (label, status) in dep_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": filename,
                        "asset_type": "dependency",
                        "algorithm": label,
                        "line": line_num,
                        "snippet": line.strip(),
                        "quantum_status": status
                    })
        if findings:
            return findings

    # 3. Source Code Scanning (.c, .cpp, .h, .java, .py, .go, etc.)
    code_patterns = [
        # Quantum Safe / PQC Algorithms
        (r"ML-KEM|Kyber|OQS_KEM", "ML-KEM (Post-Quantum)", "Quantum-Safe", "pqc_algorithm"),
        (r"ML-DSA|Dilithium|OQS_SIG", "ML-DSA (Post-Quantum)", "Quantum-Safe", "pqc_algorithm"),
        (r"SLH-DSA|SPHINCS\+", "SLH-DSA (Post-Quantum)", "Quantum-Safe", "pqc_algorithm"),
        (r"AES[-_]?256[-_]?GCM|EVP_aes_256_gcm", "AES-256-GCM", "Quantum-Safe", "algorithm"),
        (r"SHA[-_]?3|SHA3|EVP_sha3_256", "SHA-3", "Quantum-Safe", "hash"),
        (r"SHA[-_]?256|EVP_sha256", "SHA-256", "Quantum-Safe", "hash"),
        
        # Quantum Vulnerable Classical Algorithms (Asymmetric)
        (r"RSA(?:_\w+|-\d+)?|EVP_PKEY_RSA|RSA_generate_key|KeyPairGenerator\.getInstance\s*\(\s*\"RSA\"", "RSA", "Vulnerable", "asymmetric_algorithm"),
        (r"ECDSA|ECDH|EVP_PKEY_EC|EC_KEY_new", "ECC (Elliptic Curve)", "Vulnerable", "asymmetric_algorithm"),
        (r"DSA_generate_parameters|EVP_PKEY_DSA", "DSA", "Vulnerable", "asymmetric_algorithm"),
        
        # Broken/Weak Classical Algorithms & Modes
        (r"DESede|3DES|DES_ecb_encrypt|DES_cbc_encrypt", "3DES", "Legacy-Broken", "symmetric_algorithm"),
        (r"AES[-_/]ECB|EVP_aes_\d+_ecb|AES_ecb_encrypt", "AES-ECB", "Legacy-Broken", "symmetric_algorithm"),
        (r"MD5|MD5_Init|EVP_md5|MessageDigest\.getInstance\s*\(\s*\"MD5\"", "MD5", "Legacy-Broken", "hash"),
        (r"SHA-?1|SHA1_Init|EVP_sha1|MessageDigest\.getInstance\s*\(\s*\"SHA-1\"", "SHA-1", "Legacy-Broken", "hash"),
        (r"SSLv3|TLSv1\.0|TLSv1\.1", "SSLv3 / TLS 1.0 (Weak Protocol)", "Legacy-Broken", "protocol")
    ]

    for line_num, line in enumerate(lines, 1):
        stripped_line = line.strip()
        if stripped_line.startswith("//") or stripped_line.startswith("#") or stripped_line.startswith("/*"):
            continue
            
        for pattern, algo_name, status, asset_type in code_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "file": filename,
                    "asset_type": asset_type,
                    "algorithm": algo_name,
                    "line": line_num,
                    "snippet": line.strip(),
                    "quantum_status": status
                })
                break

    return findings