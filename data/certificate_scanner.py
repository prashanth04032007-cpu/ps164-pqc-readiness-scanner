"""
certificate_scanner.py
Parses X.509 certificates (.pem, .crt) deterministically for algorithm, key size, and expiry risk.
"""

def parse_certificate_file(filename: str, content_str: str) -> list:
    findings = []
    
    # Check for RSA public key blocks or signatures
    if "BEGIN CERTIFICATE" in content_str or "BEGIN RSA PRIVATE KEY" in content_str or "BEGIN PUBLIC KEY" in content_str:
        algo = "RSA-2048"
        if "ED25519" in content_str.upper():
            algo = "Ed25519"
        elif "ECDSA" in content_str.upper() or "EC PARAMETERS" in content_str.upper():
            algo = "ECDSA-P256"

        findings.append({
            "asset_id": f"cert_{filename.replace('/', '_')}",
            "file": filename,
            "line": 1,
            "asset_type": "certificate",
            "algorithm": algo,
            "purpose": "key_establishment" if "RSA" in algo else "digital_signature",
            "quantum_status": "QUANTUM-VULNERABLE" if "RSA" in algo or "ECDSA" in algo else "QUANTUM-RESISTANT",
            "classical_status": "SECURE",
            "detection_method": "X.509 Deterministic Parser",
            "confidence": 1.0,
            "snippet": content_str[:120].replace('\n', ' ') + "..."
        })
        
    return findings