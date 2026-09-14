"""
certificate_scanner.py
X.509 Certificate & Public Key Deterministic Parser (PS-164) [cite: 1]
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend

def scan_certificate(content_bytes: bytes, filename: str) -> list:
    """
    Deterministically parses PEM/DER X.509 certificates to extract 
    public key algorithms, key sizes, curves, and signature algorithms [cite: 1].
    """
    findings = []
    try:
        # Attempt to load PEM format first, fallback to DER [cite: 1]
        try:
            cert = x509.load_pem_x509_certificate(content_bytes, default_backend())
        except ValueError:
            cert = x509.load_der_x509_certificate(content_bytes, default_backend())
        
        pub_key = cert.public_key()
        pub_key_name = pub_key.__class__.__name__
        
        # 1. Classify Public Key Algorithm and size/curve [cite: 1]
        algo_str = "UNKNOWN-PUBLIC-KEY"
        key_size = getattr(pub_key, "key_size", None)
        
        if "RSAPublicKey" in pub_key_name or "RSAPrivateKey" in pub_key_name:
            algo_str = f"RSA-{key_size}" if key_size else "RSA"
        elif "EllipticCurve" in pub_key_name:
            curve_name = getattr(pub_key.curve, "name", "ECC").upper()
            algo_str = f"ECDSA-{curve_name}"

        # Determine quantum and classical vulnerability status [cite: 1]
        is_quantum_vuln = any(k in algo_str for k in ["RSA", "ECDSA"])
        is_classical_weak = (key_size and key_size < 2048)

        findings.append({
            "asset_id": f"{filename}_pubkey_{algo_str}",
            "source": filename,
            "line": 1,
            "asset_type": "certificate_public_key",
            "algorithm": algo_str,
            "purpose": "key_establishment",
            "quantum_status": "QUANTUM-VULNERABLE" if is_quantum_vuln else "UNKNOWN",
            "classical_status": "WEAK" if is_classical_weak else ("SECURE" if not is_classical_weak else "BROKEN"),
            "detection_method": "x509_certificate_parser",
            "confidence": 1.0,
            "snippet": f"Subject: {cert.subject.rfc4514_string()} | Issuer: {cert.issuer.rfc4514_string()}"
        })

        # 2. Extract Signature Algorithm [cite: 1]
        sig_algo = cert.signature_hash_algorithm
        sig_name = sig_algo.name.upper() if sig_algo else "UNKNOWN-SIGNATURE"
        is_sig_broken = any(b in sig_name for b in ["SHA1", "MD5"])

        findings.append({
            "asset_id": f"{filename}_signature_{sig_name}",
            "source": filename,
            "line": 1,
            "asset_type": "certificate_signature",
            "algorithm": sig_name,
            "purpose": "digital_signature",
            "quantum_status": "QUANTUM-VULNERABLE",
            "classical_status": "BROKEN" if is_sig_broken else "SECURE",
            "detection_method": "x509_certificate_parser",
            "confidence": 1.0,
            "snippet": f"Signature Algorithm: {sig_name} | Valid To: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}"
        })

    except Exception:
        # Ignore non-certificate or malformed files gracefully
        pass

    return findings