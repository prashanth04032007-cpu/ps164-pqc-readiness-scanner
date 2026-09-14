"""
dependency_scanner.py
Scans package manifests for cryptographic libraries and providers. [cite: 1]
"""

KNOWN_CRYPTO_LIBS = {
    "bouncycastle": ("Bouncy Castle Java Provider", "library_provider"),
    "pycryptodome": ("PyCryptodome", "library_provider"),
    "cryptography": ("Python Cryptography", "library_provider"),
    "openssl": ("OpenSSL C Library", "library_provider"),
    "libsodium": ("libsodium", "library_provider"),
    "wolfssl": ("wolfSSL", "library_provider"),
}

def scan_dependency_file(filename: str, content_str: str) -> list:
    findings = []
    lines = content_str.splitlines()
    
    for idx, line in enumerate(lines, start=1):
        line_lower = line.lower()
        for lib_key, (lib_name, asset_type) in KNOWN_CRYPTO_LIBS.items():
            if lib_key in line_lower:
                findings.append({
                    "asset_id": f"dep_{filename.replace('/', '_')}_{idx}",
                    "file": filename,
                    "line": idx,
                    "asset_type": asset_type,
                    "algorithm": lib_name,
                    "purpose": "crypto_provider",
                    "quantum_status": "QUANTUM-RESISTANT",
                    "classical_status": "SECURE",
                    "detection_method": "Manifest Dependency Parser",
                    "confidence": 0.99,
                    "snippet": line.strip()
                })
    return findings