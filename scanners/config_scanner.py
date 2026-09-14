"""
config_scanner.py
Scans general server and application configuration files (nginx.conf, sshd_config, etc.)
"""

def scan_config_file(filename: str, content_str: str) -> list:
    findings = []
    lines = content_str.splitlines()
    
    for idx, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if "diffie-hellman-group1-sha1" in line_lower or "ssh-rsa" in line_lower:
            findings.append({
                "asset_id": f"cfg_{filename.replace('/', '_')}_{idx}",
                "file": filename,
                "line": idx,
                "asset_type": "crypto_configuration",
                "algorithm": "SSH-RSA / Diffie-Hellman Group 1",
                "purpose": "key_establishment",
                "quantum_status": "QUANTUM-VULNERABLE",
                "classical_status": "WEAK",
                "detection_method": "Config File Parser",
                "confidence": 0.95,
                "snippet": line.strip()
            })
    return findings