"""Deterministic TLS/SSL protocol and cipher-suite scanner for PS-164."""
from __future__ import annotations
import re

# Each rule is intentionally specific. We do not infer a key size unless the
# configuration actually states one.
PROTOCOL_RULES = [
    (re.compile(r"\bSSLv2\b", re.I), "SSLv2", "protocol_version", "BROKEN", "QUANTUM-VULNERABLE", 0.99),
    (re.compile(r"\bSSLv3\b", re.I), "SSLv3", "protocol_version", "BROKEN", "QUANTUM-VULNERABLE", 0.99),
    (re.compile(r"\bTLSv1(?:\.0)?\b|\bTLS1\.0\b", re.I), "TLS 1.0", "protocol_version", "DEPRECATED", "QUANTUM-VULNERABLE", 0.99),
    (re.compile(r"\bTLSv1\.1\b|\bTLS1\.1\b", re.I), "TLS 1.1", "protocol_version", "DEPRECATED", "QUANTUM-VULNERABLE", 0.99),
    (re.compile(r"\bRC4(?:-|_|\b)|RC4_SHA", re.I), "RC4", "data_encryption", "DEPRECATED", "QUANTUM-RESISTANT", 0.99),
    (re.compile(r"\b(?:3DES|DES)-|\b3DES\b", re.I), "3DES", "data_encryption", "DEPRECATED", "QUANTUM-RESISTANT", 0.99),
    (re.compile(r"\bRSA[-_]EXPORT\b|\bEXPORT\b", re.I), "RSA-EXPORT", "key_establishment", "BROKEN", "QUANTUM-VULNERABLE", 0.99),
]

CIPHER_PATTERNS = [
    (re.compile(r"TLS_(?:ECDHE|ECDH)_RSA_", re.I), "EC key exchange + RSA authentication", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"TLS_(?:ECDHE|ECDH)_ECDSA_", re.I), "EC key exchange + ECDSA authentication", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"(?:ECDHE|ECDH)-RSA-", re.I), "EC key exchange + RSA authentication", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"(?:ECDHE|ECDH)-ECDSA-", re.I), "EC key exchange + ECDSA authentication", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"(?<!EC)(?:DHE|DH)-RSA-", re.I), "DH key exchange + RSA authentication", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"\bRSA-PSK\b|\bTLS_RSA_", re.I), "RSA key transport", "key_establishment", "QUANTUM-VULNERABLE"),
    (re.compile(r"AES(?:128|256)-GCM", re.I), "AES-GCM", "data_encryption", "QUANTUM-RESISTANT"),
]


def _base(filename, line_no, snippet, confidence=0.95):
    return {
        "file": filename,
        "line": line_no,
        "asset_type": "protocol_config",
        "evidence_type": "CONFIGURATION",
        "protocol": "TLS/SSL",
        "snippet": snippet.strip(),
        "confidence": confidence,
        "detection_method": "TLS/protocol configuration parser",
        "evidence": "Explicit protocol or cipher-suite configuration",
    }


def scan_protocol_file(filename: str, content_str: str) -> list[dict]:
    findings = []
    for line_num, line_text in enumerate(content_str.splitlines(), start=1):
        stripped = line_text.strip()
        if not stripped or stripped.startswith(("#", ";", "//")):
            continue

        # Explicit protocol/version findings.
        for pattern, algo, purpose, classical, quantum, conf in PROTOCOL_RULES:
            if pattern.search(line_text):
                findings.append({
                    **_base(filename, line_num, line_text, conf),
                    "asset_id": f"proto_{filename.replace('/', '_')}_{line_num}_{algo}",
                    "algorithm": algo,
                    "purpose": purpose,
                    "classical_status": classical,
                    "quantum_status": quantum,
                })

        # Cipher suite findings; one suite can produce one precise record.
        for pattern, algo, purpose, quantum in CIPHER_PATTERNS:
            match = pattern.search(line_text)
            if match:
                findings.append({
                    **_base(filename, line_num, line_text, 0.96),
                    "asset_id": f"cipher_{filename.replace('/', '_')}_{line_num}_{algo}",
                    "asset_type": "cipher_suite",
                    "algorithm": algo,
                    "purpose": purpose,
                    "quantum_status": quantum,
                    "classical_status": "SECURE",
                    "mode": "GCM" if "GCM" in match.group(0).upper() else "Not detected",
                })

    # De-duplicate exact evidence records.
    unique = {}
    for row in findings:
        key = (row.get("file"), row.get("line"), row.get("algorithm"), row.get("purpose"))
        unique[key] = row
    return list(unique.values())
