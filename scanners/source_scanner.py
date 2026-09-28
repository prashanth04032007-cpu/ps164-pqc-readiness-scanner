"""
PS-164 Precision Source Crypto Scanner

Detects cryptographic API usage in:
- Java
- Python
- C/C++
- Go

Design principle:
Explicit API evidence > contextual inference > keyword fallback.

Generic words such as "RSA" or "AES" are NOT treated as active
cryptographic usage unless there is meaningful code context.
"""

import re


# ---------------------------------------------------------------------
# Algorithm normalization
# ---------------------------------------------------------------------

def normalize_algorithm(value: str, line: str = "") -> str:
    """
    Convert API algorithm names/transforms into stable CBOM-style names.
    """
    text = f"{value or ''} {line or ''}".upper()

    # RSA
    rsa_match = re.search(r"RSA[-_/ ]?(\d{3,4})", text)
    if rsa_match:
        return f"RSA-{rsa_match.group(1)}"

    if "RSA" in text:
        return "RSA-2048"

    # ECDSA / EC
    if "ECDSA" in text:
        return "ECDSA-P256"

    if "ED25519" in text:
        return "Ed25519"

    if "ED448" in text:
        return "Ed448"

    # AES
    aes_match = re.search(r"AES[-_/ ]?(\d{3})", text)
    if aes_match:
        return f"AES-{aes_match.group(1)}"

    if "AES" in text:
        return "AES-256"

    # Hashes
    if "SHA-512" in text or "SHA512" in text:
        return "SHA-512"

    if "SHA-384" in text or "SHA384" in text:
        return "SHA-384"

    if "SHA-256" in text or "SHA256" in text:
        return "SHA-256"

    if "SHA-1" in text or "SHA1" in text:
        return "SHA-1"

    if "MD5" in text:
        return "MD5"

    # Other symmetric algorithms
    if "3DES" in text or "TRIPLEDES" in text:
        return "3DES"

    if re.search(r"\bDES\b", text):
        return "DES"

    if "RC4" in text:
        return "RC4"

    if "CHACHA20" in text or "CHACHA" in text:
        return "ChaCha20"

    # PQC
    if "ML-KEM" in text:
        return "ML-KEM-768"

    if "KYBER" in text:
        return "ML-KEM-768"

    if "ML-DSA" in text:
        return "ML-DSA-65"

    if "DILITHIUM" in text:
        return "ML-DSA-65"

    if "SLH-DSA" in text:
        return "SLH-DSA"

    if "SPHINCS" in text:
        return "SLH-DSA"

    return str(value).strip() if value else "UNKNOWN"


# ---------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------

JAVA_RULES = [
    (
        re.compile(
            r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        "Java JCA Cipher",
    ),
    (
        re.compile(
            r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        "Java JCA MessageDigest",
    ),
    (
        re.compile(
            r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        "Java JCA Signature",
    ),
    (
        re.compile(
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        "Java JCA KeyPairGenerator",
    ),
    (
        re.compile(
            r'KeyAgreement\.getInstance\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),
        "Java JCA KeyAgreement",
    ),
]


def scan_java_line(line: str):
    findings = []

    for pattern, method in JAVA_RULES:
        match = pattern.search(line)

        if not match:
            continue

        api_value = match.group(1).strip()

        if method == "Java JCA Cipher":
            # Cipher is normally encryption/decryption.
            # RSA Cipher can represent asymmetric encryption/key transport,
            # while AES/DES/etc. are data encryption.
            algo = normalize_algorithm(api_value, line)

            if algo.startswith("RSA"):
                purpose = "key_establishment"
            else:
                purpose = "data_encryption"

        elif method == "Java JCA MessageDigest":
            algo = normalize_algorithm(api_value, line)
            purpose = "hashing"

        elif method == "Java JCA Signature":
            algo = normalize_algorithm(api_value, line)
            purpose = "digital_signature"

        elif method == "Java JCA KeyPairGenerator":
            algo = normalize_algorithm(api_value, line)

            # KeyPairGenerator proves key material generation, but by
            # itself does not prove whether the key will be used for
            # signatures, key establishment, or another operation.
            purpose = "key_generation"

        elif method == "Java JCA KeyAgreement":
            algo = normalize_algorithm(api_value, line)
            purpose = "key_establishment"

        else:
            continue

        findings.append(
            {
                "algorithm": algo,
                "purpose": purpose,
                "detection_method": method,
                "confidence": 0.95,
                "snippet": line.strip(),
            }
        )

        # One explicit API match per line is enough.
        break

    return findings


# ---------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------

PYTHON_RULES = [
    (
        re.compile(r"RSA\.generate\s*\(", re.IGNORECASE),
        "RSA-2048",
        "key_establishment",
        "Python PyCryptodome RSA",
    ),
    (
        re.compile(r"Crypto\.PublicKey\.RSA", re.IGNORECASE),
        "RSA-2048",
        "key_establishment",
        "Python PyCryptodome RSA",
    ),
    (
        re.compile(r"hashes\.SHA256\s*\(", re.IGNORECASE),
        "SHA-256",
        "hashing",
        "Python Cryptography SHA256",
    ),
    (
        re.compile(r"hashes\.SHA1\s*\(", re.IGNORECASE),
        "SHA-1",
        "hashing",
        "Python Cryptography SHA1",
    ),
    (
        re.compile(r"AES\.new\s*\(", re.IGNORECASE),
        "AES-256",
        "data_encryption",
        "Python PyCryptodome AES",
    ),
    (
        re.compile(r"hashlib\.sha256\s*\(", re.IGNORECASE),
        "SHA-256",
        "hashing",
        "Python hashlib SHA256",
    ),
    (
        re.compile(r"hashlib\.sha1\s*\(", re.IGNORECASE),
        "SHA-1",
        "hashing",
        "Python hashlib SHA1",
    ),
    (
        re.compile(r"hashlib\.md5\s*\(", re.IGNORECASE),
        "MD5",
        "hashing",
        "Python hashlib MD5",
    ),
    (
        re.compile(r"rsa\.newkeys\s*\(", re.IGNORECASE),
        "RSA-2048",
        "key_establishment",
        "Python rsa library",
    ),
    (
        re.compile(r"ecdsa\.SigningKey", re.IGNORECASE),
        "ECDSA-P256",
        "digital_signature",
        "Python ecdsa library",
    ),
]


def scan_python_line(line: str):
    for pattern, algorithm, purpose, method in PYTHON_RULES:
        if pattern.search(line):
            return [
                {
                    "algorithm": algorithm,
                    "purpose": purpose,
                    "detection_method": method,
                    "confidence": 0.95,
                    "snippet": line.strip(),
                }
            ]

    return []


# ---------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------

C_RULES = [
    (
        re.compile(r"RSA_generate_key|RSA_new", re.IGNORECASE),
        "RSA-2048",
        "key_establishment",
        "OpenSSL RSA API",
    ),
    (
        re.compile(r"AES_set_encrypt_key|EVP_aes_\d+_", re.IGNORECASE),
        "AES-256",
        "data_encryption",
        "OpenSSL AES API",
    ),
    (
        re.compile(r"SHA1_Init|SHA1_Update|SHA1_Final", re.IGNORECASE),
        "SHA-1",
        "hashing",
        "OpenSSL SHA-1 API",
    ),
    (
        re.compile(r"SHA256_Init|SHA256_Update|SHA256_Final", re.IGNORECASE),
        "SHA-256",
        "hashing",
        "OpenSSL SHA-256 API",
    ),
    (
        re.compile(r"EVP_sha256\s*\(", re.IGNORECASE),
        "SHA-256",
        "hashing",
        "OpenSSL EVP SHA-256",
    ),
    (
        re.compile(r"EVP_sha1\s*\(", re.IGNORECASE),
        "SHA-1",
        "hashing",
        "OpenSSL EVP SHA-1",
    ),
]


def scan_c_line(line: str):
    for pattern, algorithm, purpose, method in C_RULES:
        if pattern.search(line):
            return [
                {
                    "algorithm": algorithm,
                    "purpose": purpose,
                    "detection_method": method,
                    "confidence": 0.95,
                    "snippet": line.strip(),
                }
            ]

    return []


# ---------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------

GO_RULES = [
    (
        re.compile(r"rsa\.GenerateKey", re.IGNORECASE),
        "RSA-2048",
        "key_establishment",
        "Go crypto/rsa",
    ),
    (
        re.compile(r"aes\.NewCipher", re.IGNORECASE),
        "AES-256",
        "data_encryption",
        "Go crypto/aes",
    ),
    (
        re.compile(r"sha256\.New", re.IGNORECASE),
        "SHA-256",
        "hashing",
        "Go crypto/sha256",
    ),
    (
        re.compile(r"sha1\.New", re.IGNORECASE),
        "SHA-1",
        "hashing",
        "Go crypto/sha1",
    ),
]


def scan_go_line(line: str):
    for pattern, algorithm, purpose, method in GO_RULES:
        if pattern.search(line):
            return [
                {
                    "algorithm": algorithm,
                    "purpose": purpose,
                    "detection_method": method,
                    "confidence": 0.95,
                    "snippet": line.strip(),
                }
            ]

    return []


# ---------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------

def scan_source_file(filename: str, content_str: str) -> list:
    """
    Scan a source file using language-specific cryptographic APIs.

    Important:
    No broad generic keyword fallback is used. This prevents strings,
    comments, documentation, variable names, and unrelated text from
    becoming high-confidence crypto findings.
    """

    findings = []

    lines = content_str.splitlines()

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext == "java":
        scanner = scan_java_line
        language = "Java"
    elif ext == "py":
        scanner = scan_python_line
        language = "Python"
    elif ext in {"c", "cpp", "cc", "h", "hpp"}:
        scanner = scan_c_line
        language = "C/C++"
    elif ext == "go":
        scanner = scan_go_line
        language = "Go"
    else:
        return []

    for line_num, line_text in enumerate(lines, start=1):

        stripped = line_text.strip()

        if not stripped:
            continue

        # Ignore common single-line comments.
        if (
            stripped.startswith("//")
            or stripped.startswith("#")
            or stripped.startswith("*")
        ):
            continue

        line_findings = scanner(line_text)

        for finding in line_findings:
            finding["asset_id"] = (
                f"src_{filename.replace('/', '_')}_{line_num}"
            )
            finding["file"] = filename
            finding["line"] = line_num
            finding["asset_type"] = "algorithm"
            finding["language"] = language

            findings.append(finding)

    return findings
