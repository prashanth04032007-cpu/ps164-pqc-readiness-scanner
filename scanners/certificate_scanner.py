"""Deterministic X.509 certificate scanner for PS-164.

Extracts certificate identity, validity, public-key algorithm/size/curve and
certificate signature algorithm.  It deliberately does not assume that a
certificate public key is used for key establishment: in normal TLS use it is
primarily an authentication/signature asset.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, dsa


def _load_certificate(content: Any):
    if isinstance(content, str):
        content = content.encode("utf-8", errors="ignore")
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("certificate content must be bytes or text")
    raw = bytes(content)
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        return x509.load_der_x509_certificate(raw)


def _public_key_info(pub) -> tuple[str, str, str]:
    """Return algorithm, key size and curve."""
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}", str(pub.key_size), "Not applicable"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        name = pub.curve.name.upper()
        return f"EC-{name}", str(pub.key_size), name
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}", str(pub.key_size), "Not applicable"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", "256", "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", "448", "Ed448"
    return type(pub).__name__, str(getattr(pub, "key_size", "Not detected")), "Not detected"


def _quantum_status(algo: str) -> str:
    u = algo.upper()
    if u.startswith(("RSA", "EC-", "DSA", "ED25519", "ED448")):
        return "QUANTUM-VULNERABLE"
    return "NOT_CLASSIFIED"


def _classical_status(algo: str, key_size: str) -> str:
    u = algo.upper()
    try:
        size = int(key_size)
    except Exception:
        size = None
    if u.startswith("RSA") and size is not None and size < 2048:
        return "WEAK"
    if u.startswith("DSA") and size is not None and size < 2048:
        return "WEAK"
    return "SECURE"


def _expiry_context(cert) -> tuple[int, str, bool]:
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days = (not_after - now).days
    return days, not_after.strftime("%Y-%m-%d"), days < 0


def scan_certificate(content_bytes: bytes | str, filename: str) -> list[dict]:
    findings: list[dict] = []
    try:
        cert = _load_certificate(content_bytes)
        pub_algo, key_size, curve = _public_key_info(cert.public_key())
        days_to_expiry, expiry_date, expired = _expiry_context(cert)
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        serial = format(cert.serial_number, "x")

        base = {
            "source": filename,
            "file": filename,
            "line": 1,
            "certificate": filename,
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "certificate_serial": serial,
            "not_valid_before": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
            "not_valid_after": expiry_date,
            "days_to_expiry": days_to_expiry,
            "expired": expired,
            "detection_method": "x509_certificate_parser",
            "confidence": 1.0,
            "evidence_type": "CERTIFICATE_METADATA",
        }

        findings.append({
            **base,
            "asset_id": f"{filename}_pubkey_{pub_algo}",
            "asset_type": "certificate_public_key",
            "algorithm": pub_algo,
            "purpose": "digital_signature",
            "key_size": key_size,
            "curve": curve,
            "quantum_status": _quantum_status(pub_algo),
            "classical_status": _classical_status(pub_algo, key_size),
            "snippet": (
                f"Subject={subject} | Issuer={issuer} | PublicKey={pub_algo} "
                f"| Curve={curve} | ValidTo={expiry_date}"
            ),
            "evidence": "X.509 public key metadata",
        })

        sig_algo = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
        sig_hash = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
        raw_sig = sig_algo.upper()
        if "RSA" in raw_sig:
            sig_display = f"RSA-{sig_hash}"
        elif "ECDSA" in raw_sig:
            sig_display = f"ECDSA-{sig_hash}"
        elif "ED25519" in raw_sig:
            sig_display = "Ed25519"
        elif "ED448" in raw_sig:
            sig_display = "Ed448"
        else:
            sig_display = raw_sig
        classical_sig = "BROKEN" if sig_hash in {"SHA1", "MD5", "MD2"} else "SECURE"
        findings.append({
            **base,
            "asset_id": f"{filename}_signature_{sig_display}",
            "asset_type": "certificate_signature",
            "algorithm": sig_display,
            "purpose": "certificate_signature",
            "version": sig_hash,
            "quantum_status": "QUANTUM-VULNERABLE" if any(x in sig_display for x in ("RSA", "ECDSA", "DSA", "ED25519", "ED448")) else "NOT_CLASSIFIED",
            "classical_status": classical_sig,
            "snippet": f"CertificateSignature={sig_display} | Hash={sig_hash} | ValidTo={expiry_date}",
            "evidence": "X.509 issuer signature algorithm",
        })

        # Expiry is an operational lifecycle signal, not a crypto algorithm.
        if days_to_expiry <= 90:
            findings.append({
                **base,
                "asset_id": f"{filename}_expiry_{expiry_date}",
                "asset_type": "certificate_lifecycle",
                "algorithm": "Certificate Expiry",
                "purpose": "certificate_lifecycle",
                "quantum_status": "NOT_APPLICABLE",
                "classical_status": "EXPIRED" if expired else "EXPIRING_SOON",
                "days_to_expiry": days_to_expiry,
                "snippet": f"Certificate expires on {expiry_date} ({days_to_expiry} days from scan)",
                "evidence": "X.509 validity period",
                "confidence": 1.0,
            })

    except Exception:
        return []
    return findings


def parse_certificate_file(filename: str, content) -> list[dict]:
    return scan_certificate(content, filename)

scan_certificate_file = parse_certificate_file
