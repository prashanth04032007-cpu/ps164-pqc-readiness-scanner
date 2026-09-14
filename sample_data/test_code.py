"""
cbom_formatter.py
CycloneDX v1.6 CBOM Export & Contextual PQC Recommendations (PS-164)
"""

import pandas as pd
from datetime import datetime
import uuid

def get_recommendation(algorithm: str) -> dict:
    """
    Provides context-aware PQC replacement suggestions, latency impact, 
    and migration cost based on NIST standards.
    """
    algo_upper = str(algorithm).upper()
    
    # PQC Recommendations based on finalized NIST standards (FIPS 203, 204, 205)
    if any(k in algo_upper for k in ['RSA', 'ECDH', 'DH']):
        return {
            "replacement": "ML-KEM (FIPS 203) / Hybrid RSA+ML-KEM",
            "latency": "Medium (Larger ciphertexts)",
            "cost": "High (Protocol/Certificate updates)"
        }
    elif any(k in algo_upper for k in ['ECDSA', 'ED25519', 'DSA']):
        return {
            "replacement": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
            "latency": "High (Larger signatures)",
            "cost": "High (Identity/PKI updates)"
        }
    elif any(k in algo_upper for k in ['AES-128', 'DES', '3DES', 'RC4']):
        return {
            "replacement": "AES-256 (Quantum-Safe Symmetric)",
            "latency": "Low",
            "cost": "Low (Drop-in replacement)"
        }
    elif any(k in algo_upper for k in ['SHA-1', 'MD5']):
        return {
            "replacement": "SHA-256 / SHA-3",
            "latency": "Low",
            "cost": "Low (Drop-in replacement)"
        }
    elif 'SHA' in algo_upper or 'AES-256' in algo_upper:
        return {
            "replacement": "Maintain (Already Quantum-Resistant)",
            "latency": "None",
            "cost": "None"
        }
    elif any(k in algo_upper for k in ['ML-KEM', 'ML-DSA', 'SLH-DSA']):
        return {
            "replacement": "None (Already PQC Standardized)",
            "latency": "None",
            "cost": "None"
        }
    
    return {
        "replacement": "Manual Review Required",
        "latency": "Unknown",
        "cost": "Unknown"
    }

def export_cyclonedx_cbom(df: pd.DataFrame) -> dict:
    """
    Exports the scanned findings into a machine-readable CycloneDX v1.6 CBOM format.
    """
    components = []
    
    for _, row in df.iterrows():
        # Create a unique purl (package URL) reference for the crypto asset
        safe_algo_name = str(row.get('algorithm', 'unknown')).lower().replace(' ', '-')
        bom_ref = f"pkg:crypto/{safe_algo_name}-{uuid.uuid4().hex[:8]}"
        
        component = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": str(row.get('algorithm', 'Unknown Algorithm')),
            "properties": [
                {"name": "crypto:asset_type", "value": str(row.get('asset_type', 'unknown'))},
                {"name": "crypto:purpose", "value": str(row.get('purpose', 'unknown'))},
                {"name": "crypto:quantum_status", "value": str(row.get('quantum_status', 'unknown'))},
                {"name": "discovery:file", "value": str(row.get('file', 'unknown'))},
                {"name": "discovery:line", "value": str(row.get('line', '0'))},
                {"name": "risk:tier", "value": str(row.get('Risk Tier', 'UNKNOWN'))},
                {"name": "risk:priority", "value": str(row.get('Priority', 'UNKNOWN'))}
            ]
        }
        components.append(component)

    # CycloneDX v1.6 Base Wrapper
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "PQC Assessment Tool",
                    "name": "SIH PS-164 Scanner",
                    "version": "2.0.0"
                }
            ]
        },
        "components": components
    }
    
    return cbom