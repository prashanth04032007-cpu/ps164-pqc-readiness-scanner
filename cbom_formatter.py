import uuid
from datetime import datetime

PQC_MAPPINGS = {
    "RSA": {"replacement": "ML-KEM (Kyber) or Hybrid X25519+ML-KEM", "latency": "Low Impact", "cost": "Medium"},
    "ECC (Elliptic Curve)": {"replacement": "ML-KEM-768 / ML-DSA-65", "latency": "Low Impact", "cost": "Low"},
    "DSA": {"replacement": "ML-DSA (Dilithium) or SLH-DSA", "latency": "Low Impact", "cost": "Low"},
    "3DES": {"replacement": "AES-256-GCM", "latency": "None", "cost": "Low"},
    "AES-ECB": {"replacement": "AES-256-GCM", "latency": "None", "cost": "Low"},
    "MD5": {"replacement": "SHA-256 / SHA-3", "latency": "None", "cost": "Low"},
    "SHA-1": {"replacement": "SHA-256 / SHA-3", "latency": "None", "cost": "Low"},
    "SSLv3 / TLS 1.0 (Weak Protocol)": {"replacement": "TLS 1.3 with Hybrid PQC", "latency": "Low Impact", "cost": "Medium"},
    "ML-KEM (Post-Quantum)": {"replacement": "Already PQC Compliant", "latency": "None", "cost": "None"},
    "ML-DSA (Post-Quantum)": {"replacement": "Already PQC Compliant", "latency": "None", "cost": "None"},
    "SLH-DSA (Post-Quantum)": {"replacement": "Already PQC Compliant", "latency": "None", "cost": "None"},
    "AES-256-GCM": {"replacement": "Already Quantum-Resistant", "latency": "None", "cost": "None"},
    "SHA-256": {"replacement": "Already Quantum-Resistant", "latency": "None", "cost": "None"},
    "SHA-3": {"replacement": "Already Quantum-Resistant", "latency": "None", "cost": "None"}
}

def get_recommendation(algorithm_name):
    return PQC_MAPPINGS.get(algorithm_name, {
        "replacement": "Review Algorithm Specification",
        "latency": "N/A",
        "cost": "N/A"
    })

def export_cyclonedx_cbom(findings_df):
    components = []
    
    for _, row in findings_df.iterrows():
        algo = row['algorithm']
        rec = get_recommendation(algo)
        
        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{uuid.uuid4().hex[:8]}",
            "name": algo,
            "evidence": {
                "occurrences": [
                    {
                        "location": row['file'],
                        "line": int(row['line']),
                        "offset": 0,
                        "symbol": row['snippet']
                    }
                ]
            },
            "cryptoProperties": {
                "assetType": row['asset_type'],
                "algorithmProperties": {
                    "variant": algo,
                    "quantumStatus": row['quantum_status']
                },
                "pqcTargetState": rec['replacement'],
                "riskAssessment": {
                    "moscaStatus": row['Risk Tier'],
                    "actionRequired": row['Action']
                }
            }
        }
        components.append(component)
        
    cyclonedx_bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "PQC Readiness Suite",
                    "name": "PS-164 Discovery & Risk Engine",
                    "version": "1.0.0"
                }
            ]
        },
        "components": components
    }
    
    return cyclonedx_bom