"""
cbom_formatter.py
Generates CycloneDX v1.6 Cryptographic Bill of Materials (CBOM) exports and PQC recommendations. [cite: 1]
"""
import uuid
import datetime

def get_recommendation(algorithm: str) -> dict:
    """
    Returns purpose-aware NIST PQC replacement recommendations, latency impact, and cost. [cite: 1]
    """
    algo_upper = str(algorithm).upper()
    if any(k in algo_upper for k in ["RSA", "ECDH", "DH", "KYBER", "ML-KEM"]):
        return {
            "replacement": "ML-KEM-768 (FIPS 203)",
            "latency": "Low / Moderate",
            "cost": "Medium"
        }
    elif any(k in algo_upper for k in ["ECDSA", "DSA", "DILITHIUM", "ML-DSA"]):
        return {
            "replacement": "ML-DSA-65 (FIPS 204)",
            "latency": "Moderate",
            "cost": "Medium"
        }
    elif any(k in algo_upper for k in ["SHA-1", "MD5"]):
        return {
            "replacement": "SHA-256 / SHA-3",
            "latency": "Negligible",
            "cost": "Low"
        }
    elif any(k in algo_upper for k in ["3DES", "DES", "RC4"]):
        return {
            "replacement": "AES-256",
            "latency": "Negligible",
            "cost": "Low"
        }
    else:
        return {
            "replacement": "NIST PQC Approved Standard",
            "latency": "Depends on profile",
            "cost": "Variable"
        }

def export_cyclonedx_cbom(df) -> dict:
    """
    Converts the findings DataFrame into a CycloneDX v1.6 CBOM JSON structure with component relationships. [cite: 1]
    """
    components = []
    dependencies = []
    root_uuid = str(uuid.uuid4())
    
    # Root application node in the CBOM graph [cite: 1]
    components.append({
        "type": "application",
        "bom-ref": root_uuid,
        "name": "PS-164-Scanned-Project",
        "version": "1.0.0"
    })
    
    dep_depends_on = []

    for idx, row in df.iterrows():
        comp_uuid = str(uuid.uuid4())
        dep_depends_on.append(comp_uuid)
        
        algo = str(row.get('algorithm', 'UNKNOWN'))
        asset_type = str(row.get('asset_type', 'algorithm'))
        purpose = str(row.get('purpose', 'unknown'))
        q_status = str(row.get('quantum_status', 'QUANTUM-VULNERABLE'))
        
        # Map asset_type to CycloneDX 1.6 component type
        cdx_type = "cryptographic-asset"
        if asset_type == 'certificate':
            cdx_type = "certificate"
        elif asset_type == 'library_provider':
            cdx_type = "library"
        elif asset_type == 'protocol':
            cdx_type = "protocol"
            
        components.append({
            "type": cdx_type,
            "bom-ref": comp_uuid,
            "name": algo,
            "version": "1.0",
            "cryptoProperties": {
                "assetType": asset_type,
                "purpose": purpose,
                "quantumRisk": q_status,
                "location": {
                    "file": str(row.get('file', '')),
                    "line": int(row.get('line', 1))
                }
            }
        })
        
    dependencies.append({
        "ref": root_uuid,
        "dependsOn": dep_depends_on
    })

    cbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "PS-164",
                    "name": "PQC Discovery & Quantum Risk Assessment Platform",
                    "version": "1.0.0"
                }
            ]
        },
        "components": components,
        "dependencies": dependencies
    }
    
    return cbom_doc