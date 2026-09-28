"""
mosca_engine.py
MOSCA Risk & Contextual Prioritization Engine (PS-164)
"""
import os
import json

CATALOG_PATH = os.path.join(os.path.dirname(__file__), "data", "crypto_catalog.json")
CRYPTO_CATALOG = {}
if os.path.exists(CATALOG_PATH):
    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            CRYPTO_CATALOG = json.load(f)
    except Exception:
        CRYPTO_CATALOG = {}


def derive_asset_context(finding: dict) -> dict:
    """
    Derives functional purpose, operational exposure, data sensitivity,
    shelf-life (X), migration time (Y), and MOSCA risk prioritization
    respecting per-asset/per-file metadata or the crypto catalog if present. [cite: 1]
    """
    algorithm = str(finding.get("algorithm", "")).upper()
    asset_type = str(finding.get("asset_type", "")).lower()
    source = str(finding.get("source", finding.get("file", ""))).lower()

    # Check if algorithm exists in catalog first
    catalog_entry = CRYPTO_CATALOG.get(algorithm, {})

    # 1. Determine Cryptographic Purpose
    if catalog_entry and "purposes" in catalog_entry and catalog_entry["purposes"]:
        purpose = catalog_entry["purposes"][0]
    elif any(k in algorithm for k in ["RSA", "ECDH", "DH", "KYBER", "ML-KEM"]):
        purpose = "key_establishment"
    elif any(k in algorithm for k in ["ECDSA", "DSA", "DILITHIUM", "ML-DSA", "SLH-DSA"]):
        purpose = "digital_signature"
    elif any(k in algorithm for k in ["AES", "DES", "3DES", "RC4"]):
        purpose = "data_encryption"
    elif any(k in algorithm for k in ["MD5", "SHA-1", "SHA-256", "SHA-3"]):
        purpose = "hashing"
    else:
        purpose = "crypto_provider" if asset_type == "library_provider" else "unknown"

    # Default weights by purpose
    purpose_defaults = {
        "key_establishment": (7.0, 3.0, 3.0, 3.0),
        "digital_signature": (3.0, 2.0, 3.0, 3.0),
        "data_encryption": (10.0, 2.0, 3.0, 3.0),
        "hashing": (2.0, 1.0, 2.0, 2.0),
        "crypto_provider": (5.0, 2.0, 2.0, 2.0),
        "unknown": (5.0, 2.0, 2.0, 2.0)
    }
    default_x, default_y, default_w, default_b = purpose_defaults.get(purpose, (5.0, 2.0, 2.0, 2.0))

    # Allow per-asset / per-file metadata override (P0 Fixes #1, #2, #4) [cite: 1]
    x_shelf_life = float(finding.get("x_shelf_life", default_x))
    y_migration_time = float(finding.get("y_migration_time", default_y))
    data_sensitivity = float(finding.get("data_sensitivity", default_w))
    business_criticality = float(finding.get("business_criticality", default_b))

    # 2. Determine Operational Exposure
    if any(k in source for k in ["nginx", "sshd", "server", "cert", "pem", "crt", "public"]):
        exposure = "external_facing"
    elif any(k in source for k in ["config", "api", "client"]):
        exposure = "internal_service"
    else:
        exposure = "isolated_code"

    # 3. Determine Quantum Status
    if catalog_entry and "quantum_status" in catalog_entry:
        q_status = catalog_entry["quantum_status"]
    else:
        q_status = finding.get("quantum_status", "QUANTUM-VULNERABLE").upper()
        if any(k in algorithm for k in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS+"]):
            q_status = "QUANTUM-SAFE"
        elif any(k in algorithm for k in ["AES-256", "SHA-256", "SHA-3", "SHA-512"]):
            q_status = "QUANTUM-RESISTANT"

    # 4. Calculate Risk Score, Risk Tier, and Priority
    if q_status == "QUANTUM-SAFE":
        risk_score = 10
        risk_tier = "LOW"
        priority = "P4"
    elif q_status == "QUANTUM-RESISTANT":
        risk_score = 25
        risk_tier = "LOW"
        priority = "P3"
    else:  # Quantum Vulnerable / Legacy Broken
        if exposure == "external_facing" and purpose in ["key_establishment", "digital_signature"]:
            risk_score = 95
            risk_tier = "CRITICAL"
            priority = "P1"
        elif exposure == "external_facing":
            risk_score = 80
            risk_tier = "HIGH"
            priority = "P1"
        elif purpose in ["key_establishment", "digital_signature"]:
            risk_score = 75
            risk_tier = "HIGH"
            priority = "P2"
        else:
            risk_score = 50
            risk_tier = "MEDIUM"
            priority = "P3"

    return {
        "purpose": purpose,
        "exposure": exposure,
        "quantum_status": q_status,
        "risk_score": risk_score,
        "Risk Tier": risk_tier,
        "Priority": priority,
        "x_shelf_life": x_shelf_life,
        "y_migration_time": y_migration_time,
        "data_sensitivity": data_sensitivity,
        "business_criticality": business_criticality
    }


def evaluate_asset_risk(
    algorithm: str,
    purpose: str,
    quantum_status: str,
    classical_status: str,
    x_shelf_life: float,
    y_migration_time: float,
    z_crqc_horizon: float,
    data_sensitivity: int = 3,       # Scale 1 (Public) to 5 (Highly Sensitive)
    business_criticality: int = 3,   # Scale 1 (Non-critical) to 5 (Mission-critical)
    method: str = "Standard Mosca Inequality (X + Y > Z)"
):
    """
    Tuned & Calibrated Cryptographic Asset Risk Evaluation Engine (PS-164).
    Supports Standard Mosca, Sensitivity-Weighted QPS, and Data Shelf-Life Ratio. [cite: 1]
    """
    total_exposure = round(x_shelf_life + y_migration_time, 2)
    z_safe = max(1.0, float(z_crqc_horizon))
    margin = round(total_exposure - z_safe, 2)
    exposure_ratio = round(total_exposure / z_safe, 2)

    is_classical_broken = classical_status in ["BROKEN", "DEPRECATED"]
    is_pqc = quantum_status in ["PQC-STANDARDIZED", "QUANTUM-RESISTANT"] and not is_classical_broken

    if is_pqc:
        return {
            "tier": "LOW",
            "priority": "P3",
            "action": "Quantum-Resistant / No Action Needed",
            "X": x_shelf_life,
            "Y": y_migration_time,
            "Z": z_crqc_horizon,
            "exposure_years": 0.0,
            "metric_value": 0.0,
            "metric_label": "Safe (PQC)",
            "explanation": f"{algorithm} ({purpose}) is quantum-resistant and compliant with NIST standards."
        }

    # -------------------------------------------------------------------------
    # MODEL 1: Standard Mosca Inequality (X + Y > Z) — Tuned Thresholds
    # -------------------------------------------------------------------------
    if method == "Standard Mosca Inequality (X + Y > Z)":
        if is_classical_broken:
            tier = "CRITICAL"
            priority = "P0"
            action = f"Immediate Remediation: Classically broken/deprecated ({classical_status})"
        elif total_exposure > z_safe:
            tier = "CRITICAL"
            priority = "P0" if business_criticality >= 4 else "P1"
            action = f"Critical: Data Exposure ({total_exposure} yrs) exceeds CRQC Horizon ({z_safe} yrs)"
        elif total_exposure >= (z_safe * 0.75):
            tier = "HIGH"
            priority = "P1"
            action = f"High Risk: Approaching CRQC Horizon (Margin: {margin} yrs)"
        elif total_exposure >= (z_safe * 0.40):
            tier = "MEDIUM"
            priority = "P2"
            action = "Medium Risk: Schedule Planned PQC Roadmap Review"
        else:
            tier = "LOW"
            priority = "P3"
            action = "Low Risk: Long-Term Horizon Monitor"

        explanation = (
            f"Mosca check: X ({x_shelf_life} yrs) + Y ({y_migration_time} yrs) = {total_exposure} yrs vs "
            f"Z ({z_safe} yrs horizon). Margin = {margin} yrs (Ratio: {exposure_ratio}x)."
        )

        return {
            "tier": tier,
            "priority": priority,
            "action": action,
            "X": x_shelf_life,
            "Y": y_migration_time,
            "Z": z_crqc_horizon,
            "exposure_years": total_exposure,
            "metric_value": total_exposure,
            "metric_label": "Exposure (X+Y)",
            "explanation": explanation
        }

    # -------------------------------------------------------------------------
    # MODEL 2: Sensitivity-Weighted Quantum Exposure Score (QES) — Tuned
    # -------------------------------------------------------------------------
    elif method == "Sensitivity-Weighted QPS (W × max(1, (X+Y)/Z))":
        w_factor = float(data_sensitivity)
        if is_classical_broken:
            qes = round(w_factor * 5.0, 2)
        else:
            ratio = max(1.0, exposure_ratio)
            qes = round(w_factor * ratio, 2)

        if qes >= 6.0:
            tier = "CRITICAL"
            priority = "P0"
            action = f"Urgent PQC Migration Required (Weighted QES: {qes})"
        elif qes >= 3.5:
            tier = "HIGH"
            priority = "P1"
            action = f"Plan PQC Migration Soon (Weighted QES: {qes})"
        elif qes >= 1.8:
            tier = "MEDIUM"
            priority = "P2"
            action = f"Schedule Roadmap Review (Weighted QES: {qes})"
        else:
            tier = "LOW"
            priority = "P3"
            action = f"Monitor & Inventory (Weighted QES: {qes})"

        explanation = (
            f"Sensitivity-Weighted QES: W ({w_factor}) × max(1, {exposure_ratio}) = {qes}. "
            f"Data Sensitivity = {data_sensitivity}/5, Business Criticality = {business_criticality}/5."
        )

        return {
            "tier": tier,
            "priority": priority,
            "action": action,
            "X": x_shelf_life,
            "Y": y_migration_time,
            "Z": z_crqc_horizon,
            "exposure_years": total_exposure,
            "metric_value": qes,
            "metric_label": "QES Score",
            "explanation": explanation
        }

    # -------------------------------------------------------------------------
    # MODEL 3: Data Shelf-Life Exposure Ratio (X / Z) — Tuned
    # -------------------------------------------------------------------------
    elif method == "Data Shelf-Life Ratio (X / Z)":
        shelf_ratio = round(x_shelf_life / z_safe, 2)
        if is_classical_broken or shelf_ratio >= 1.2:
            tier = "CRITICAL"
            priority = "P0"
            action = f"Critical Shelf-Life Exposure (Ratio: {shelf_ratio}x beyond CRQC)"
        elif shelf_ratio >= 0.8:
            tier = "HIGH"
            priority = "P1"
            action = f"High Shelf-Life Exposure (Ratio: {shelf_ratio}x)"
        elif shelf_ratio >= 0.4:
            tier = "MEDIUM"
            priority = "P2"
            action = f"Medium Shelf-Life Exposure (Ratio: {shelf_ratio}x)"
        else:
            tier = "LOW"
            priority = "P3"
            action = f"Low Shelf-Life Exposure (Ratio: {shelf_ratio}x)"

        explanation = (
            f"Shelf-Life Ratio: X ({x_shelf_life} yrs) / Z ({z_safe} yrs) = {shelf_ratio}x. "
            f"Measures how long encrypted data must remain confidential post-CRQC."
        )

        return {
            "tier": tier,
            "priority": priority,
            "action": action,
            "X": x_shelf_life,
            "Y": y_migration_time,
            "Z": z_crqc_horizon,
            "exposure_years": total_exposure,
            "metric_value": shelf_ratio,
            "metric_label": "Shelf-Life Ratio (X/Z)",
            "explanation": explanation
        }

    return {
        "tier": "LOW",
        "priority": "P3",
        "action": "Review Implementation",
        "X": x_shelf_life,
        "Y": y_migration_time,
        "Z": z_crqc_horizon,
        "exposure_years": total_exposure,
        "metric_value": 0.0,
        "metric_label": "N/A",
        "explanation": "Default low risk evaluation."
    }