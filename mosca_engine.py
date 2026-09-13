def evaluate_asset_risk(quantum_status, x_shelf_life, y_migration_time, z_crqc_arrival):
    total_exposure = x_shelf_life + y_migration_time
    
    if quantum_status == "Quantum-Safe":
        return {
            "tier": "LOW",
            "action": "Quantum-Resistant / No Action Needed",
            "exposure_years": total_exposure
        }
    
    elif quantum_status == "Legacy-Broken":
        return {
            "tier": "HIGH",
            "action": "Migrate Classically (Insecure Mode/Hash)",
            "exposure_years": total_exposure
        }
        
    elif quantum_status == "Vulnerable":
        if total_exposure > z_crqc_arrival:
            return {
                "tier": "CRITICAL",
                "action": "Urgent PQC Migration Required (X+Y > Z)",
                "exposure_years": total_exposure
            }
        elif total_exposure == z_crqc_arrival:
            return {
                "tier": "HIGH",
                "action": "Plan PQC Migration Now (X+Y = Z)",
                "exposure_years": total_exposure
            }
        else:
            return {
                "tier": "MEDIUM",
                "action": "Monitor & Inventory (X+Y < Z)",
                "exposure_years": total_exposure
            }
            
    return {
        "tier": "LOW",
        "action": "Review Implementation",
        "exposure_years": total_exposure
    }