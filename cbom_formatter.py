from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from core.models import CryptoAsset


def _serialize(value: Any) -> Any:
    """
    Convert dataclasses, enums, lists and dictionaries into
    JSON-serializable Python objects.
    """
    if isinstance(value, Enum):
        return value.value

    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]

    return value


def asset_to_cbom_component(asset: CryptoAsset) -> dict[str, Any]:
    """
    Convert one CryptoAsset into a CBOM component.
    """

    component = asset.component
    evidence = asset.evidence
    business = asset.business
    quantum = asset.quantum
    risk = asset.risk
    recommendation = asset.recommendation

    properties = {
        "asset_id": asset.asset_id,
        "asset_status": asset.asset_status,

        "algorithm": asset.algorithm,
        "algorithm_family": asset.algorithm_family,
        "algorithm_type": asset.algorithm_type,
        "variant": asset.variant,
        "key_size": asset.key_size,
        "curve": asset.curve,
        "mode": asset.mode,
        "padding": asset.padding,
        "hash_algorithm": asset.hash_algorithm,

        "protocol": asset.protocol,
        "protocol_version": asset.protocol_version,

        "purpose": _serialize(asset.purpose),

        "quantum_status": _serialize(quantum.quantum_status),
        "classical_status": _serialize(quantum.classical_status),
        "harvest_now_decrypt_later": quantum.harvest_now_decrypt_later,
        "quantum_attack_type": quantum.quantum_attack_type,
        "pqc_standard": quantum.pqc_standard,
        "pqc_readiness": quantum.pqc_readiness,

        "mosca": {
            "data_lifetime_years": quantum.x_data_lifetime,
            "migration_time_years": quantum.y_migration_time,
            "crqc_horizon_years": quantum.z_crqc_horizon,
            "margin": quantum.mosca_margin,
            "ratio": quantum.mosca_ratio,
            "result": quantum.mosca_result,
        },

        "risk": {
            "score": risk.risk_score,
            "tier": _serialize(risk.risk_tier),
            "priority": _serialize(risk.priority),
            "factors": list(risk.risk_factors),
            "explanation": risk.risk_explanation,
        },

        "recommendation": {
            "recommended_algorithm": recommendation.recommended_algorithm,
            "recommended_family": recommendation.recommended_family,
            "migration_strategy": _serialize(
                recommendation.migration_strategy
            ),
            "hybrid_option": recommendation.hybrid_option,
            "compatibility": recommendation.compatibility,
            "latency_impact": recommendation.latency_impact,
            "performance_impact": recommendation.performance_impact,
            "migration_cost": recommendation.migration_cost,
            "migration_complexity": recommendation.migration_complexity,
            "reason": recommendation.recommendation_reason,
        },

        "component": {
            "application_name": component.application_name,
            "component_name": component.component_name,
            "library_name": component.library_name,
            "library_version": component.library_version,
            "binary_name": component.binary_name,
            "binary_version": component.binary_version,
            "container_name": component.container_name,
            "container_digest": component.container_digest,
            "environment": component.environment,
        },

        "evidence": {
            "source_type": evidence.source_type if evidence else None,
            "source_path": evidence.source_path if evidence else None,
            "line_start": evidence.line_start if evidence else None,
            "line_end": evidence.line_end if evidence else None,
            "evidence_text": evidence.evidence_text if evidence else None,
            "detection_method": (
                _serialize(evidence.detection_method)
                if evidence
                else None
            ),
            "confidence": evidence.confidence if evidence else None,
        },

        "business_context": {
            "data_sensitivity": business.data_sensitivity,
            "business_criticality": business.business_criticality,
            "data_lifetime_years": business.data_lifetime_years,
            "migration_time_years": business.migration_time_years,
            "internet_exposure": business.internet_exposure,
        },
    }

    # Remove empty values from the component while retaining
    # the core analytical fields.
    properties = {
        key: value
        for key, value in properties.items()
        if value is not None
    }

    return {
        "type": "cryptographic-asset",
        "name": asset.asset_name,
        "bom-ref": asset.asset_id,
        "properties": properties,
    }


def assets_to_cbom(
    assets: Iterable[CryptoAsset],
    source_name: str = "PQC Readiness Scanner",
) -> dict[str, Any]:
    """
    Create a complete CBOM document from CryptoAsset objects.

    The structure follows a CycloneDX-inspired BOM structure while
    preserving PQC-specific analytics required by PS-164.
    """

    asset_list = list(assets)

    components = [
        asset_to_cbom_component(asset)
        for asset in asset_list
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            f"urn:uuid:pqc-scanner-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        ),
        "version": 1,

        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "PQC Readiness Scanner",
                    "name": "PQC Readiness Scanner",
                    "version": "0.1.0",
                }
            ],
            "source": source_name,
        },

        "properties": {
            "cbom_type": "cryptographic-bill-of-materials",
            "pqc_analysis": True,
            "risk_analysis": True,
            "mosca_analysis": True,
            "recommendation_analysis": True,
            "asset_count": len(asset_list),
        },

        "components": components,
    }


def export_cbom(
    assets: Iterable[CryptoAsset],
    output_path: str | Path,
    source_name: str = "PQC Readiness Scanner",
) -> dict[str, Any]:
    """
    Generate and save CBOM JSON.
    """

    cbom = assets_to_cbom(
        assets,
        source_name=source_name,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(
            cbom,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return cbom


def cbom_to_json(
    assets: Iterable[CryptoAsset],
    source_name: str = "PQC Readiness Scanner",
) -> str:
    """
    Return CBOM as formatted JSON text.
    """

    cbom = assets_to_cbom(
        assets,
        source_name=source_name,
    )

    return json.dumps(
        cbom,
        indent=2,
        ensure_ascii=False,
    )
