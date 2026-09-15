from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from core.enums import (
    ClassicalStatus,
    Priority,
    QuantumStatus,
    RiskTier,
)
from core.models import CryptoAsset


@dataclass
class MoscaResult:
    x_data_lifetime: float
    y_migration_time: float
    z_crqc_horizon: float
    margin: float
    ratio: float
    result: str


@dataclass
class RiskSummary:
    total_assets: int = 0

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    unknown: int = 0

    p0: int = 0
    p1: int = 0
    p2: int = 0
    p3: int = 0
    p4: int = 0

    quantum_vulnerable: int = 0
    quantum_resistant: int = 0
    quantum_unknown: int = 0

    classical_broken: int = 0
    classical_weak: int = 0
    classical_secure: int = 0
    classical_unknown: int = 0

    mosca_action_required: int = 0
    mosca_plan_migration: int = 0
    mosca_outside_window: int = 0

    average_risk_score: float = 0.0
    maximum_risk_score: float = 0.0


class RiskEngine:
    """
    Risk assessment engine for discovered cryptographic assets.

    The scoring model is a heuristic intended for prioritization.
    It is not a prediction of the exact date of a cryptographically
    relevant quantum computer.
    """

    DEFAULT_CRQC_HORIZON = 10.0

    def calculate_mosca(
        self,
        data_lifetime: float,
        migration_time: float,
        crqc_horizon: float,
    ) -> MoscaResult:

        margin = (
            data_lifetime
            + migration_time
            - crqc_horizon
        )

        ratio = (
            (data_lifetime + migration_time)
            / crqc_horizon
            if crqc_horizon > 0
            else 0.0
        )

        if margin >= 0:
            result = "ACTION_REQUIRED"
        elif margin >= -2:
            result = "PLAN_MIGRATION"
        else:
            result = "OUTSIDE_CURRENT_WINDOW"

        return MoscaResult(
            x_data_lifetime=data_lifetime,
            y_migration_time=migration_time,
            z_crqc_horizon=crqc_horizon,
            margin=margin,
            ratio=ratio,
            result=result,
        )

    def quantum_base_score(
        self,
        asset: CryptoAsset,
    ) -> float:

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:
            return 70.0

        if asset.quantum.quantum_status == QuantumStatus.RESISTANT:
            return 10.0

        return 30.0

    def classical_adjustment(
        self,
        asset: CryptoAsset,
    ) -> float:

        status = asset.quantum.classical_status

        if status == ClassicalStatus.BROKEN:
            return 20.0

        if status == ClassicalStatus.WEAK:
            return 10.0

        return 0.0

    def business_adjustment(
        self,
        asset: CryptoAsset,
    ) -> float:

        adjustment = 0.0

        criticality = asset.business.business_criticality
        sensitivity = asset.business.data_sensitivity

        if criticality is not None:
            criticality = max(1, min(5, criticality))

        if sensitivity is not None:
            sensitivity = max(1, min(5, sensitivity))

        quantum_status = asset.quantum.quantum_status

        #
        # Business context amplifies meaningful technical risk.
        #

        if quantum_status == QuantumStatus.VULNERABLE:

            if criticality is not None:
                adjustment += (criticality - 1) * 4

            if sensitivity is not None:
                adjustment += (sensitivity - 1) * 4

        elif quantum_status == QuantumStatus.RESISTANT:

            if criticality is not None:
                adjustment += (criticality - 1) * 1

            if sensitivity is not None:
                adjustment += (sensitivity - 1) * 1

        else:

            if criticality is not None:
                adjustment += (criticality - 1) * 1.5

            if sensitivity is not None:
                adjustment += (sensitivity - 1) * 1.5

        return adjustment

    def mosca_adjustment(
        self,
        mosca: MoscaResult,
        asset: CryptoAsset,
    ) -> float:

        #
        # Mosca strongly influences assets that are actually
        # quantum-vulnerable.
        #

        if asset.quantum.quantum_status != QuantumStatus.VULNERABLE:
            return 0.0

        if mosca.result == "ACTION_REQUIRED":
            return 20.0

        if mosca.result == "PLAN_MIGRATION":
            return 10.0

        return 0.0

    def determine_risk_tier(
        self,
        score: float,
    ) -> RiskTier:

        if score >= 80:
            return RiskTier.CRITICAL

        if score >= 60:
            return RiskTier.HIGH

        if score >= 40:
            return RiskTier.MEDIUM

        if score >= 20:
            return RiskTier.LOW

        return RiskTier.INFORMATIONAL

    def determine_priority(
        self,
        tier: RiskTier,
    ) -> Priority:

        if tier == RiskTier.CRITICAL:
            return Priority.P0

        if tier == RiskTier.HIGH:
            return Priority.P1

        if tier == RiskTier.MEDIUM:
            return Priority.P2

        if tier == RiskTier.LOW:
            return Priority.P3

        return Priority.P4

    def assess_asset(
        self,
        asset: CryptoAsset,
        crqc_horizon: Optional[float] = None,
    ) -> CryptoAsset:

        score = self.quantum_base_score(asset)

        score += self.classical_adjustment(asset)

        score += self.business_adjustment(asset)

        data_lifetime = asset.business.data_lifetime_years
        migration_time = asset.business.migration_time_years

        mosca = None

        if (
            data_lifetime is not None
            and migration_time is not None
        ):

            horizon = (
                crqc_horizon
                if crqc_horizon is not None
                else self.DEFAULT_CRQC_HORIZON
            )

            mosca = self.calculate_mosca(
                data_lifetime,
                migration_time,
                horizon,
            )

            asset.quantum.x_data_lifetime = (
                mosca.x_data_lifetime
            )

            asset.quantum.y_migration_time = (
                mosca.y_migration_time
            )

            asset.quantum.z_crqc_horizon = (
                mosca.z_crqc_horizon
            )

            asset.quantum.mosca_margin = mosca.margin

            asset.quantum.mosca_ratio = mosca.ratio

            asset.quantum.mosca_result = mosca.result

            score += self.mosca_adjustment(
                mosca,
                asset,
            )

        score = max(
            0.0,
            min(100.0, score),
        )

        tier = self.determine_risk_tier(score)

        priority = self.determine_priority(tier)

        risk_factors = []

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:
            risk_factors.append(
                "Quantum-vulnerable cryptography"
            )

        if asset.quantum.classical_status == ClassicalStatus.BROKEN:
            risk_factors.append(
                "Classically broken cryptography"
            )

        elif asset.quantum.classical_status == ClassicalStatus.WEAK:
            risk_factors.append(
                "Classically weak cryptography"
            )

        #
        # Business factors are most meaningful when the
        # cryptographic mechanism itself is quantum-vulnerable.
        #

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:

            if (
                asset.business.business_criticality is not None
                and asset.business.business_criticality >= 4
            ):
                risk_factors.append(
                    "High business criticality"
                )

            if (
                asset.business.data_sensitivity is not None
                and asset.business.data_sensitivity >= 4
            ):
                risk_factors.append(
                    "High data sensitivity"
                )

        if mosca is not None:

            if mosca.result == "ACTION_REQUIRED":
                risk_factors.append(
                    "Mosca inequality indicates action is required"
                )

            elif mosca.result == "PLAN_MIGRATION":
                risk_factors.append(
                    "Mosca inequality indicates migration should be planned"
                )

        explanation_parts = []

        explanation_parts.append(
            f"Risk score is {score:.1f}/100."
        )

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:

            explanation_parts.append(
                "The cryptographic mechanism is vulnerable "
                "to quantum attacks."
            )

        elif asset.quantum.quantum_status == QuantumStatus.RESISTANT:

            explanation_parts.append(
                "The cryptographic mechanism is currently "
                "classified as quantum-resistant."
            )

        else:

            explanation_parts.append(
                "Quantum security status is unknown."
            )

        if asset.quantum.classical_status == ClassicalStatus.BROKEN:

            explanation_parts.append(
                "The mechanism is also classically broken."
            )

        elif asset.quantum.classical_status == ClassicalStatus.WEAK:

            explanation_parts.append(
                "The mechanism has a classical security weakness."
            )

        if mosca is not None:

            explanation_parts.append(
                f"Mosca result: {mosca.result} "
                f"(margin {mosca.margin:.1f})."
            )

        asset.risk.risk_score = score
        asset.risk.risk_tier = tier
        asset.risk.priority = priority
        asset.risk.risk_factors = risk_factors
        asset.risk.risk_explanation = " ".join(
            explanation_parts
        )

        return asset

    def assess_assets(
        self,
        assets: Iterable[CryptoAsset],
        crqc_horizon: Optional[float] = None,
    ) -> list[CryptoAsset]:

        return [
            self.assess_asset(
                asset,
                crqc_horizon,
            )
            for asset in assets
        ]

    def summarize(
        self,
        assets: Iterable[CryptoAsset],
    ) -> RiskSummary:

        assets = list(assets)

        summary = RiskSummary(
            total_assets=len(assets)
        )

        scores = []

        for asset in assets:

            risk_score = asset.risk.risk_score

            if risk_score is not None:

                scores.append(risk_score)

                summary.maximum_risk_score = max(
                    summary.maximum_risk_score,
                    risk_score,
                )

            tier = asset.risk.risk_tier

            if tier == RiskTier.CRITICAL:
                summary.critical += 1

            elif tier == RiskTier.HIGH:
                summary.high += 1

            elif tier == RiskTier.MEDIUM:
                summary.medium += 1

            elif tier == RiskTier.LOW:
                summary.low += 1

            elif tier == RiskTier.INFORMATIONAL:
                summary.informational += 1

            else:
                summary.unknown += 1

            priority = asset.risk.priority

            if priority == Priority.P0:
                summary.p0 += 1

            elif priority == Priority.P1:
                summary.p1 += 1

            elif priority == Priority.P2:
                summary.p2 += 1

            elif priority == Priority.P3:
                summary.p3 += 1

            elif priority == Priority.P4:
                summary.p4 += 1

            quantum_status = asset.quantum.quantum_status

            if quantum_status == QuantumStatus.VULNERABLE:
                summary.quantum_vulnerable += 1

            elif quantum_status == QuantumStatus.RESISTANT:
                summary.quantum_resistant += 1

            else:
                summary.quantum_unknown += 1

            classical_status = asset.quantum.classical_status

            if classical_status == ClassicalStatus.BROKEN:
                summary.classical_broken += 1

            elif classical_status == ClassicalStatus.WEAK:
                summary.classical_weak += 1

            elif classical_status == ClassicalStatus.SECURE:
                summary.classical_secure += 1

            else:
                summary.classical_unknown += 1

            mosca_result = asset.quantum.mosca_result

            if mosca_result == "ACTION_REQUIRED":
                summary.mosca_action_required += 1

            elif mosca_result == "PLAN_MIGRATION":
                summary.mosca_plan_migration += 1

            elif mosca_result == "OUTSIDE_CURRENT_WINDOW":
                summary.mosca_outside_window += 1

        if scores:

            summary.average_risk_score = (
                sum(scores) / len(scores)
            )

        return summary


def assess_asset(
    asset: CryptoAsset,
    crqc_horizon: Optional[float] = None,
) -> CryptoAsset:

    return RiskEngine().assess_asset(
        asset,
        crqc_horizon,
    )


def assess_assets(
    assets: Iterable[CryptoAsset],
    crqc_horizon: Optional[float] = None,
) -> list[CryptoAsset]:

    return RiskEngine().assess_assets(
        assets,
        crqc_horizon,
    )


def summarize_risks(
    assets: Iterable[CryptoAsset],
) -> RiskSummary:

    return RiskEngine().summarize(assets)
