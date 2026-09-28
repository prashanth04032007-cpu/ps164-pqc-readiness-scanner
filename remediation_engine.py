from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from core.enums import (
    ClassicalStatus,
    Priority,
    QuantumStatus,
)
from core.models import CryptoAsset


@dataclass
class RemediationItem:
    rank: int
    asset: CryptoAsset
    priority: Priority
    risk_score: float
    reason: str


class RemediationEngine:
    """
    Converts assessed crypto assets into an ordered remediation queue.

    The queue helps organizations determine which assets should
    receive attention first after discovery and risk assessment.
    """

    PRIORITY_ORDER = {
        Priority.P0: 0,
        Priority.P1: 1,
        Priority.P2: 2,
        Priority.P3: 3,
        Priority.P4: 4,
    }

    def calculate_sort_key(
        self,
        asset: CryptoAsset,
    ) -> tuple:

        priority = asset.risk.priority

        priority_rank = self.PRIORITY_ORDER.get(
            priority,
            99,
        )

        risk_score = (
            asset.risk.risk_score
            if asset.risk.risk_score is not None
            else 0.0
        )

        quantum_vulnerable = (
            1
            if asset.quantum.quantum_status
            == QuantumStatus.VULNERABLE
            else 0
        )

        classical_broken = (
            1
            if asset.quantum.classical_status
            == ClassicalStatus.BROKEN
            else 0
        )

        classical_weak = (
            1
            if asset.quantum.classical_status
            == ClassicalStatus.WEAK
            else 0
        )

        business_criticality = (
            asset.business.business_criticality
            if asset.business.business_criticality is not None
            else 0
        )

        data_sensitivity = (
            asset.business.data_sensitivity
            if asset.business.data_sensitivity is not None
            else 0
        )

        return (
            priority_rank,
            -risk_score,
            -quantum_vulnerable,
            -classical_broken,
            -classical_weak,
            -business_criticality,
            -data_sensitivity,
        )

    def build_reason(
        self,
        asset: CryptoAsset,
    ) -> str:

        reasons = []

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:

            reasons.append(
                "quantum-vulnerable cryptography"
            )

        if asset.quantum.classical_status == ClassicalStatus.BROKEN:

            reasons.append(
                "classically broken cryptography"
            )

        elif asset.quantum.classical_status == ClassicalStatus.WEAK:

            reasons.append(
                "classically weak cryptography"
            )

        #
        # Business factors are included in the migration reason
        # when the asset is actually quantum-vulnerable.
        #

        if asset.quantum.quantum_status == QuantumStatus.VULNERABLE:

            if (
                asset.business.business_criticality is not None
                and asset.business.business_criticality >= 4
            ):
                reasons.append(
                    "high business criticality"
                )

            if (
                asset.business.data_sensitivity is not None
                and asset.business.data_sensitivity >= 4
            ):
                reasons.append(
                    "high data sensitivity"
                )

        if asset.quantum.mosca_result == "ACTION_REQUIRED":

            reasons.append(
                "Mosca assessment requires action"
            )

        elif asset.quantum.mosca_result == "PLAN_MIGRATION":

            reasons.append(
                "Mosca assessment indicates migration planning"
            )

        if not reasons:

            reasons.append(
                "no immediate high-risk factor identified"
            )

        return "; ".join(reasons)

    def prioritize(
        self,
        assets: Iterable[CryptoAsset],
    ) -> list[RemediationItem]:

        assets = list(assets)

        sorted_assets = sorted(
            assets,
            key=self.calculate_sort_key,
        )

        queue = []

        for index, asset in enumerate(
            sorted_assets,
            start=1,
        ):

            priority = asset.risk.priority

            if priority is None:
                priority = Priority.P4

            score = (
                asset.risk.risk_score
                if asset.risk.risk_score is not None
                else 0.0
            )

            queue.append(
                RemediationItem(
                    rank=index,
                    asset=asset,
                    priority=priority,
                    risk_score=score,
                    reason=self.build_reason(asset),
                )
            )

        return queue


def prioritize_assets(
    assets: Iterable[CryptoAsset],
) -> list[RemediationItem]:

    return RemediationEngine().prioritize(
        assets
    )
