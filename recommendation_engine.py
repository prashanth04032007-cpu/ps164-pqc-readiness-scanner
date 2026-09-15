from __future__ import annotations

from dataclasses import dataclass

from core.enums import (
    ClassicalStatus,
    MigrationStrategy,
    Purpose,
    QuantumStatus,
)
from core.models import CryptoAsset, Recommendation


@dataclass(frozen=True)
class RecommendationProfile:
    recommended_algorithm: str
    recommended_family: str
    migration_strategy: MigrationStrategy
    hybrid_option: str | None
    compatibility: str
    latency_impact: str
    performance_impact: str
    migration_cost: str
    migration_complexity: str
    recommendation_reason: str


class RecommendationEngine:

    def recommend_for_asset(
        self,
        asset: CryptoAsset,
    ) -> Recommendation:

        algorithm = (
            asset.algorithm
            or asset.asset_name
            or ""
        ).upper()

        asset_name = (
            asset.asset_name
            or ""
        ).upper()

        purpose = asset.purpose

        quantum_status = asset.quantum.quantum_status
        classical_status = asset.quantum.classical_status

        # =====================================================
        # 1. CLASSICALLY BROKEN / OBSOLETE CRYPTO
        # =====================================================

        if (
            classical_status == ClassicalStatus.BROKEN
            or algorithm in {
                "RC4",
                "MD5",
                "DES",
            }
            or "3DES" in algorithm
            or "TRIPLE-DES" in algorithm
        ):
            return Recommendation(
                recommended_algorithm="AES-256-GCM",
                recommended_family="AES",
                migration_strategy=MigrationStrategy.REPLACE,
                hybrid_option=None,
                compatibility=(
                    "Widely supported; verify application and "
                    "protocol compatibility."
                ),
                latency_impact="Low",
                performance_impact="Low",
                migration_cost="Low",
                migration_complexity="Low",
                recommendation_reason=(
                    "The current mechanism is classically broken "
                    "or obsolete. Replace it with a modern "
                    "authenticated encryption mechanism such as "
                    "AES-256-GCM."
                ),
            )

        # =====================================================
        # 2. WEAK HASH FUNCTIONS
        # =====================================================

        if (
            algorithm in {"SHA-1", "MD5"}
            or asset_name in {"SHA-1", "MD5"}
        ):
            return Recommendation(
                recommended_algorithm="SHA-256",
                recommended_family="SHA-2",
                migration_strategy=MigrationStrategy.REPLACE,
                hybrid_option=None,
                compatibility=(
                    "Generally widely supported; verify protocol "
                    "and certificate requirements."
                ),
                latency_impact="Low",
                performance_impact="Low",
                migration_cost="Low",
                migration_complexity="Low",
                recommendation_reason=(
                    "The current hash function is deprecated or "
                    "cryptographically weak. Replace it with a "
                    "modern SHA-2 family hash such as SHA-256."
                ),
            )

        # =====================================================
        # 3. LEGACY TLS / SSL
        # =====================================================

        if (
            "TLSV1.0" in asset_name
            or "TLS 1.0" in asset_name
            or "SSLV3" in asset_name
            or "SSLV2" in asset_name
            or "SSL 3" in asset_name
        ):
            return Recommendation(
                recommended_algorithm="TLS 1.3",
                recommended_family="TLS",
                migration_strategy=MigrationStrategy.UPGRADE,
                hybrid_option=None,
                compatibility=(
                    "Requires compatible clients, servers and "
                    "cryptographic libraries."
                ),
                latency_impact="Low",
                performance_impact="Low",
                migration_cost="Low",
                migration_complexity="Medium",
                recommendation_reason=(
                    "The current protocol version is legacy and "
                    "insecure. Upgrade to a modern TLS version, "
                    "preferably TLS 1.3."
                ),
            )

        # =====================================================
        # 4. ALREADY QUANTUM-RESISTANT AND CLASSICALLY SECURE
        # =====================================================

        if  quantum_status == QuantumStatus.RESISTANT:
            return Recommendation(
                recommended_algorithm=asset.algorithm,
                recommended_family=(
                    asset.algorithm_family
                    or "Quantum-resistant cryptography"
                ),
                migration_strategy=MigrationStrategy.RETAIN,
                hybrid_option=None,
                compatibility=(
                    "Retain subject to implementation, key-size, "
                    "protocol and organizational policy checks."
                ),
                latency_impact="None",
                performance_impact="None",
                migration_cost="None",
                migration_complexity="None",
                recommendation_reason=(
                    "The discovered mechanism is currently "
                    "classified as quantum-resistant and "
                    "classically secure. Retain it while verifying "
                    "implementation and policy requirements."
                ),
            )

        # =====================================================
        # 5. PQC ALREADY IN USE
        # =====================================================

        if (
            algorithm.startswith("ML-KEM")
            or algorithm.startswith("KYBER")
            or algorithm.startswith("ML-DSA")
            or algorithm.startswith("DILITHIUM")
            or algorithm.startswith("SLH-DSA")
        ):
            return Recommendation(
                recommended_algorithm=asset.algorithm,
                recommended_family=(
                    asset.algorithm_family
                    or "NIST Post-Quantum Cryptography"
                ),
                migration_strategy=MigrationStrategy.RETAIN,
                hybrid_option=None,
                compatibility=(
                    "Verify implementation against approved "
                    "PQC standards and deployment policy."
                ),
                latency_impact="Implementation dependent",
                performance_impact="Implementation dependent",
                migration_cost="None",
                migration_complexity="Low",
                recommendation_reason=(
                    "A post-quantum cryptographic mechanism was "
                    "detected. Retain it while verifying standards "
                    "compliance and deployment configuration."
                ),
            )

        # =====================================================
        # 6. PUBLIC-KEY DIGITAL SIGNATURES
        # =====================================================

        signature_algorithms = (
            "RSA",
            "ECDSA",
            "DSA",
            "ED25519",
            "ED448",
        )

        if (
            purpose == Purpose.DIGITAL_SIGNATURE
            or algorithm.startswith(signature_algorithms)
            or "SIGNATURE" in asset_name
        ):
            return Recommendation(
                recommended_algorithm="ML-DSA",
                recommended_family=(
                    "Module-Lattice-Based Digital Signature"
                ),
                migration_strategy=MigrationStrategy.HYBRID,
                hybrid_option=(
                    "Classical signature + ML-DSA during transition"
                ),
                compatibility=(
                    "Requires protocol, certificate, library and "
                    "key-management support."
                ),
                latency_impact="Moderate",
                performance_impact="Moderate",
                migration_cost="Medium",
                migration_complexity="Medium",
                recommendation_reason=(
                    "The current public-key signature mechanism is "
                    "vulnerable to quantum attacks. ML-DSA is a "
                    "NIST-standardized PQC digital-signature option. "
                    "A hybrid transition can reduce migration risk "
                    "where protocol support permits."
                ),
            )

        # =====================================================
        # 7. KEY ESTABLISHMENT
        # =====================================================

        key_establishment_algorithms = (
            "DH",
            "ECDH",
            "DIFFIE-HELLMAN",
        )

        if (
            purpose == Purpose.KEY_ESTABLISHMENT
            or algorithm.startswith(key_establishment_algorithms)
            or "DIFFIE-HELLMAN" in asset_name
        ):
            return Recommendation(
                recommended_algorithm="ML-KEM-768",
                recommended_family=(
                    "Module-Lattice-Based "
                    "Key-Encapsulation Mechanism"
                ),
                migration_strategy=MigrationStrategy.HYBRID,
                hybrid_option=(
                    "Classical key establishment + ML-KEM-768"
                ),
                compatibility=(
                    "Requires protocol and cryptographic-library "
                    "support for PQC key establishment."
                ),
                latency_impact="Moderate",
                performance_impact="Moderate",
                migration_cost="Medium",
                migration_complexity="Medium",
                recommendation_reason=(
                    "The current key-establishment mechanism relies "
                    "on classical public-key cryptography vulnerable "
                    "to quantum attacks. ML-KEM is a NIST-standardized "
                    "PQC KEM family. ML-KEM-768 is a practical default "
                    "candidate for migration assessment."
                ),
            )

        # =====================================================
        # 8. OTHER QUANTUM-VULNERABLE ASSETS
        # =====================================================

        if quantum_status == QuantumStatus.VULNERABLE:
            return Recommendation(
                recommended_algorithm="ML-KEM-768 / ML-DSA",
                recommended_family="NIST Post-Quantum Cryptography",
                migration_strategy=MigrationStrategy.REVIEW,
                hybrid_option=(
                    "Use an appropriate classical + PQC hybrid"
                ),
                compatibility=(
                    "Requires assessment of the asset's exact "
                    "cryptographic purpose and protocol."
                ),
                latency_impact="Moderate",
                performance_impact="Moderate",
                migration_cost="Medium",
                migration_complexity="Medium",
                recommendation_reason=(
                    "The asset is vulnerable to quantum attacks, "
                    "but its exact cryptographic purpose must be "
                    "confirmed before selecting the appropriate "
                    "PQC replacement."
                ),
            )

        # =====================================================
        # 9. UNKNOWN
        # =====================================================

        return Recommendation(
            recommended_algorithm=None,
            recommended_family=None,
            migration_strategy=MigrationStrategy.REVIEW,
            hybrid_option=None,
            compatibility="Requires manual cryptographic assessment.",
            latency_impact="Unknown",
            performance_impact="Unknown",
            migration_cost="Unknown",
            migration_complexity="Unknown",
            recommendation_reason=(
                "The scanner could not determine a sufficiently "
                "specific migration target. Manual review is required."
            ),
        )

    def recommend_assets(
        self,
        assets,
    ) -> list[CryptoAsset]:

        asset_list = list(assets)

        for asset in asset_list:
            asset.recommendation = self.recommend_for_asset(asset)

        return asset_list


def recommend_asset(
    asset: CryptoAsset,
) -> CryptoAsset:

    engine = RecommendationEngine()

    asset.recommendation = engine.recommend_for_asset(asset)

    return asset


def recommend_assets(
    assets,
) -> list[CryptoAsset]:

    return RecommendationEngine().recommend_assets(assets)
