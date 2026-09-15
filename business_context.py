from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from core.models import BusinessContext, CryptoAsset


@dataclass
class BusinessProfile:
    """
    Default business context for a group of assets.

    Values are analyst-provided or organization-provided.
    They are not inferred automatically from the cryptographic
    algorithm itself.
    """

    data_sensitivity: Optional[int] = None
    business_criticality: Optional[int] = None
    data_lifetime_years: Optional[float] = None
    migration_time_years: Optional[float] = None
    internet_exposure: Optional[str] = None


class BusinessContextEngine:
    """
    Applies business context to discovered cryptographic assets.

    This separates technical discovery from business-risk information.
    """

    def validate_sensitivity(
        self,
        value: Optional[int],
    ) -> Optional[int]:

        if value is None:
            return None

        if not 1 <= value <= 5:
            raise ValueError(
                "data_sensitivity must be between 1 and 5"
            )

        return value

    def validate_criticality(
        self,
        value: Optional[int],
    ) -> Optional[int]:

        if value is None:
            return None

        if not 1 <= value <= 5:
            raise ValueError(
                "business_criticality must be between 1 and 5"
            )

        return value

    def validate_years(
        self,
        value: Optional[float],
        field_name: str,
    ) -> Optional[float]:

        if value is None:
            return None

        if value < 0:
            raise ValueError(
                f"{field_name} cannot be negative"
            )

        return float(value)

    def validate_profile(
        self,
        profile: BusinessProfile,
    ) -> BusinessProfile:

        self.validate_sensitivity(
            profile.data_sensitivity
        )

        self.validate_criticality(
            profile.business_criticality
        )

        self.validate_years(
            profile.data_lifetime_years,
            "data_lifetime_years",
        )

        self.validate_years(
            profile.migration_time_years,
            "migration_time_years",
        )

        return profile

    def apply_profile(
        self,
        asset: CryptoAsset,
        profile: BusinessProfile,
    ) -> CryptoAsset:

        self.validate_profile(profile)

        asset.business = BusinessContext(
            data_sensitivity=profile.data_sensitivity,
            business_criticality=profile.business_criticality,
            data_lifetime_years=profile.data_lifetime_years,
            migration_time_years=profile.migration_time_years,
            internet_exposure=profile.internet_exposure,
        )

        return asset

    def apply_profiles(
        self,
        assets: Iterable[CryptoAsset],
        profile: BusinessProfile,
    ) -> list[CryptoAsset]:

        return [
            self.apply_profile(asset, profile)
            for asset in assets
        ]


def apply_business_profile(
    asset: CryptoAsset,
    profile: BusinessProfile,
) -> CryptoAsset:

    return BusinessContextEngine().apply_profile(
        asset,
        profile,
    )


def apply_business_profiles(
    assets: Iterable[CryptoAsset],
    profile: BusinessProfile,
) -> list[CryptoAsset]:

    return BusinessContextEngine().apply_profiles(
        assets,
        profile,
    )
