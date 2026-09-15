from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List
from collections import Counter
from datetime import datetime
import time

from core.asset_identity import deduplicate_assets
from core.models import CryptoAsset

from scanners.source_adapter import scan_source_file_normalized
from scanners.binary_adapter import scan_binary_file_normalized
from scanners.certificate_adapter import scan_certificate_normalized
from scanners.dependency_adapter import scan_dependency_file_normalized
from scanners.config_adapter import scan_config_file_normalized
from scanners.protocol_adapter import scan_protocol_file_normalized
from scanners.container_adapter import (
    scan_container_directory_normalized,
)

# =========================================================
# File categories
# =========================================================

CERTIFICATE_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
}

BINARY_EXTENSIONS = {
    ".jar",
    ".class",
    ".so",
    ".dll",
    ".exe",
    ".bin",
}

DEPENDENCY_FILES = {
    "requirements.txt",
    "pipfile",
    "package.json",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "cargo.toml",
}

CONFIG_EXTENSIONS = {
    ".conf",
    ".config",
    ".ini",
    ".properties",
}


# =========================================================
# Directories excluded from scanning
# =========================================================

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    "dist",
}


# =========================================================
# Safety limits
# =========================================================

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


# =========================================================
# Scan result model
# =========================================================

@dataclass
class ScanResult:
    """
    Complete result of a repository scan.
    """

    repository: str

    started_at: str

    completed_at: str = ""

    duration_seconds: float = 0.0

    files_discovered: int = 0

    files_scanned: int = 0

    files_skipped: int = 0

    files_failed: int = 0

    assets_found: int = 0

    assets: List[CryptoAsset] = field(
        default_factory=list
    )

    skipped_files: List[str] = field(
        default_factory=list
    )

    errors: List[str] = field(
        default_factory=list
    )

    file_types: Counter = field(
        default_factory=Counter
    )

    asset_types: Counter = field(
        default_factory=Counter
    )

    quantum_status: Counter = field(
        default_factory=Counter
    )

    classical_status: Counter = field(
        default_factory=Counter
    )


# =========================================================
# File classification
# =========================================================

def classify_file(path: Path) -> str:
    """
    Determine which scanner should handle a file.
    """

    filename = path.name.lower()
    suffix = path.suffix.lower()

    if suffix in CERTIFICATE_EXTENSIONS:
        return "certificate"

    if suffix in BINARY_EXTENSIONS:
        return "binary"

    if filename in DEPENDENCY_FILES:
        return "dependency"

    if suffix in CONFIG_EXTENSIONS:
        return "configuration"

    if "nginx" in filename or "sshd" in filename:
        return "configuration"

    return "source"


# =========================================================
# File reading
# =========================================================

def read_file(path: Path):
    """
    Read file contents while respecting the maximum
    file-size safety limit.
    """

    try:
        size = path.stat().st_size

        if size > MAX_FILE_SIZE:
            return None

        return path.read_bytes()

    except (OSError, PermissionError):
        return None


# =========================================================
# Scan one file
# =========================================================

def scan_discovered_file(
    path: Path,
    root_path: Path,
) -> List[CryptoAsset]:
    """
    Scan one discovered file using the appropriate
    normalized scanner.
    """

    content = read_file(path)

    if content is None:
        return []

    try:
        relative_path = str(
            path.relative_to(root_path)
        )

    except ValueError:
        relative_path = str(path)

    category = classify_file(path)

    # -----------------------------------------------------
    # Certificate
    # -----------------------------------------------------

    if category == "certificate":

        return scan_certificate_normalized(
            relative_path,
            content,
        )

    # -----------------------------------------------------
    # Binary
    # -----------------------------------------------------

    if category == "binary":

        return scan_binary_file_normalized(
            relative_path,
            content,
        )

    # -----------------------------------------------------
    # Text conversion
    # -----------------------------------------------------

    content_str = content.decode(
        "utf-8",
        errors="ignore",
    )

    # -----------------------------------------------------
    # Dependencies
    # -----------------------------------------------------

    if category == "dependency":

        return scan_dependency_file_normalized(
            relative_path,
            content_str,
        )

    # -----------------------------------------------------
    # Configuration + Protocol
    # -----------------------------------------------------

    if category == "configuration":

        assets = []

        assets.extend(
            scan_config_file_normalized(
                relative_path,
                content_str,
            )
        )

        assets.extend(
            scan_protocol_file_normalized(
                relative_path,
                content_str,
            )
        )

        return assets

    # -----------------------------------------------------
    # Source
    # -----------------------------------------------------

    return scan_source_file_normalized(
        relative_path,
        content_str,
    )


# =========================================================
# Recursive repository scan
# =========================================================

def scan_repository(
    root_directory: str,
) -> ScanResult:
    """
    Recursively scan a repository and return a normalized,
    deduplicated CryptoAsset inventory.
    """

    root_path = Path(
        root_directory
    ).expanduser().resolve()

    if not root_path.exists():

        raise FileNotFoundError(
            f"Directory does not exist: {root_path}"
        )

    if not root_path.is_dir():

        raise NotADirectoryError(
            f"Expected a directory: {root_path}"
        )

    started_time = time.perf_counter()

    started_at = datetime.now().isoformat()

    result = ScanResult(
        repository=str(root_path),
        started_at=started_at,
    )

    # -----------------------------------------------------
    # Discover files
    # -----------------------------------------------------

    for path in root_path.rglob("*"):

        if path.is_dir():
            continue

        # -------------------------------------------------
        # Ignore excluded directories
        # -------------------------------------------------

        if any(
            ignored in path.parts
            for ignored in IGNORED_DIRECTORIES
        ):

            result.files_skipped += 1

            result.skipped_files.append(
                str(
                    path.relative_to(root_path)
                )
            )

            continue

        # -------------------------------------------------
        # Register discovered file
        # -------------------------------------------------

        result.files_discovered += 1

        category = classify_file(path)

        result.file_types[category] += 1

        # -------------------------------------------------
        # Scan file
        # -------------------------------------------------

        try:

            assets = scan_discovered_file(
                path,
                root_path,
            )

            result.files_scanned += 1

            result.assets.extend(assets)

        except Exception as exc:

            result.files_failed += 1

            result.errors.append(
                f"{path}: {exc}"
            )

    # =====================================================
    # Deduplicate complete repository inventory
    # =====================================================

    result.assets = deduplicate_assets(
        result.assets
    )

    # -----------------------------------------------------
    # Calculate final statistics
    # -----------------------------------------------------

    result.assets_found = len(
        result.assets
    )

    # Clear counters in case this function is reused
    # or statistics are recalculated later.
    result.asset_types.clear()

    result.quantum_status.clear()

    result.classical_status.clear()

    # -----------------------------------------------------
    # Rebuild statistics from UNIQUE assets
    # -----------------------------------------------------

    for asset in result.assets:

        result.asset_types[
            asset.asset_type.value
        ] += 1

        result.quantum_status[
            asset.quantum.quantum_status.value
        ] += 1

        result.classical_status[
            asset.quantum.classical_status.value
        ] += 1

    # -----------------------------------------------------
    # Completion metadata
    # -----------------------------------------------------

    result.completed_at = (
        datetime.now().isoformat()
    )

    result.duration_seconds = (
        time.perf_counter()
        - started_time
    )

    return result
# =========================================================
# Container filesystem scan
# =========================================================

def scan_container(
    root_directory: str,
) -> ScanResult:
    """
    Scan an extracted container filesystem.

    Container findings are normalized into the same
    CryptoAsset model used by repository scanning.
    """

    root_path = (
        Path(root_directory)
        .expanduser()
        .resolve()
    )

    if not root_path.exists():

        raise FileNotFoundError(
            f"Container directory does not exist: {root_path}"
        )

    if not root_path.is_dir():

        raise NotADirectoryError(
            f"Expected a container filesystem directory: {root_path}"
        )

    started_time = time.perf_counter()

    started_at = datetime.now().isoformat()

    result = ScanResult(
        repository=str(root_path),
        started_at=started_at,
    )

    # -----------------------------------------------------
    # Count files
    # -----------------------------------------------------

    for path in root_path.rglob("*"):

        if path.is_dir():
            continue

        result.files_discovered += 1

        result.file_types[
            "container"
        ] += 1

    # -----------------------------------------------------
    # Run container scanner
    # -----------------------------------------------------

    try:

        assets = scan_container_directory_normalized(
            str(root_path)
        )

        result.files_scanned = (
            result.files_discovered
        )

        result.assets = (
            deduplicate_assets(
                assets
            )
        )

    except Exception as exc:

        result.files_failed = 1

        result.errors.append(
            f"{root_path}: {exc}"
        )

        result.assets = []

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    result.assets_found = len(
        result.assets
    )

    for asset in result.assets:

        result.asset_types[
            asset.asset_type.value
        ] += 1

        result.quantum_status[
            asset.quantum.quantum_status.value
        ] += 1

        result.classical_status[
            asset.quantum.classical_status.value
        ] += 1

    # -----------------------------------------------------
    # Completion metadata
    # -----------------------------------------------------

    result.completed_at = (
        datetime.now().isoformat()
    )

    result.duration_seconds = (
        time.perf_counter()
        - started_time
    )

    return result