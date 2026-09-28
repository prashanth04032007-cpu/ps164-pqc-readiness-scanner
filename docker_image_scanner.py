import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from container_scanner import scan_container_image


DOCKER_TIMEOUT = 120


def run_docker_command(args, timeout=DOCKER_TIMEOUT):
    """
    Execute a Docker CLI command safely without shell=True.
    """

    result = subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()

        raise RuntimeError(
            f"Docker command failed: {error}"
        )

    return result.stdout.strip()


def check_docker_available():
    """
    Verify that Docker CLI and Docker Engine are available.
    """

    try:
        version = run_docker_command(
            ["version", "--format", "{{.Server.Version}}"],
            timeout=15,
        )

        return {
            "available": True,
            "server_version": version,
            "error": None,
        }

    except Exception as exc:

        return {
            "available": False,
            "server_version": None,
            "error": str(exc),
        }


def inspect_docker_image(image_name):
    """
    Retrieve metadata for a local Docker image.
    """

    output = run_docker_command(
        [
            "image",
            "inspect",
            image_name,
        ]
    )

    data = json.loads(output)

    if not data:
        raise RuntimeError(
            f"Docker image not found: {image_name}"
        )

    image = data[0]

    repo_tags = image.get(
        "RepoTags",
        []
    )

    repo_digests = image.get(
        "RepoDigests",
        []
    )

    config = image.get(
        "Config",
        {}
    )

    return {
        "image_name": image_name,
        "image_id": image.get("Id"),
        "created": image.get("Created"),
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
        "size_bytes": image.get("Size"),
        "virtual_size": image.get("VirtualSize"),
        "repo_tags": repo_tags,
        "repo_digests": repo_digests,
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "working_dir": config.get("WorkingDir"),
        "user": config.get("User"),
        "environment_count": len(
            config.get("Env") or []
        ),
    }


def save_docker_image(image_name, output_path):
    """
    Export a local Docker image to a TAR archive.
    """

    output_path = str(
        Path(output_path).resolve()
    )

    run_docker_command(
        [
            "save",
            image_name,
            "-o",
            output_path,
        ],
        timeout=300,
    )

    if not os.path.exists(output_path):
        raise RuntimeError(
            "Docker save completed but the TAR file was not created."
        )

    return output_path


def scan_docker_image(image_name):
    """
    Scan a local Docker image.

    Workflow:
        Docker inspect
        Docker save
        Container layer scanner
        Cleanup
    """

    image_name = image_name.strip()

    if not image_name:
        raise ValueError(
            "Docker image name cannot be empty."
        )

    docker_status = check_docker_available()

    if not docker_status["available"]:
        raise RuntimeError(
            docker_status["error"]
            or "Docker Engine is unavailable."
        )

    metadata = inspect_docker_image(
        image_name
    )

    temp_dir = tempfile.mkdtemp(
        prefix="pqc_docker_scan_"
    )

    tar_path = os.path.join(
        temp_dir,
        "image.tar"
    )

    try:

        save_docker_image(
            image_name,
            tar_path
        )

        findings, scanner_metadata = (
            scan_container_image(
                tar_path
            )
        )

        metadata.update({
            "scan_mode": "live_docker",
            "container_tar_size_bytes": os.path.getsize(
                tar_path
            ),
            "container_scanner": scanner_metadata,
        })

        for finding in findings:

            finding["container_image"] = (
                image_name
            )

            finding["image_id"] = (
                metadata.get("image_id")
            )

            finding["architecture"] = (
                metadata.get("architecture")
            )

            finding["os"] = (
                metadata.get("os")
            )

            finding["scan_mode"] = (
                "live_docker"
            )

        return findings, metadata

    finally:

        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )


def get_docker_image_names():
    """
    Return locally available Docker image names.
    """

    output = run_docker_command(
        [
            "image",
            "ls",
            "--format",
            "{{.Repository}}:{{.Tag}}",
        ]
    )

    images = []

    for line in output.splitlines():

        line = line.strip()

        if line and line != "<none>:<none>":
            images.append(line)

    return sorted(
        set(images)
    )
