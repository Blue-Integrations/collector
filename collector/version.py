from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def read_pyproject_version() -> str:
    import tomllib

    path = project_root() / "pyproject.toml"
    with path.open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def installed_version() -> str:
    """Return app version; pyproject.toml wins when running from a checkout."""
    root = project_root()
    if (root / "pyproject.toml").is_file():
        return read_pyproject_version()
    try:
        from importlib.metadata import version

        return version("netflow-collector")
    except Exception:
        return read_pyproject_version()
