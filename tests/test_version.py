from collector import __version__
from collector.version import read_pyproject_version


def test_pyproject_version_matches_package():
    assert read_pyproject_version() == __version__


def test_installed_version_is_semverish():
    assert __version__
    parts = __version__.split(".")
    assert len(parts) >= 2
