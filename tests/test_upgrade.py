from unittest.mock import MagicMock, patch

from collector.upgrade import UpgradeStatus, check_upgrade, installed_version, is_git_checkout, project_root


def test_installed_version():
    assert installed_version()


def test_project_root_is_repo():
    root = project_root()
    assert (root / "pyproject.toml").exists()


def test_check_upgrade_non_git(monkeypatch, tmp_path):
    monkeypatch.setattr("collector.upgrade.project_root", lambda: tmp_path)
    status = check_upgrade(fetch=False)
    assert status.git is False
    assert "Not a git checkout" in status.message


def test_check_upgrade_behind(monkeypatch):
    root = project_root()
    if not is_git_checkout(root):
        return

    def fake_run(cmd, cwd, *, check=True, timeout=60):
        proc = MagicMock()
        proc.returncode = 0
        if cmd[:3] == ["git", "branch", "--show-current"]:
            proc.stdout = "main"
        elif cmd[:2] == ["git", "rev-parse"]:
            if "HEAD" in cmd:
                proc.stdout = "abc1234"
            else:
                proc.stdout = "def5678"
        elif cmd[:2] == ["git", "rev-list"]:
            proc.stdout = "3"
        else:
            proc.stdout = ""
        proc.stderr = ""
        return proc

    with patch("collector.upgrade._run", side_effect=fake_run):
        status = check_upgrade(fetch=False)

    assert isinstance(status, UpgradeStatus)
    assert status.commits_behind == 3
    assert status.update_available is True
