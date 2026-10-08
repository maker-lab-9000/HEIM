"""Weekly schedule slot + catalogue path (security audit, Task 1)."""
import pytest
from pydantic import ValidationError

from heim.config import SchedulesCfg, load_config, parse_weekly


@pytest.mark.parametrize("spec,expected", [
    ("mon 06:00", ("mon", 6, 0)),
    ("SUN 23:59", ("sun", 23, 59)),
    ("  fri 7:05 ", ("fri", 7, 5)),
])
def test_parse_weekly_accepts_day_and_time(spec, expected):
    assert parse_weekly(spec) == expected


@pytest.mark.parametrize("spec", ["", "monday 06:00", "mon", "mon 24:00", "mon 06:60", "mon 06", "mon 6:0:0"])
def test_parse_weekly_rejects_garbage(spec):
    with pytest.raises(ValueError):
        parse_weekly(spec)


def test_schedules_default_and_disable():
    assert SchedulesCfg().security_audit == "mon 06:00"
    assert SchedulesCfg(security_audit="").security_audit == ""      # "" = disabled


def test_schedules_rejects_invalid_weekly_spec():
    with pytest.raises(ValidationError):
        SchedulesCfg(security_audit="every monday")


def test_load_config_points_at_the_security_catalogue(tmp_path):
    import shutil
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    croot = tmp_path / "config"
    shutil.copytree(root / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    assert cfg.security_checks_path == croot / "security" / "checks.yaml"
    assert cfg.settings.schedules.security_audit == "mon 06:00"
