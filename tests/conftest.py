import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

#: Deployment-identity vars that `config/` references as `${VAR}`. Any test
#: that loads config/settings.example.yaml needs every one of them set, or
#: `expand_env` raises.
#:
#: They live here rather than in each test module's own DUMMY_ENV because
#: there are ~17 copies of that dict: adding a host used to mean editing all
#: of them, and forgetting one produced a RuntimeError in an unrelated file.
#: Modules that set their own values still win — an autouse fixture is set up
#: before the explicitly-requested fixtures that override it.
IDENTITY_DEFAULTS = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_OBSERVABILITY_IP": "10.0.0.4",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


@pytest.fixture(autouse=True)
def _identity_env(monkeypatch):
    """Give every test the identity vars config/ expects."""
    for key, value in IDENTITY_DEFAULTS.items():
        monkeypatch.setenv(key, value)
