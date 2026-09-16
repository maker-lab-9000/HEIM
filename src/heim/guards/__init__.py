"""Guards package: faithful Python ports of the n8n Code-node guards.

Ports the guard Code nodes from the PAM n8n workflows:
- ``Guard Command`` (PAM-40 SSH Diagnostic)  -> :func:`guard_command`
- ``Guard Path``    (PAM-42 HA API)          -> :func:`guard_ha_path`
- ``Guard Path``    (PAM-44 Proxmox API)     -> :func:`guard_proxmox_path`
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuardResult:
    """Outcome of a guard check.

    ``normalized`` is the value as it will actually be used downstream
    (the command as executed, or the cleaned API path).
    """

    allowed: bool
    reason: str | None = None
    normalized: str | None = None


# GuardResult must be defined before these imports: the submodules import it
# back from this package.
from heim.guards.command_guard import guard_command  # noqa: E402
from heim.guards.ha_guard import guard_ha_path  # noqa: E402
from heim.guards.proxmox_guard import guard_proxmox_path  # noqa: E402

__all__ = ["GuardResult", "guard_command", "guard_ha_path", "guard_proxmox_path"]
