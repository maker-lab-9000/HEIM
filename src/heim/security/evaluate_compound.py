"""Checks derived from other checks' results (no evidence of their own). Pure."""
from __future__ import annotations

from heim.security.evaluate import EvalContext, fail, ok, unavailable
from heim.security.types import CheckResult, CheckSpec


def no_firewall_any_layer(spec: CheckSpec, results: list[CheckResult], ctx: EvalContext) -> list[CheckResult]:
    pve_row = next((r for r in results if r.check_id == "pve.firewall_disabled" and r.subject == "cluster"), None)
    guest_row = next((r for r in results if r.check_id == "ssh.host_firewall"), None)
    # R5 deviation from the brief: the brief only checked `status == "fail"` /
    # `status == "note"` and otherwise fell through to `ok`. That silently
    # reports "verified: a firewall is active" when one of the two inputs
    # was never actually verified (e.g. the Proxmox firewall API denied —
    # pve.firewall_disabled is itself `unavailable`). A compound check built
    # from an unverified input must stay `unavailable`, not default to `ok`.
    if pve_row is None or guest_row is None:
        return [unavailable(spec, ctx.ssh_host, "missing pve.firewall_disabled or ssh.host_firewall result to derive this check from")]
    if pve_row.status == "unavailable" or guest_row.status == "unavailable":
        return [unavailable(spec, ctx.ssh_host,
                             f"cannot verify: pve.firewall_disabled={pve_row.status}, ssh.host_firewall={guest_row.status}")]
    pve_off = pve_row.status == "fail"
    guest_off = guest_row.status == "note"
    if pve_off and guest_off:
        return [fail(spec, ctx.ssh_host, ctx.ssh_host,
                     f"no packet filter is active at any layer for {ctx.ssh_host}: Proxmox firewall off, no ufw/nftables in the guest")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


COMPOUND = {"net.no_firewall_any_layer": no_firewall_any_layer}
