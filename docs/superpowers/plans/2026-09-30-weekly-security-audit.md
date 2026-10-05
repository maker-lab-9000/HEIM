# Weekly Security Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a weekly, read-only, defensive configuration-hygiene audit of the owner's own homelab to HEIM, whose findings are detected by deterministic code (stable fingerprints, week-over-week diff, existing false-positive/suppression machinery) and explained by one bounded LLM pass that can fail without losing the report.

**Architecture:** A new pure package `heim.security` (catalogue loader, evaluators, diff, report renderer — no I/O) sits between an I/O collector module (`pipelines/security_sources.py`: fixed GET paths, fixed PromQL, fixed guard-validated SSH lines — never model-chosen) and a new pipeline (`pipelines/security_audit.py`) that persists into the existing `runs` / `findings` / `investigations` tables and delivers over the existing channels. The deterministic report is the primary artefact; the `security_auditor` agent (Sonnet 5, 3 read-only API/PromQL tools, no SSH, hard cap 6) appends an `## AI assessment`, and a refusal/timeout degrades that section only. A `CronTrigger(day_of_week=…)` job in the daemon and a `heim security-audit` CLI verb drive it.

**Tech Stack:** Python 3.13, pydantic v2, APScheduler 3 `CronTrigger`, httpx (GET only), asyncssh, Jinja2 prompts, SQLite via `IncidentStore`, Anthropic SDK through the existing `agent.runner.run_agent`, pytest (`.venv/bin/pytest`, asyncio_mode=auto).

---

## Design

### 0. Judgement on the proposed direction

The "deterministic collectors + one LLM pass" split is right, with five corrections the evidence forces:

1. **"Pure collectors" must be two layers, not one.** HEIM's convention (AGENTS.md conventions) is *pure logic in `incidents/ metrics/ guards/ reports/`, I/O in `tools/ channels/ pipelines/`*. A collector that performs a GET is I/O. So: **fetchers** (I/O, `pipelines/security_sources.py`) produce an `EvidenceBundle` of raw bodies + statuses; **evaluators** (pure, `security/evaluate_*.py`) turn evidence into `CheckResult`s and are unit-tested against recorded fixtures. The evidence bundle — not the LLM transcript — is what a post-mortem or a replay needs.
2. **The deterministic report is primary; the LLM writes an appendix.** `investigate.py`'s contract is "no `## Summary` from the model → synthetic incomplete report". Copying that here would let one `stop_reason: "refusal"` (a real risk for security-framed prompts, brief §6) throw away 47 correctly computed check rows. Instead `render_audit_report()` produces the full `## Summary`-led report from the rows; the model's output still goes through `salvage()` (constraint 5) and, only if complete, is appended under `## AI assessment` with headings demoted. An incomplete assessment marks the *investigations* row `incomplete` and the email subject, nothing else.
3. **The model must not hold the SSH tool.** Every SSH read the audit needs (listeners with owning process, effective sshd directives, failed-auth counts, pending updates via the world-readable update-notifier file, sudoers scope, container HostConfig) is a fixed line in `config/security/checks.yaml`, validated by `guard_command()` at load time and executed by HEIM code. Giving the model `ssh_diagnostic` would (a) make this the first *unattended* model-chosen shell access in HEIM (investigations are approval-gated), (b) put shell activity under a security framing in front of the classifier, and (c) add nothing the collectors do not already return. The `security_auditor` agent therefore gets `prometheus_query`, `discover_metrics`, `proxmox_api` — read-only APIs behind the *unchanged* guards — with `hard_step_cap: 6`, and its prompt forbids "finding new issues". Anything it observes via tools lands in prose, never in a check row.
4. **The LLM must consume the diff, not the table.** Its one real contribution over a rendered table is "what changed and what matters most *this* week", so the brief hands it new / persisting / resolved / carried explicitly.
5. **Severity is data, not judgement.** Several "bad" conditions here are owner intent (Proxmox firewall off on a NAT'd LAN; `monitor-box` powered off; password auth on a LAN-only guest). No LLM can resolve intent; the right tools are the check's `params` (allowlists) and the existing `mark_false_positive` → suppression path, which works unchanged because every row carries a stable `host|check_id|subject` fingerprint. The model may *argue* priority in words; it never alters a stored severity.

Where the guards sit (brief "two facts"): the model's `proxmox_guard._ALLOW`, `ha_guard._ALLOW` and `command_guard._HARD_DENY` are **not touched**. The PVE fetcher has its own fixed, GET-only, code-reviewed allowlist (`security/catalogue.py: PVE_AUDIT_ALLOW`) that *does* include `/access/*`, `/cluster/firewall/*`, `/nodes/homelab/apt/*`, `/nodes/homelab/certificates/info`, `/cluster/backup`, `/nodes/homelab/services` — all confirmed 200 for the auditor token in the live dossier. The HA fetcher's paths must pass `guard_ha_path` (both audit paths already do). SSH lines must pass `guard_command` **and** a loader rule that rejects `sudo cat` / `sudo grep` (they would fail at the sudoers layer anyway; rejecting them at load keeps the promise explicit).

### 1. Scope: hosts × categories

| Host | Access today | Audit vantage | Categories covered | Not observable (v1) |
|---|---|---|---|---|
| `homelab` (PVE 9.1 hypervisor) | auditor API token (`*.Audit` + `Sys.Syslog`), node-exporter, apt textfile collector | PVE API (fetcher allowlist) + PromQL | accounts/TFA/ACL, firewall state, pending updates (incl. kernel/microcode), repos, TLS cert, backup coverage & last status, services, failed auth in journal, VM config hardening, OS EOL, reboot-required, time sync | API-token inventory (`/access/users/{id}/token` → 403, needs `User.Modify` — not requested), sshd config on the hypervisor (no shell) |
| `ubuntu-server` (VM 100) | SSH as the monitoring user (scoped sudoers), node-exporter, cAdvisor | fixed SSH lines + PromQL | wildcard listeners + owning process, sshd effective directives, failed SSH auth (7 d), pending security updates, unattended-upgrades, host firewall/fail2ban presence, world-writable files under /etc /usr/local /opt, external logins, login-shell users, agent sudo scope, container HostConfig risks, stale images, failed units, reboot-required, time sync, OS EOL | pending updates via Prometheus (no apt collector — monitoring gap reported), `lastb` (root-only), full `sshd -T` (root-only) |
| `home-assistant` (VM 101) | non-admin long-lived token | HA REST (`/api/config`, `/api/states`) + PVE VM config | core/OS/add-on updates (security-sensitive set), core-update-while-publicly-exposed, safe/recovery mode, cert-expiry sensors (and which are unpopulated), failed-login persistent notifications, external dirs | `/api/error_log` (404), auth providers/users (no REST surface), OS-level state (no node-exporter) |
| `heim` (VM 103, runs HEIM) | node-exporter + PVE VM config only (no shell) | PromQL + PVE | reboot-required, failed units, time sync, OS EOL, VM hardening flags, backup coverage | listeners, sshd, auth log, pending updates (apt collector absent → gap reported). Owner-side step 5 would add SSH. |
| `monitor-box` (VM 102, powered off by design) | PVE only | PVE VM config + status | `onboot` on a deliberately-off VM, protection flag, backup job absence (note), "unexpectedly running" (note) | everything in-guest — by design; not a coverage gap |

### 2. Check catalogue

Sources are declared once in `config/security/checks.yaml` and referenced by checks. Statuses per row: `ok` · `fail` (finding when severity is critical/warning) · `note` (informational fact, never a finding) · `unavailable` (not verified — reported under Coverage gaps, never counts as passed **or** resolved).

Availability legend: **today** = confirmed 200/readable in the live dossier or by the codebase; **today\*** = expected to work today but not exercised by the live probe, verified by the first `--no-llm` run; **owner step N** = needs the listed owner-side step.

Sources (all PVE paths under `/api2/json`, GET; HA under `/api`, GET; PromQL instant; SSH on `ubuntu-server`):

| Source key | Kind | Target | Control (proves an empty list is genuine) |
|---|---|---|---|
| `pve.version` | pve | `/version` | — |
| `pve.node_status` | pve | `/nodes/homelab/status` | — |
| `pve.resources_vm` | pve | `/cluster/resources?type=vm` | — |
| `pve.access_users` | pve | `/access/users` | — |
| `pve.access_acl` | pve | `/access/acl` | `pve.access_users` |
| `pve.access_roles` | pve | `/access/roles` | — |
| `pve.access_tfa` | pve | `/access/tfa` | `pve.access_users` |
| `pve.fw_cluster_options` | pve | `/cluster/firewall/options` | — |
| `pve.fw_cluster_rules` | pve | `/cluster/firewall/rules` | `pve.fw_cluster_options` |
| `pve.fw_node_options` | pve | `/nodes/homelab/firewall/options` | — |
| `pve.fw_node_rules` | pve | `/nodes/homelab/firewall/rules` | `pve.fw_node_options` |
| `pve.fw_vm_options` | pve (expand `vmid`) | `/nodes/homelab/qemu/{vmid}/firewall/options` | — |
| `pve.vm_config` | pve (expand `vmid`) | `/nodes/homelab/qemu/{vmid}/config` | — |
| `pve.vm_status` | pve (expand `vmid`) | `/nodes/homelab/qemu/{vmid}/status/current` | — |
| `pve.apt_versions` | pve | `/nodes/homelab/apt/versions` | — |
| `pve.apt_repositories` | pve | `/nodes/homelab/apt/repositories` | — |
| `pve.certificates` | pve | `/nodes/homelab/certificates/info` | — |
| `pve.backup_jobs` | pve | `/cluster/backup` | `pve.resources_vm` |
| `pve.tasks_vzdump` | pve | `/nodes/homelab/tasks?typefilter=vzdump&limit=20` | — |
| `pve.tasks_errors` | pve | `/nodes/homelab/tasks?errors=1&limit=50` | `pve.tasks_vzdump` |
| `pve.services` | pve | `/nodes/homelab/services` | — |
| `pve.journal` | pve | `/nodes/homelab/journal?lastentries=1000` | — |
| `ha.config` | ha | `/api/config` | — |
| `ha.states` | ha | `/api/states` | — |
| `prom.reboot_required` | prom | `node_reboot_required` | — |
| `prom.apt_pending` | prom | `sum by (instance) (apt_upgrades_pending)` | — |
| `prom.apt_present` | prom | `count by (instance) (node_exporter_build_info)` | — |
| `prom.failed_units` | prom | `node_systemd_unit_state{state="failed"} == 1` | — |
| `prom.timex` | prom | `node_timex_sync_status` | — |
| `prom.up` | prom | `up` | — |
| `prom.os_info` | prom | `node_os_info` | — |
| `ssh.listeners` | ssh | `sudo ss -tunlpH` | — |
| `ssh.sshd_config` | ssh | `cat /etc/ssh/sshd_config` | — |
| `ssh.sshd_config_d` | ssh | `cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null` | — |
| `ssh.sshd_config_d_ls` | ssh | `ls -la /etc/ssh/sshd_config.d/` | — |
| `ssh.auth_fail_count` | ssh | `journalctl --no-pager -u ssh -u sshd --since=-7d -o cat \| grep -c -E 'Failed password\|Invalid user\|maximum authentication attempts'` | — |
| `ssh.auth_fail_sample` | ssh | same pipeline with `grep -E … \| tail -n 20` | — |
| `ssh.updates_available` | ssh | `cat /var/lib/update-notifier/updates-available` | — |
| `ssh.auto_upgrades` | ssh | `cat /etc/apt/apt.conf.d/20auto-upgrades` | — |
| `ssh.unit_states` | ssh | `systemctl is-active ufw nftables fail2ban unattended-upgrades ssh` | — |
| `ssh.world_writable` | ssh | `find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null` | — |
| `ssh.last_logins` | ssh | `last -w -F -n 100 -s -7days` | — |
| `ssh.login_shells` | ssh | `grep -E ':/bin/(ba\|z\|da)?sh$' /etc/passwd` | — |
| `ssh.sudo_scope` | ssh | `sudo -n -l` | — |
| `ssh.docker_ps` | ssh | `sudo agent-docker ps` | — |
| `ssh.docker_inspect` | ssh (expand `container`) | `sudo agent-docker inspect {container}` | — |
| `ssh.docker_images` | ssh | `sudo agent-docker images` | — |

Every SSH line above passes `guard_command` (first tokens `ss`, `cat`, `ls`, `journalctl`, `grep`, `tail`, `systemctl is-active`, `find` without `-exec/-delete`, `last`, `sudo -n -l` → `-l`, `agent-docker`; only `2>/dev/null` redirections; no `$(`/backticks) and the sudoers scope (`sudo` only in front of `ss` and `agent-docker`, plus `sudo -n -l` which lists the caller's own rights). Note `journalctl` is used **without** `-q`: `-q` suppresses exactly the "not seeing messages from other users and the system" hint the evaluator needs to tell "0 failures" from "no permission".

Checks:

| Check id | Host(s) | Sources | "Bad" looks like | Severity | Availability |
|---|---|---|---|---|---|
| `pve.tfa_missing` | homelab | access_tfa, access_users | an enabled user in `params.interactive_users` (default `root@pam`) has no TFA entry; token-only users → note | warning | today (live: `[]` with `/access/users`=3 → genuine) |
| `pve.firewall_disabled` | homelab, each VM | fw_* options/rules, vm_config | cluster `enable`≠1 → fail; VM NIC `firewall=1` while VM firewall off → note | warning | today (live: off everywhere, 0 rules) |
| `pve.pending_updates` | homelab | apt_versions | rows with `OldVersion`≠`Version` | warning | today (live: 47/57) |
| `pve.pending_updates_sensitive` | homelab | apt_versions | pending package matches a class prefix (kernel, microcode, ssh, firewall, hypervisor, tls) → one row per class | warning | today (live: kernel, microcode, firewall, qemu pending) |
| `pve.repo_security` | homelab | apt_repositories | no enabled repo with a `*-security` suite or `security.debian.org` URI | critical | today (live: ok) |
| `pve.repo_risky` | homelab | apt_repositories | `pve-test` enabled → fail; `pve-enterprise` enabled → note | warning | today (live: test disabled) |
| `pve.cert_expiry` | homelab | certificates | `notafter` < 90 d → warning, < 30 d → critical; `pve-ssl.pem` issued by the internal PVE CA → note | warning/critical | today (live: 423 d) |
| `pve.acl_privileged` | homelab | access_acl, access_roles | a non-root ugid holds a role whose privs match `Modify\|Allocate\|Console\|PowerMgmt\|Permissions\|Backup\|Migrate\|Snapshot\|Clone\|Config` | warning | today (live: none) |
| `pve.backup_coverage` | each VM | backup_jobs, resources_vm | running VM in no enabled job (`all=1` minus `exclude` honoured) → fail; stopped VM uncovered → note | warning | today (live: 102 uncovered & stopped → note) |
| `pve.backup_last_status` | homelab / VM | tasks_vzdump, backup_jobs | a vzdump task in the last 8 d with `status`≠OK; or none ran although jobs exist | warning | today |
| `pve.failed_tasks` | homelab | tasks_errors | failed tasks in the last 7 d (count + first UPIDs) | info (note) | today (live: 0) |
| `pve.services_dead` | homelab | services | `params.required_active` (sshd, pveproxy, pvedaemon, pve-firewall, pvefw-logger) not running; none of `params.time_sync_any` (chrony, systemd-timesyncd) running | warning | today (live: all ok; timesyncd dead but chrony running) |
| `pve.auth_failures` | homelab | journal | sshd `Failed password\|Invalid user\|maximum authentication attempts` lines, or `pvedaemon … authentication failure` lines; ≥ `critical_count` (50) → critical; 0 journal lines → unavailable | warning/critical | today\* (`/journal` needs `Sys.Syslog`, which the token has, and the investigator uses it routinely; not exercised by the live probe) |
| `pve.vm_hardening` | each VM | vm_config | `protection`≠1; `hostpci*`/`usb*` passthrough present; `agent` unset | info (note) | today |
| `pve.stopped_vm_onboot` | stopped VMs | vm_config, vm_status | stopped VM with `onboot=1` (would start on host reboot) | info (note) | today |
| `pve.secureboot` | homelab | node_status | `boot-info.secureboot`≠1 | info (note) | today (live: 0) |
| `ha.pending_updates_sensitive` | home-assistant | states | `update.*` with state `on` whose id/title matches `params.sensitive_patterns` (core, operating_system, supervisor, vaultwarden, bitwarden, letsencrypt, ssh, adguard, nginx, proxy, wireguard, tailscale, cloudflared) → one row per entity | warning | today (live: 14/28 on; core, OS, Vaultwarden, Let's Encrypt, two SSH add-ons match) |
| `ha.pending_updates_other` | home-assistant | states | count of other `update.*` on | info (note) | today |
| `ha.core_update_exposed` | home-assistant | states, config | `external_url` host is public **and** core update pending | critical | today (live: both true → fires on run 1) |
| `ha.external_url` | home-assistant | config | public `external_url` (DynDNS) | info (note) | today |
| `ha.safe_mode` | home-assistant | config | `safe_mode` or `recovery_mode` true | warning | today (live: false) |
| `ha.cert_expiry` | home-assistant | states | `sensor.*certificate_expiry*` numeric < 30 d → warning, < 14 d → critical; non-numeric → one note "N of M unpopulated" | warning/critical | today (live: 1/11 populated → note) |
| `ha.login_notifications` | home-assistant | states | `persistent_notification.*` whose title/message matches `login\|ban` | warning | today (live: 0 → ok; fires when HA raises one) |
| `ha.external_dirs` | home-assistant | config | `allowlist_external_dirs` outside `params.allowed` | info (note) | today |
| `prom.reboot_required` | homelab, ubuntu-server, heim | reboot_required | value 1 | warning | today (live: all 0) |
| `prom.apt_pending` | homelab (+gap notes) | apt_pending, apt_present | `sum>0` → fail; node-exporter instance with no apt series → note "collector absent" | warning | today for homelab; owner step 2 for ubuntu-server/heim |
| `prom.failed_units` | all node-exporter hosts | failed_units | unit in failed state not in `params.expected_failed` | warning | today (live: `openipmi.service` ×2 → owner suppresses or lists) |
| `prom.time_sync` | all node-exporter hosts | timex | `node_timex_sync_status`=0 | warning | today (live: all 1) |
| `prom.targets_down` | per job | up | `up`=0 (a blind spot for this audit) | warning | today (live: 7/7 up) |
| `prom.os_eol` | all node-exporter hosts | os_info | EOL in `params.os_eol` < 180 d → warning, past → critical; unknown OS or table past `review_by` → note | warning/critical | today |
| `ssh.listeners_unexpected` | ubuntu-server | listeners | wildcard-bound listener (`0.0.0.0`, `*`, `[::]`) whose port ∉ `params.expected_ports`; port ∈ `params.critical_ports` (2375/2376 docker API, 23, 3389, 5900) → critical; no :22 in output → unavailable | warning/critical | today (`sudo ss` in sudoers). First run is a triage run: expect ~10–20 rows until `expected_ports` is filled |
| `ssh.sshd_password_auth` | ubuntu-server | sshd_config(+_d, _d_ls) | effective `PasswordAuthentication` ≠ `no` (default yes; drop-ins evaluated first, first-wins); unreadable drop-in in `ls` → unavailable | warning | today\* (644 by default on Ubuntu; cloud-init drop-ins commonly set `yes`) |
| `ssh.sshd_root_login` | ubuntu-server | same | `PermitRootLogin yes` | critical | today\* |
| `ssh.sshd_empty_passwords` | ubuntu-server | same | `PermitEmptyPasswords yes` | critical | today\* |
| `ssh.sshd_hardening` | ubuntu-server | same | `X11Forwarding yes`, `MaxAuthTries` > 6, neither `AllowUsers` nor `AllowGroups`, non-22 port | info (note) | today\* |
| `ssh.auth_failures` | ubuntu-server | auth_fail_count, auth_fail_sample | count > 0; ≥ `critical_count` (100) → critical; stderr hint "not seeing messages"/"No journal files" → unavailable | warning/critical | today\* if the SSH user can read the journal (privileges text lists `journalctl -u`), else owner step 1 |
| `ssh.pending_security_updates` | ubuntu-server | updates_available | "N of these updates are standard security updates" with N > 0 → fail; only non-security → note; file unreadable → unavailable | warning | today\* (Ubuntu Server default `update-notifier-common`) |
| `ssh.auto_upgrades_off` | ubuntu-server | auto_upgrades, unit_states | `Unattended-Upgrade "1"` absent or unit not active | warning | today |
| `ssh.host_firewall` | ubuntu-server | unit_states | neither `ufw` nor `nftables` active | info (note; feeds compound) | today |
| `ssh.fail2ban_absent` | ubuntu-server | unit_states | `fail2ban` not active | info (note) | today |
| `ssh.world_writable` | ubuntu-server | world_writable | any path listed (cap 20 rows) | warning | today |
| `ssh.external_logins` | ubuntu-server | last_logins | login source IP ∉ `params.trusted_cidrs` (RFC1918, 100.64/10 Tailscale, loopback) → one row `external` listing IPs | warning | today (`/var/log/wtmp` world-readable) |
| `ssh.login_shell_users` | ubuntu-server | login_shells | count/list of accounts with a login shell | info (note) | today |
| `ssh.agent_sudo_scope` | ubuntu-server | sudo_scope | `sudo -n -l` shows a command outside `params.expected_sudo_binaries` (du, df, findmnt, lsof, ls, ss, agent-docker) or `ALL`; non-zero exit → unavailable | warning | today\* (`sudo -l` needs no password when every entry is NOPASSWD) |
| `ssh.docker_privileged` | ubuntu-server / container | docker_inspect[*] | `HostConfig.Privileged`, `/var/run/docker.sock` bind, `NetworkMode=host`, `CapAdd` ∩ {SYS_ADMIN, NET_ADMIN, SYS_PTRACE, ALL} | warning | today (`agent-docker inspect` redacts env — no secrets in evidence) |
| `ssh.docker_stale_images` | ubuntu-server | docker_images | `CREATED` ≥ 6 months (cap 15) — the local stand-in for CVE lookups | info (note) | today |
| `net.no_firewall_any_layer` | ubuntu-server | compound of `pve.firewall_disabled`(cluster fail) + `ssh.host_firewall`(note) | no packet filter at hypervisor or guest layer | warning | today |

47 checks. Realistic first-run outcome from the live dossier: **critical 1** (`ha.core_update_exposed`), **warnings ≈ 10 + N unexpected listeners** (`pve.tfa_missing|root@pam`, `pve.firewall_disabled|cluster`, `pve.pending_updates`, 4× `pve.pending_updates_sensitive`, ≈6× `ha.pending_updates_sensitive`, 2× `prom.failed_units|openipmi.service`, `net.no_firewall_any_layer`, likely `ssh.sshd_password_auth`), plus notes. The owner's first job is triage via `expected_ports` / `expected_failed` in `checks.yaml` or "false positive" on `/findings`.

### 3. Data flow

```
daemon CronTrigger(day_of_week=mon, 06:00)  ──►  _security_audit_job(rt)  ──►  run_security_audit(rt, llm=True)
   │ (or: heim security-audit [--dry-run] [--no-llm])
   ▼
load_catalogue(config/security/checks.yaml)        pure · validates every SSH line (guard_command, no sudo cat/grep),
                                                   HA path (guard_ha_path), PVE path (PVE_AUDIT_ALLOW), ids, severities
collect_evidence(cfg, cat)                          I/O · 4 kinds in parallel, each under a 300 s cap; per call 30 s (HTTP),
                                                   20 s connect / 90 s command (SSH); GET only; expands {vmid}/{container}
evaluate(cat, bundle, ctx) → list[CheckResult]      pure · control rule for empty lists; per-check try/except → unavailable
active_suppressions() → drop muted fingerprints     existing store API
runs(kind=security_audit, limit=1) → findings_for_run(prev) → diff_findings(...)   pure · new/persisting/resolved/carried
render_audit_report(...) → report_md ("## Summary" first)                          pure
insert_run(kind=security_audit) + insert_findings(source=security_audit, trend=new|persisting|carried)
[llm] create_investigation(agent_name=security_auditor, trigger=security_audit, host=all) → run_agent(3 API tools, cap 6)
      → salvage() → complete: append "## AI assessment" (headings demoted) · incomplete: append the reason line
      → update_investigation(status, tokens, cost, transcript, report_md=final)
deliver: email (full) · Telegram digest (+ 🔴 line for new criticals) · HA sensor.pam_security_audit · Loki finding/investigation/action
```

### 4. Resolved decisions

| Decision | Default | Trade-off (one line) |
|---|---|---|
| Schedule | `schedules.security_audit: "mon 06:00"` (configured tz), `misfire_grace_time=3600`; `""` disables | Sunday is maintenance night (PVE vzdump Sun 01:00 heim; Sun 03:00 *stop-mode* backup of ubuntu-server + home-assistant — Prometheus lives on ubuntu-server so it is down too; HEIM backup 03:30); Monday 06:00 sees finished backup tasks, lands before the 07:00 daily report, and never runs against a stopped guest. Cost: findings are one day "old" relative to a Sunday run. |
| Where results live | No new table, no migration: `runs.kind="security_audit"`, `findings.source="security_audit"` (`metric`=check id, `trend`=new/persisting/carried, `fingerprint`=host\|check\|subject), `investigations.agent_name="security_auditor"`, `trigger="security_audit"`, `host="all"`; new store reads `findings_for_run`, `finding_run_count` | `/findings`, verdicts, `mark_false_positive`→suppression and `/investigations` work with one dashboard line changed; `incidents` is deliberately **not** used (poller/`missedRuns` lifecycle and `qid` anchoring do not fit weekly observations). Tokens/cost are written on the investigations row only (runs row 0) so `/costs` does not double count. |
| Delivery | Email = full report (deterministic + assessment) via `security_audit_email` (reuses `investigation.html.j2`); Telegram = one digest message (counts, new findings, resolved, assessment status) + an immediate 🔴 message for *new* criticals; dashboard = `/investigations?trigger=security_audit` (detail page shows brief, steps, report, cost) and `/findings`; HA `sensor.pam_security_audit` (state = counts line, attributes = counts + report); Loki `finding` events with `labels.category="security"`, one `investigation` event (`host=all`), `action` phases `audit_started`/`report` | Full 47-row report over Telegram is noise — digest instead; no new Loki event type (invariant 5 kept). |
| New critical → incident/investigation? | **Report only** + the 🔴 Telegram line. No `incidents` row, no `dispatch_all` | An incident needs a 5-minute signal to clear it (poller ownership, `missedRuns`); an investigation is root-cause-framed and would be a second security-framed model run (refusal exposure). The owner can still queue an investigation from the dashboard. Revisit if the "needs attention" queue should include audit criticals. |
| Approval gate | **None.** The pipeline never calls `run_investigation`; enabling `schedules.security_audit` *is* the standing approval | The gate exists so a human decides per *event* whether to spend an agent run and shell access; the audit is scheduled, fixed-scope, and its model holds no SSH tool. Every collector SSH line is guard-validated config; the live Telegram feed still streams the model's 0–6 API calls. |
| Model & budget | `claude-sonnet-5`, `max_tokens 8192`, `soft_step_budget 4`, `hard_step_cap 6`, tools `prometheus_query, discover_metrics, proxmox_api`; priced in `model_prices` (2.00 / 10.00 per MTok) | Estimate: first turn ≈ 5.3k in (prompt 1.2k + brief 3.5k + schemas 0.6k). Worst case 6 tool turns re-sending context ≈ 73k in + 6k out ≈ **$0.21/run**; typical 2 calls ≈ 21k in + 4.5k out ≈ **$0.09/run**; ≈ $5–11/year. `--no-llm` = $0. |
| External CVE lookups | **No** in v1. Signals used instead: PVE `/apt/versions` version diff, Prometheus `apt_upgrades_pending`, update-notifier "security updates" count, HA `update.*` entities, image age | v2 option: OSV.dev batch query — sends the full package inventory (OS, exact versions) to a third party, fingerprinting the host; HEIM is outbound-only so it is technically possible, but it is a privacy decision the owner must make, not a default. |
| `heim` (no shell) / `monitor-box` (off) | `heim`: PromQL + PVE config only; its missing apt collector and absent shell are listed under Coverage gaps every week. `monitor-box`: PVE config/status only; `stopped` is expected (`params.expected_offline_vms`), `running` is a note, no backup job is a note | Adding SSH to `heim` is owner step 5 (HEIM would hold a key to its own host). |

### 5. Failure modes

| Situation | Behaviour |
|---|---|
| Model returns `stop_reason: "refusal"` | `salvage()` → incomplete with the refusal reason; deterministic report is delivered unchanged with `## AI assessment` → "_Unavailable — the model declined …_"; investigations row `incomplete`, email subject gets "(AI assessment unavailable)", digest shows ⚠️; no retry (a re-run is declined again). Prompt hygiene is enforced by a test: rendered system prompt + brief contain none of `exploit, attack, brute, penetration, pentest, payload, intrusion, crack, bypass`. |
| `max_tokens` / `loop-cap` / leaked tool-call text | same path via `salvage()`'s existing reasons. |
| Anthropic API down after 3 retries / exception in `run_agent` | caught in `_assessment`: investigations row `failed`, report still delivered, digest says "assessment failed: <exc>". |
| One source kind (e.g. SSH) unreachable / times out | its `Evidence` rows are `error`/`timeout`; every dependent check is `unavailable`; findings from last week whose check is unavailable are **carried** (`trend="carried"`, detail "not re-verified: <reason>") — never resolved; the report lists them under Coverage gaps. |
| `ubuntu-server` down | SSH *and* Prometheus (hosted there) unavailable → all `ssh.*` and `prom.*` carried/unavailable; PVE + HA parts still ship. |
| Every source unreachable | `run_security_audit` raises `RuntimeError("every source was unreachable")` → `_security_audit_job` logs and `rt.notify("🔴 HEIM weekly security audit FAILED: …")`; nothing persisted. |
| API "200 with an empty list" (privsep token trap) | a source with a `control` may only be treated as genuinely empty when the control source returned non-empty in the same run; otherwise the check is `unavailable` with the reason "cannot tell 'nothing there' from 'not permitted'". PVE 401/403 → `denied`, 404 → `error`. |
| SSH `journalctl` without journal permission | stderr hint detected → `ssh.auth_failures` unavailable with the owner-step text, never `ok` with count 0. |
| Guard rejects a YAML SSH line / bad PVE path | `load_catalogue` raises `CatalogueError` at startup and in `heim check`; the audit never runs with an invalid catalogue. |
| Daemon restarted across the slot | `misfire_grace_time=3600` runs it up to an hour late; later than that the week is skipped (next Monday). |
| Duplicate run in one week (manual + cron) | allowed; the diff is against the *previous run*, so the second run shows mostly `persisting`. |

### 6. Deliberately not in v1

Network/port scanning of any kind (in-guest `ss` only); external CVE feeds; remediation of any kind; PVE token inventory (needs `User.Modify`); SSH to `heim` or `homelab`; HA auth-provider/user audit (no REST surface); a dedicated dashboard page (the investigations detail + findings pages suffice); Grafana/Loki access-control review; changes to any guard allowlist.

---

## Owner-side steps

None are required for v1 to run. Each below unlocks a listed check or closes a gap; do them deliberately.

1. **Journal read for the SSH user on `ubuntu-server`** (unlocks `ssh.auth_failures`): `usermod -aG systemd-journal ${HEIM_SSH_USER}`. Risk: the agent user can read *all* system journal entries (read-only), including other services' logs. Alternative: leave the check `unavailable`.
2. **apt textfile collector on `ubuntu-server` and `heim`** (unlocks `prom.apt_pending` there): install `prometheus-node-exporter-collectors` (provides `apt_info.py` + systemd timer writing to the textfile dir). Risk: negligible (a root cron writing one metrics file).
3. **HA failed-login visibility** (makes `ha.login_notifications` meaningful): in `configuration.yaml` set `http: ip_ban_enabled: true, login_attempts_threshold: 5`. Risk: a mistyped password from your own device gets that IP banned until you edit `ip_bans.yaml`.
4. **Triage after run 1**: fill `expected_ports` (port → process) and `expected_failed` (e.g. `openipmi.service`) in `config/security/checks.yaml`, or mark rows "false positive" on `/findings` (90-day suppression by default). Risk: an allowlisted port is never re-flagged — keep the list minimal.
5. **(v2) SSH to `heim`**: `config/hosts/heim.yaml` `ssh:` block + the same scoped user/sudoers as `ubuntu-server` + a second `ssh_host` in the catalogue. Risk: HEIM's container holds a key that opens its own host; a compromise of HEIM becomes a foothold on `heim`. Not recommended until the audit has run for a few weeks.
6. **Not recommended**: granting `User.Modify` to the auditor token to list API tokens — it is a *modify* privilege and breaks the read-only-by-privilege invariant.
7. **Decision, not default**: external CVE lookups (OSV.dev) and a blackbox exporter probing the public HA URL — both send data outward or probe; the owner decides.

---

## Global Constraints

- Read-only end to end: fetchers call `httpx.AsyncClient.get` only; PromQL via `/api/v1/query`; SSH lines must pass `guard_command` and contain no `sudo cat`/`sudo grep`; the model's tool set is `prometheus_query, discover_metrics, proxmox_api` (no `ssh_diagnostic`).
- No new privilege: credentials are the existing `PROXMOX_TOKEN` (PAMAuditor), `HA_TOKEN` (non-admin), the existing SSH key; `guards/*.py` unchanged.
- No scanning: no connection to any address not already in `config/hosts/*.yaml` or `settings.prometheus.url`.
- Fingerprint: `f"{host}|{check_id}|{subject}"`, `subject` from `clean_subject()` (charset `[A-Za-z0-9_.:/@=+-]`, ≤ 64 chars, never a count or wording).
- Report contract: `render_audit_report()` output starts with `## Summary`; model output passes through `salvage(..., stop_reason=...)`; assessment appended under `## AI assessment` via `demote_headings()`.
- Loki: event types only `finding | investigation | action`; `labels.category="security"`; `labels.host` low-cardinality (`all` for the run).
- Store: no schema change; `runs.kind="security_audit"`, `findings.source="security_audit"`, `investigations.agent_name="security_auditor"`, `trigger="security_audit"`, `host="all"`, `host_role="audit"`; tokens/cost on the investigations row only.
- Model: `claude-sonnet-5`, `max_tokens: 8192`, `soft_step_budget: 4`, `hard_step_cap: 6`, no temperature override.
- Schedule: `SchedulesCfg.security_audit = "mon 06:00"`; format `<mon..sun> HH:MM`; `misfire_grace_time=3600`; job name `security-audit`.
- Timeouts: HTTP 30 s per call; SSH connect 20 s, command 90 s (`COMMAND_TIMEOUT_S`), stdout clip 65536 bytes; 300 s per source kind.
- Prompt lint: neither `security_auditor.md.j2` nor `briefs/security_audit.md.j2` renders any of `exploit, attack, brute, penetration, pentest, payload, intrusion, crack, bypass`.
- Config is data: every check, allowlist, path, PromQL and SSH line lives in `config/security/checks.yaml`; identity via `${VAR}`; no real IP/user/secret anywhere in this plan or the tree.
- Tests: baseline `788 passed` with `.venv/bin/pytest -q`; every task ends green; docs updated to the final count.

---

## File Structure

New:
- `src/heim/security/__init__.py` — package docstring (pure, no I/O).
- `src/heim/security/types.py` — `SourceSpec`, `CheckSpec`, `Evidence`, `EvidenceBundle`, `CheckResult`, `clean_subject`.
- `src/heim/security/catalogue.py` — `Catalogue`, `load_catalogue`, `CatalogueError`, `PVE_AUDIT_ALLOW`, validation.
- `src/heim/security/parsers.py` — pure text/JSON parsers (ss, sshd_config, update-notifier, last, docker ps/images, apt versions, resources, URL publicness, CIDR test).
- `src/heim/security/evaluate.py` — `EvalContext`, result helpers, control rule, `evaluate()` dispatcher + registry.
- `src/heim/security/evaluate_pve.py`, `evaluate_ha.py`, `evaluate_prom.py`, `evaluate_ssh.py`, `evaluate_compound.py` — one `EVALUATORS` dict each.
- `src/heim/security/diff.py` — `AuditDiff`, `diff_findings`.
- `src/heim/security/report.py` — `render_audit_report`, `demote_headings`, `brief_sections`, `telegram_digest`, `ha_attributes`, `finding_events`, `overall_of`.
- `src/heim/pipelines/security_sources.py` — `collect_evidence`, `fetch_pve/ha/prom/ssh`, `classify_http` (I/O).
- `src/heim/pipelines/security_audit.py` — `run_security_audit`, prompt builders, `_assessment`, delivery.
- `config/security/checks.yaml` — the catalogue (sources, checks, params).
- `config/agents/security_auditor.yaml` — the agent.
- `config/prompts/security_auditor.md.j2`, `config/prompts/briefs/security_audit.md.j2` — prompts.
- `tests/test_security_config.py`, `test_security_catalogue.py`, `test_security_parsers.py`, `test_security_evaluate_pve.py`, `test_security_evaluate_ha_prom.py`, `test_security_evaluate_ssh.py`, `test_security_diff.py`, `test_security_report.py`, `test_security_sources.py`, `test_security_prompt.py`, `test_security_pipeline.py`, `test_security_daemon_cli.py`, `test_security_dashboard.py`.

Modified:
- `src/heim/config.py:60-62` (`SchedulesCfg`), `:231-239` (`Config`), `:341-349` (`load_config`) — weekly slot + catalogue path.
- `src/heim/incidents/store.py:777` (after `recent_findings`) — `findings_for_run`, `finding_run_count`.
- `src/heim/reports/render.py:200` (after `investigation_email`) — `security_audit_email`.
- `src/heim/daemon.py:29-30` (import), `:42` (after constants), `:58` (after `_poll_job`), `:199-201` (register job), `:222-229` (log line).
- `src/heim/cli.py:16-17` (docstring), `:480` (after `_cmd_daemon`), `:547` (parser), `:559` (handler map), `_cmd_check` after the `queries:` line.
- `src/heim/dashboard/app.py:1010` — `_TRIGGERS`.
- `config/settings.example.yaml:40-42` — `schedules.security_audit`.
- `AGENTS.md:30,44,53,468,478`, `README.md:113`, `docs/ARCHITECTURE.md:29-44` — docs + test count.

---

### Task 1: Weekly schedule slot and catalogue path in config

**Files**
- Modify `src/heim/config.py:60-62` (`SchedulesCfg`), `src/heim/config.py:231-239` (`Config` dataclass), `src/heim/config.py:341-349` (`load_config` return), plus the pydantic import line (`from pydantic import BaseModel, Field`).
- Modify `config/settings.example.yaml:40-42` (`schedules:` block).
- Create `tests/test_security_config.py`.

**Interfaces**
- Produces `heim.config.parse_weekly(spec: str) -> tuple[str, int, int]` — `"mon 06:00"` → `("mon", 6, 0)`; raises `ValueError` otherwise.
- Produces `SchedulesCfg.security_audit: str = "mon 06:00"` (validated; `""` allowed = disabled).
- Produces `Config.security_checks_path: Path | None = None`, set by `load_config` to `root / "security" / "checks.yaml"`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_config.py
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
```

- [ ] Run `.venv/bin/pytest tests/test_security_config.py -q` — expect `ImportError: cannot import name 'parse_weekly'`.
- [ ] Implement in `src/heim/config.py`. Change the import to `from pydantic import BaseModel, Field, field_validator`, then replace `SchedulesCfg`:

```python
_WEEKDAYS_CRON = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_weekly(spec: str) -> tuple[str, int, int]:
    """``"mon 06:00"`` → ``("mon", 6, 0)`` — the weekly cron slot format.

    APScheduler's ``day_of_week`` takes the same three-letter names, so the
    daemon passes the parts straight through. Anything else raises ValueError
    naming the value, so a typo in settings fails at load, not next Monday.
    """
    parts = str(spec or "").strip().lower().split()
    if len(parts) != 2 or parts[0] not in _WEEKDAYS_CRON:
        raise ValueError(f"weekly schedule must be '<mon..sun> HH:MM', got {spec!r}")
    hh, sep, mm = parts[1].partition(":")
    if not sep or not hh.isdigit() or not mm.isdigit() or ":" in mm:
        raise ValueError(f"weekly schedule must be '<mon..sun> HH:MM', got {spec!r}")
    hour, minute = int(hh), int(mm)
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ValueError(f"weekly schedule time out of range in {spec!r}")
    return parts[0], hour, minute


class SchedulesCfg(BaseModel):
    daily: list[str] = ["07:00", "22:00"]  # HH:MM in the configured timezone
    poll_minutes: int = 5
    #: Weekly read-only security audit slot, "<mon..sun> HH:MM" in the
    #: configured timezone. "" disables the job. Monday morning by default:
    #: Sunday is maintenance night (PVE stop-mode backups, HEIM's own backup).
    security_audit: str = "mon 06:00"

    @field_validator("security_audit")
    @classmethod
    def _valid_weekly(cls, v: str) -> str:
        if v:
            parse_weekly(v)
        return v
```

  In the `Config` dataclass add, after `queries_path: Path`:

```python
    #: config/security/checks.yaml — the weekly audit's sources, checks and allowlists
    security_checks_path: Path | None = None
```

  In `load_config`'s `return Config(...)` add `security_checks_path=root / "security" / "checks.yaml",` after `queries_path=...`.

- [ ] Edit `config/settings.example.yaml` `schedules:` block to:

```yaml
schedules:
  daily: ["07:00", "22:00"]   # local time, see `timezone`
  poll_minutes: 5             # fast-path alert poller interval
  security_audit: "mon 06:00" # weekly read-only security audit ("" disables). Monday:
                              # Sunday night runs the PVE stop-mode backups and HEIM's own backup.
```

- [ ] Run `.venv/bin/pytest tests/test_security_config.py -q` — expect 13 passed. Run `.venv/bin/pytest -q` — expect 801 passed (788 + 13).
- [ ] Commit: `git add src/heim/config.py config/settings.example.yaml tests/test_security_config.py && git commit -m "config: weekly security_audit schedule slot and security catalogue path"`

### Task 2: Pure types, the check catalogue loader and the catalogue itself

**Files**
- Create `src/heim/security/__init__.py`, `src/heim/security/types.py`, `src/heim/security/catalogue.py`.
- Create `config/security/checks.yaml`.
- Create `tests/test_security_catalogue.py`.

**Interfaces**
- Produces (types): `SourceSpec(key, kind, target, control="", expand="")`, `CheckSpec(id, title, severity, sources: tuple[str,...], params: dict, recommendation="", compound=False)`, `Evidence(key, status, body=None, http_status=0, exit_code=None, stderr="", detail="", target="")` with `.usable`, `EvidenceBundle(items, collected_at)` with `.get(key)` and `.expanded(prefix) -> dict[str, Evidence]`, `CheckResult(check_id, host, subject, status, severity, summary, detail="", recommendation="")` with `.fingerprint`, `.is_finding`, `.as_finding(trend) -> dict`, and `clean_subject(s) -> str`.
- Produces (catalogue): `Catalogue(sources: dict[str, SourceSpec], checks: list[CheckSpec], params: dict, pve_node: str, ssh_host: str, ha_host: str)`, `load_catalogue(path: Path) -> Catalogue`, `CatalogueError(ValueError)`, `PVE_AUDIT_ALLOW: tuple[re.Pattern, ...]`, `validate_pve_path(path) -> str`, `validate_ssh_line(line) -> str`.
- Consumes `heim.guards.guard_command`, `heim.guards.guard_ha_path`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_catalogue.py
"""Catalogue loader: every SSH line is guard-checked, every PVE path is on the
audit allowlist, HA paths pass the HA guard, ids/severities are valid."""
from pathlib import Path

import pytest
import yaml

from heim.security.catalogue import (
    PVE_AUDIT_ALLOW, CatalogueError, load_catalogue, validate_pve_path, validate_ssh_line,
)
from heim.security.types import CheckResult, Evidence, EvidenceBundle, clean_subject

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "config" / "security" / "checks.yaml"


def test_shipped_catalogue_loads_and_is_complete():
    cat = load_catalogue(CATALOGUE)
    assert cat.pve_node == "homelab" and cat.ssh_host == "ubuntu-server" and cat.ha_host == "home-assistant"
    ids = [c.id for c in cat.checks]
    assert len(ids) == len(set(ids)) == 47
    for c in cat.checks:
        assert c.severity in ("critical", "warning", "info")
        for s in c.sources:
            assert s in cat.sources, f"{c.id} references unknown source {s}"
    kinds = {s.kind for s in cat.sources.values()}
    assert kinds == {"pve", "ha", "prom", "ssh"}


@pytest.mark.parametrize("path", [
    "/api2/json/access/tfa", "/api2/json/cluster/firewall/rules",
    "/api2/json/nodes/homelab/qemu/103/firewall/options", "/api2/json/nodes/homelab/apt/versions",
    "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20", "/api2/json/nodes/homelab/journal?lastentries=1000",
])
def test_pve_audit_allowlist_accepts_read_paths(path):
    assert validate_pve_path(path) == path


@pytest.mark.parametrize("path", [
    "/api2/json/nodes/homelab/apt/update",            # needs Sys.Modify; not audit
    "/api2/json/access/users/root@pam/token",          # 403 and not wanted
    "/api2/json/nodes/homelab/qemu/100/status/stop",   # a POST target
    "/api2/json/nodes/homelab/journal?lastentries=99999",
    "/api2/json/nodes/other/status", "nodes/homelab/status", "/api2/json/nodes/homelab/../access",
])
def test_pve_audit_allowlist_rejects_everything_else(path):
    with pytest.raises(CatalogueError):
        validate_pve_path(path)


@pytest.mark.parametrize("line", [
    "sudo ss -tunlpH", "cat /etc/ssh/sshd_config", "sudo -n -l", "sudo agent-docker inspect {container}",
    "journalctl --no-pager -u ssh -u sshd --since=-7d -o cat | grep -c -E 'Failed password|Invalid user'",
    "find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null",
])
def test_ssh_lines_that_pass(line):
    assert validate_ssh_line(line) == line


@pytest.mark.parametrize("line", [
    "sudo cat /etc/shadow",                 # sudoers excludes sudo cat; loader refuses it too
    "sudo grep root /etc/sudoers",
    "dpkg -l", "apt list --upgradable",     # package managers are hard-denied by the guard
    "cat /etc/passwd > /tmp/x", "ls $(pwd)", "systemctl restart ssh", "sudo -n -l; rm -rf /",
])
def test_ssh_lines_that_fail(line):
    with pytest.raises(CatalogueError):
        validate_ssh_line(line)


def test_loader_rejects_a_catalogue_with_a_bad_ssh_line(tmp_path):
    data = yaml.safe_load(CATALOGUE.read_text())
    data["sources"].append({"key": "ssh.evil", "kind": "ssh", "target": "sudo cat /etc/shadow"})
    p = tmp_path / "checks.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogueError, match="ssh.evil"):
        load_catalogue(p)


def test_loader_rejects_unknown_source_reference(tmp_path):
    data = yaml.safe_load(CATALOGUE.read_text())
    data["checks"][0]["sources"] = ["pve.does_not_exist"]
    p = tmp_path / "checks.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogueError, match="does_not_exist"):
        load_catalogue(p)


def test_types_fingerprint_and_finding_shape():
    r = CheckResult("ssh.listeners_unexpected", "ubuntu-server", clean_subject("8081/docker-proxy"),
                    "fail", "warning", "docker-proxy listens on :8081", detail="0.0.0.0:8081",
                    recommendation="bind to 127.0.0.1")
    assert r.fingerprint == "ubuntu-server|ssh.listeners_unexpected|8081/docker-proxy"
    assert r.is_finding
    f = r.as_finding("new")
    assert f["metric"] == "ssh.listeners_unexpected" and f["trend"] == "new"
    assert set(f) >= {"host", "metric", "severity", "trend", "summary", "detail", "recommendation", "fingerprint"}
    assert not CheckResult("x", "h", "-", "note", "info", "fact").is_finding
    assert not CheckResult("x", "h", "-", "unavailable", "warning", "n/a").is_finding


def test_clean_subject_is_stable_and_bounded():
    assert clean_subject(" root@pam ") == "root@pam"
    assert clean_subject("a b|c") == "a_b_c"
    assert clean_subject("") == "-"
    assert len(clean_subject("x" * 200)) == 64


def test_bundle_expanded_and_missing():
    b = EvidenceBundle(items={"pve.vm_config[100]": Evidence("pve.vm_config[100]", "ok", body={}),
                              "pve.vm_config[103]": Evidence("pve.vm_config[103]", "ok", body={})})
    assert set(b.expanded("pve.vm_config")) == {"100", "103"}
    assert b.get("nope").status == "error" and not b.get("nope").usable
```

- [ ] Run `.venv/bin/pytest tests/test_security_catalogue.py -q` — expect `ModuleNotFoundError: No module named 'heim.security'`.
- [ ] Create `src/heim/security/__init__.py`:

```python
"""Weekly security audit — the PURE half (no I/O, fully unit-tested).

catalogue.py  loads config/security/checks.yaml and refuses anything that is
              not a read: SSH lines go through guard_command, HA paths through
              guard_ha_path, PVE paths through PVE_AUDIT_ALLOW (the audit's own
              GET allowlist — wider than the model's proxmox_guard on purpose,
              and never exposed to the model).
evaluate*.py  turn an EvidenceBundle into CheckResults (ok/fail/note/unavailable).
diff.py       week-over-week: new / persisting / resolved / carried.
report.py     the deterministic '## Summary' report, digests, Loki events.

I/O lives in pipelines/security_sources.py (fetch) and pipelines/security_audit.py.
"""
```

- [ ] Create `src/heim/security/types.py`:

```python
"""Data types shared by the security-audit modules. Pure."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "warning", "info")
RESULT_STATUSES = ("ok", "fail", "note", "unavailable")
EVIDENCE_STATUSES = ("ok", "empty", "error", "timeout", "denied", "blocked")

_SUBJECT_BAD = re.compile(r"[^A-Za-z0-9_.:/@=+-]+")
SUBJECT_MAX = 64


def clean_subject(s: object) -> str:
    """Fingerprint-safe subject: fixed charset, ≤ 64 chars, never empty.

    The subject is the third fingerprint segment (``host|check_id|subject``),
    so it must be a stable identifier (a user id, a port/process, a unit
    name) — never a count or a sentence.
    """
    t = _SUBJECT_BAD.sub("_", str(s if s is not None else "").strip()).strip("_")
    return (t or "-")[:SUBJECT_MAX]


@dataclass(frozen=True)
class SourceSpec:
    key: str
    kind: str            # pve | ha | prom | ssh
    target: str          # API path / PromQL / shell line (may contain {vmid} or {container})
    control: str = ""    # sibling source that must be non-empty for an empty result to count
    expand: str = ""     # "" | "vmid" | "container"


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    severity: str
    sources: tuple[str, ...]
    params: dict = field(default_factory=dict)
    recommendation: str = ""
    compound: bool = False     # evaluated over other checks' results, not evidence


@dataclass
class Evidence:
    key: str
    status: str                 # one of EVIDENCE_STATUSES
    body: object = None         # parsed JSON (API) / text (SSH)
    http_status: int = 0
    exit_code: int | None = None
    stderr: str = ""
    detail: str = ""            # human reason for a non-ok status
    target: str = ""            # what was actually fetched/run

    @property
    def usable(self) -> bool:
        return self.status in ("ok", "empty")


@dataclass
class EvidenceBundle:
    items: dict[str, Evidence] = field(default_factory=dict)
    collected_at: str = ""

    def get(self, key: str) -> Evidence:
        return self.items.get(key) or Evidence(key, "error", detail="not collected")

    def expanded(self, prefix: str) -> dict[str, Evidence]:
        """``prefix[<x>]`` items → ``{x: evidence}`` (per-VM / per-container sources)."""
        out: dict[str, Evidence] = {}
        head = prefix + "["
        for k, e in self.items.items():
            if k.startswith(head) and k.endswith("]"):
                out[k[len(head):-1]] = e
        return out


@dataclass
class CheckResult:
    check_id: str
    host: str
    subject: str
    status: str                 # one of RESULT_STATUSES
    severity: str
    summary: str
    detail: str = ""
    recommendation: str = ""

    @property
    def fingerprint(self) -> str:
        return f"{self.host}|{self.check_id}|{self.subject}"

    @property
    def is_finding(self) -> bool:
        return self.status == "fail" and self.severity in ("critical", "warning")

    def as_finding(self, trend: str) -> dict:
        """The ``findings`` row shape (``store._FINDING_FIELDS`` + fingerprint)."""
        return {
            "host": self.host, "metric": self.check_id, "severity": self.severity,
            "trend": trend, "summary": self.summary, "detail": self.detail,
            "recommendation": self.recommendation, "fingerprint": self.fingerprint,
            "subject": self.subject,
        }
```

- [ ] Create `src/heim/security/catalogue.py`:

```python
"""Load and validate config/security/checks.yaml. Pure.

The catalogue is the ONLY place the audit's reads are defined; the model never
chooses one. So the loader is the gate: a line that is not provably read-only
makes the whole catalogue invalid (startup and `heim check` both fail loudly).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from heim.guards import guard_command, guard_ha_path
from heim.security.types import SEVERITIES, CheckSpec, SourceSpec


class CatalogueError(ValueError):
    """The catalogue asks for something the audit must not do."""


_ID_RE = re.compile(r"^[a-z]+\.[a-z0-9_]+$")
_KINDS = ("pve", "ha", "prom", "ssh")
_BAD_CHARS = re.compile(r"\s|\\|\.\.")
_N = r"/api2/json/nodes/homelab"

#: The audit's own GET allowlist against the hypervisor — deliberately wider
#: than heim.guards.proxmox_guard (which bounds what the MODEL may call) and
#: never handed to the model. Every path here answered 200 to the auditor
#: token (PAMAuditor: *.Audit + Sys.Syslog) in the live probe, except
#: /journal, which the investigator uses routinely. Nothing here mutates.
PVE_AUDIT_ALLOW: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api2/json/version$"),
    re.compile(r"^/api2/json/cluster/resources(\?type=vm)?$"),
    re.compile(r"^/api2/json/cluster/(backup|options|status)$"),
    re.compile(r"^/api2/json/cluster/firewall/(options|rules)$"),
    re.compile(r"^/api2/json/access/(users|acl|roles|tfa|domains|groups)$"),
    re.compile("^" + _N + r"/(status|services|dns|time|apt/versions|apt/repositories|"
               r"certificates/info|firewall/options|firewall/rules)$"),
    re.compile("^" + _N + r"/qemu/\d+/(config|status/current|firewall/options)$"),
    re.compile("^" + _N + r"/tasks\?(typefilter=vzdump&limit=\d{1,3}|errors=1&limit=\d{1,3})$"),
    re.compile("^" + _N + r"/journal\?lastentries=\d{1,4}$"),
)

_SUDO_FILE_READ = re.compile(r"^sudo\s+(-[A-Za-z]+\s+)*(cat|grep)\b", re.IGNORECASE)
_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")


def validate_pve_path(path: str, *, key: str = "") -> str:
    p = str(path or "").strip()
    probe = p.replace("{vmid}", "100")
    where = f" ({key})" if key else ""
    if not p.startswith("/api2/json/") or _BAD_CHARS.search(probe):
        raise CatalogueError(f"PVE path must start with /api2/json/ and contain no whitespace/'..'{where}: {p!r}")
    if not any(rx.search(probe) for rx in PVE_AUDIT_ALLOW):
        raise CatalogueError(f"PVE path not on PVE_AUDIT_ALLOW{where}: {p!r}")
    return p


def validate_ha_path(path: str, *, key: str = "") -> str:
    g = guard_ha_path(str(path or ""))
    if not g.allowed:
        raise CatalogueError(f"HA path rejected by guard_ha_path ({key}): {path!r} — {g.reason}")
    return str(path)


def validate_ssh_line(line: str, *, key: str = "") -> str:
    raw = str(line or "").strip()
    probe = raw.replace("{container}", "x")
    g = guard_command(probe)
    where = f" ({key})" if key else ""
    if not g.allowed:
        raise CatalogueError(f"SSH line rejected by guard_command{where}: {raw!r} — {g.reason}")
    for seg in _SEGMENT_SPLIT.split(probe):
        if _SUDO_FILE_READ.match(seg.strip()):
            raise CatalogueError(
                f"SSH line uses sudo cat/grep{where}: {raw!r} — the sudoers scope deliberately "
                f"excludes them; read world-readable files without sudo instead")
    return raw


def validate_promql(expr: str, *, key: str = "") -> str:
    e = str(expr or "").strip()
    if not e or len(e) > 1000:
        raise CatalogueError(f"PromQL must be 1..1000 chars ({key})")
    return e


_VALIDATORS = {"pve": validate_pve_path, "ha": validate_ha_path, "ssh": validate_ssh_line, "prom": validate_promql}


@dataclass
class Catalogue:
    sources: dict[str, SourceSpec]
    checks: list[CheckSpec]
    params: dict = field(default_factory=dict)
    pve_node: str = "homelab"
    ssh_host: str = "ubuntu-server"
    ha_host: str = "home-assistant"

    def check(self, check_id: str) -> CheckSpec:
        for c in self.checks:
            if c.id == check_id:
                return c
        raise KeyError(check_id)

    def by_kind(self, kind: str) -> list[SourceSpec]:
        return [s for s in self.sources.values() if s.kind == kind]


def load_catalogue(path: Path) -> Catalogue:
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    sources: dict[str, SourceSpec] = {}
    for raw in data.get("sources") or []:
        key, kind = str(raw.get("key") or ""), str(raw.get("kind") or "")
        if not _ID_RE.match(key) or key in sources:
            raise CatalogueError(f"bad or duplicate source key {key!r}")
        if kind not in _KINDS:
            raise CatalogueError(f"source {key}: kind must be one of {_KINDS}, got {kind!r}")
        expand = str(raw.get("expand") or "")
        if expand not in ("", "vmid", "container"):
            raise CatalogueError(f"source {key}: expand must be '', 'vmid' or 'container'")
        target = _VALIDATORS[kind](str(raw.get("target") or ""), key=key)
        sources[key] = SourceSpec(key=key, kind=kind, target=target,
                                  control=str(raw.get("control") or ""), expand=expand)
    for s in sources.values():
        if s.control and s.control not in sources:
            raise CatalogueError(f"source {s.key}: control {s.control!r} is not a source")

    checks: list[CheckSpec] = []
    seen: set[str] = set()
    for raw in data.get("checks") or []:
        cid = str(raw.get("id") or "")
        if not _ID_RE.match(cid) or cid in seen:
            raise CatalogueError(f"bad or duplicate check id {cid!r}")
        seen.add(cid)
        sev = str(raw.get("severity") or "")
        if sev not in SEVERITIES:
            raise CatalogueError(f"check {cid}: severity must be one of {SEVERITIES}, got {sev!r}")
        srcs = tuple(str(s) for s in (raw.get("sources") or []))
        for s in srcs:
            if s not in sources:
                raise CatalogueError(f"check {cid}: unknown source {s!r}")
        checks.append(CheckSpec(
            id=cid, title=str(raw.get("title") or cid), severity=sev, sources=srcs,
            params=dict(raw.get("params") or {}), recommendation=str(raw.get("recommendation") or ""),
            compound=bool(raw.get("compound", False)),
        ))
    if not checks:
        raise CatalogueError(f"{path}: no checks defined")
    return Catalogue(
        sources=sources, checks=checks, params=dict(data.get("params") or {}),
        pve_node=str(data.get("pve_node") or "homelab"),
        ssh_host=str(data.get("ssh_host") or "ubuntu-server"),
        ha_host=str(data.get("ha_host") or "home-assistant"),
    )
```

- [ ] Create `config/security/checks.yaml` (the whole catalogue; `homelab` is the PVE node name, exactly as `guards/proxmox_guard.py` hard-codes it — not deployment identity):

```yaml
# Weekly read-only security audit — sources, checks, allowlists.
# Everything the audit READS is listed here and nowhere else; the model never
# chooses a read. The loader (heim.security.catalogue) refuses any SSH line
# guard_command would block or that uses sudo cat/grep, any HA path outside
# guard_ha_path, and any PVE path outside PVE_AUDIT_ALLOW (GET-only).
pve_node: homelab
ssh_host: ubuntu-server
ha_host: home-assistant

params:
  expected_offline_vms: [monitor-box]     # powered off by design: "stopped" is not a finding

sources:
  - {key: pve.version,            kind: pve, target: /api2/json/version}
  - {key: pve.node_status,        kind: pve, target: /api2/json/nodes/homelab/status}
  - {key: pve.resources_vm,       kind: pve, target: "/api2/json/cluster/resources?type=vm"}
  - {key: pve.access_users,       kind: pve, target: /api2/json/access/users}
  - {key: pve.access_acl,         kind: pve, target: /api2/json/access/acl,   control: pve.access_users}
  - {key: pve.access_roles,       kind: pve, target: /api2/json/access/roles}
  - {key: pve.access_tfa,         kind: pve, target: /api2/json/access/tfa,   control: pve.access_users}
  - {key: pve.fw_cluster_options, kind: pve, target: /api2/json/cluster/firewall/options}
  - {key: pve.fw_cluster_rules,   kind: pve, target: /api2/json/cluster/firewall/rules, control: pve.fw_cluster_options}
  - {key: pve.fw_node_options,    kind: pve, target: /api2/json/nodes/homelab/firewall/options}
  - {key: pve.fw_node_rules,      kind: pve, target: /api2/json/nodes/homelab/firewall/rules, control: pve.fw_node_options}
  - {key: pve.fw_vm_options,      kind: pve, target: "/api2/json/nodes/homelab/qemu/{vmid}/firewall/options", expand: vmid}
  - {key: pve.vm_config,          kind: pve, target: "/api2/json/nodes/homelab/qemu/{vmid}/config", expand: vmid}
  - {key: pve.vm_status,          kind: pve, target: "/api2/json/nodes/homelab/qemu/{vmid}/status/current", expand: vmid}
  - {key: pve.apt_versions,       kind: pve, target: /api2/json/nodes/homelab/apt/versions}
  - {key: pve.apt_repositories,   kind: pve, target: /api2/json/nodes/homelab/apt/repositories}
  - {key: pve.certificates,       kind: pve, target: /api2/json/nodes/homelab/certificates/info}
  - {key: pve.backup_jobs,        kind: pve, target: /api2/json/cluster/backup, control: pve.resources_vm}
  - {key: pve.tasks_vzdump,       kind: pve, target: "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20"}
  - {key: pve.tasks_errors,       kind: pve, target: "/api2/json/nodes/homelab/tasks?errors=1&limit=50", control: pve.tasks_vzdump}
  - {key: pve.services,           kind: pve, target: /api2/json/nodes/homelab/services}
  - {key: pve.journal,            kind: pve, target: "/api2/json/nodes/homelab/journal?lastentries=1000"}

  - {key: ha.config,              kind: ha,  target: /api/config}
  - {key: ha.states,              kind: ha,  target: /api/states}

  - {key: prom.reboot_required,   kind: prom, target: node_reboot_required}
  - {key: prom.apt_pending,       kind: prom, target: "sum by (instance) (apt_upgrades_pending)"}
  - {key: prom.apt_present,       kind: prom, target: "count by (instance) (node_exporter_build_info)"}
  - {key: prom.failed_units,      kind: prom, target: 'node_systemd_unit_state{state="failed"} == 1'}
  - {key: prom.timex,             kind: prom, target: node_timex_sync_status}
  - {key: prom.up,                kind: prom, target: up}
  - {key: prom.os_info,           kind: prom, target: node_os_info}

  # ubuntu-server: no sudo except ss / agent-docker (sudoers), and `sudo -n -l` (own rights).
  - {key: ssh.listeners,          kind: ssh, target: "sudo ss -tunlpH"}
  - {key: ssh.sshd_config,        kind: ssh, target: "cat /etc/ssh/sshd_config"}
  - {key: ssh.sshd_config_d,      kind: ssh, target: "cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null"}
  - {key: ssh.sshd_config_d_ls,   kind: ssh, target: "ls -la /etc/ssh/sshd_config.d/"}
  # no -q: it would hide the "not seeing messages from other users" hint that tells 0 from no-permission
  - {key: ssh.auth_fail_count,    kind: ssh, target: "journalctl --no-pager -u ssh -u sshd --since=-7d -o cat | grep -c -E 'Failed password|Invalid user|maximum authentication attempts'"}
  - {key: ssh.auth_fail_sample,   kind: ssh, target: "journalctl --no-pager -u ssh -u sshd --since=-7d -o cat | grep -E 'Failed password|Invalid user|maximum authentication attempts' | tail -n 20"}
  - {key: ssh.updates_available,  kind: ssh, target: "cat /var/lib/update-notifier/updates-available"}
  - {key: ssh.auto_upgrades,      kind: ssh, target: "cat /etc/apt/apt.conf.d/20auto-upgrades"}
  - {key: ssh.unit_states,        kind: ssh, target: "systemctl is-active ufw nftables fail2ban unattended-upgrades ssh"}
  - {key: ssh.world_writable,     kind: ssh, target: "find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null"}
  - {key: ssh.last_logins,        kind: ssh, target: "last -w -F -n 100 -s -7days"}
  - {key: ssh.login_shells,       kind: ssh, target: "grep -E ':/bin/(ba|z|da)?sh$' /etc/passwd"}
  - {key: ssh.sudo_scope,         kind: ssh, target: "sudo -n -l"}
  - {key: ssh.docker_ps,          kind: ssh, target: "sudo agent-docker ps"}
  - {key: ssh.docker_inspect,     kind: ssh, target: "sudo agent-docker inspect {container}", expand: container}
  - {key: ssh.docker_images,      kind: ssh, target: "sudo agent-docker images"}

checks:
  # ---------------------------------------------------------------- Proxmox
  - id: pve.tfa_missing
    title: Interactive Proxmox accounts without a second factor
    severity: warning
    sources: [pve.access_tfa, pve.access_users]
    params: {interactive_users: ["root@pam"]}
    recommendation: Add a TOTP or WebAuthn factor under Datacenter → Permissions → Two Factor for every account a person logs in with.
  - id: pve.firewall_disabled
    title: Proxmox firewall state (cluster, node, per-VM)
    severity: warning
    sources: [pve.fw_cluster_options, pve.fw_cluster_rules, pve.fw_node_options, pve.fw_node_rules, pve.fw_vm_options, pve.vm_config]
    recommendation: Either enable the datacenter firewall with an explicit rule set, or remove firewall=1 from the NICs so the config states what is actually enforced. Mark as false positive if "no PVE firewall" is the intended design.
  - id: pve.pending_updates
    title: Proxmox host packages with a newer version available
    severity: warning
    sources: [pve.apt_versions]
    recommendation: Schedule `apt update && apt dist-upgrade` on the hypervisor in a maintenance window; reboot if the kernel changed.
  - id: pve.pending_updates_sensitive
    title: Security-relevant Proxmox packages pending
    severity: warning
    sources: [pve.apt_versions]
    params:
      classes:
        kernel: [proxmox-kernel, pve-kernel, linux-image]
        microcode: [amd64-microcode, intel-microcode]
        ssh: [openssh]
        firewall: [pve-firewall, proxmox-firewall]
        hypervisor: [pve-qemu-kvm, qemu-server, pve-manager, libpve-access-control, pve-container]
        tls: [openssl, libssl, ca-certificates]
    recommendation: Prioritise these classes in the next hypervisor update window.
  - id: pve.repo_security
    title: Debian security repository enabled on the hypervisor
    severity: critical
    sources: [pve.apt_repositories]
    recommendation: Re-enable the Debian *-security suite in /etc/apt/sources.list(.d); without it security fixes never arrive.
  - id: pve.repo_risky
    title: Test/enterprise repositories
    severity: warning
    sources: [pve.apt_repositories]
    recommendation: Disable pve-test on a production node; pve-enterprise needs a subscription or apt update fails.
  - id: pve.cert_expiry
    title: Proxmox web/API certificate validity
    severity: warning
    sources: [pve.certificates]
    params: {warning_days: 90, critical_days: 30}
    recommendation: Renew via `pvecm updatecerts` (internal CA) or the ACME plugin before expiry.
  - id: pve.acl_privileged
    title: Non-root principals holding modify privileges
    severity: warning
    sources: [pve.access_acl, pve.access_roles]
    recommendation: Keep service accounts on *Auditor roles; move any human account with modify rights behind TFA.
  - id: pve.backup_coverage
    title: Running VMs without a backup job
    severity: warning
    sources: [pve.backup_jobs, pve.resources_vm]
    recommendation: Add the VM to a vzdump job (Datacenter → Backup) or document why it is excluded.
  - id: pve.backup_last_status
    title: Result of the most recent backup tasks
    severity: warning
    sources: [pve.tasks_vzdump, pve.backup_jobs]
    params: {max_age_days: 8}
    recommendation: Open the failed task's log in the PVE UI; check the target storage's free space and the guest agent.
  - id: pve.failed_tasks
    title: Failed Proxmox tasks in the last 7 days
    severity: info
    sources: [pve.tasks_errors]
  - id: pve.services_dead
    title: Security-relevant hypervisor services not running
    severity: warning
    sources: [pve.services]
    params:
      required_active: [sshd, pveproxy, pvedaemon, pve-firewall, pvefw-logger]
      time_sync_any: [chrony, systemd-timesyncd]
    recommendation: "`systemctl status <service>` on the hypervisor and restart it deliberately."
  - id: pve.auth_failures
    title: Failed SSH / PVE authentication attempts in the hypervisor journal
    severity: warning
    sources: [pve.journal]
    params: {critical_count: 50}
    recommendation: Identify the source addresses in the journal; if they are outside your LAN/Tailscale, close the exposure at the router; consider key-only SSH on the hypervisor.
  - id: pve.vm_hardening
    title: VM configuration hygiene (protection, passthrough, guest agent)
    severity: info
    sources: [pve.vm_config]
  - id: pve.stopped_vm_onboot
    title: Stopped VMs that would start on host boot
    severity: info
    sources: [pve.vm_config, pve.vm_status]
  - id: pve.secureboot
    title: Secure Boot state of the hypervisor
    severity: info
    sources: [pve.node_status]

  # ---------------------------------------------------------- Home Assistant
  - id: ha.pending_updates_sensitive
    title: Security-sensitive Home Assistant updates pending
    severity: warning
    sources: [ha.states]
    params:
      sensitive_patterns: [core, operating_system, supervisor, vaultwarden, bitwarden, letsencrypt, let_s_encrypt, ssh, adguard, nginx, proxy, wireguard, tailscale, cloudflared]
    recommendation: Apply core/OS/supervisor updates first, then the password vault, TLS and remote-access add-ons.
  - id: ha.pending_updates_other
    title: Other Home Assistant updates pending
    severity: info
    sources: [ha.states]
  - id: ha.core_update_exposed
    title: Publicly reachable Home Assistant running an outdated core
    severity: critical
    sources: [ha.states, ha.config]
    params: {core_entity: update.home_assistant_core_update}
    recommendation: Update HA core now, or temporarily disable the port-forward/DynDNS exposure until it is updated.
  - id: ha.external_url
    title: Home Assistant external URL
    severity: info
    sources: [ha.config]
  - id: ha.safe_mode
    title: Home Assistant running in safe or recovery mode
    severity: warning
    sources: [ha.config]
    recommendation: Fix the failing integration/config and restart normally; safe mode disables custom components and some protections.
  - id: ha.cert_expiry
    title: Certificate-expiry sensors
    severity: warning
    sources: [ha.states]
    params: {warning_days: 30, critical_days: 14}
    recommendation: Renew the certificate; for sensors reporting unknown/unavailable, fix the cert-expiry integration's host/port.
  - id: ha.login_notifications
    title: Failed-login / IP-ban notifications in Home Assistant
    severity: warning
    sources: [ha.states]
    recommendation: Review the notification's source address; keep ip_ban_enabled on.
  - id: ha.external_dirs
    title: Allowlisted external directories
    severity: info
    sources: [ha.config]
    params: {allowed: [/media, /config/www, /share]}

  # -------------------------------------------------------------- Prometheus
  - id: prom.reboot_required
    title: Hosts needing a reboot to apply installed updates
    severity: warning
    sources: [prom.reboot_required]
    recommendation: Reboot the guest (or hypervisor) in a maintenance window.
  - id: prom.apt_pending
    title: Pending apt upgrades as reported by node_exporter
    severity: warning
    sources: [prom.apt_pending, prom.apt_present]
    recommendation: Apply the upgrades; for hosts flagged "collector absent", install prometheus-node-exporter-collectors (owner-side step 2).
  - id: prom.failed_units
    title: systemd units in failed state
    severity: warning
    sources: [prom.failed_units]
    params: {expected_failed: []}
    recommendation: "`systemctl status <unit>`; if the unit is irrelevant hardware support, mask it or list it under expected_failed."
  - id: prom.time_sync
    title: Clock not synchronised
    severity: warning
    sources: [prom.timex]
    recommendation: Check chrony/timesyncd on the host; TLS and log correlation depend on it.
  - id: prom.targets_down
    title: Prometheus targets down (blind spots for this audit)
    severity: warning
    sources: [prom.up]
    recommendation: Restore the exporter; until then this audit cannot see that host.
  - id: prom.os_eol
    title: Operating system end-of-life horizon
    severity: warning
    sources: [prom.os_info]
    params:
      warning_days: 180
      review_by: "2027-06-01"           # re-check these dates against the vendors by then
      os_eol:
        "ubuntu 24.04": "2029-05-31"     # standard support
        "debian 13": "2028-06-30"        # regular (non-LTS) support, approximate
    recommendation: Plan the distribution upgrade before the date; extend the os_eol table when a new OS appears.

  # ------------------------------------------------- ubuntu-server via SSH
  - id: ssh.listeners_unexpected
    title: Services listening on all interfaces
    severity: warning
    sources: [ssh.listeners]
    params:
      expected_ports: {"22": sshd, "9090": prometheus, "9100": node_exporter, "3100": loki, "8081": cadvisor}
      critical_ports: {"2375": "Docker API without TLS", "2376": "Docker API", "23": telnet, "3389": rdp, "5900": vnc}
    recommendation: Bind the service to 127.0.0.1 or a Docker-internal network, or add it to expected_ports once reviewed.
  - id: ssh.sshd_password_auth
    title: SSH password authentication
    severity: warning
    sources: [ssh.sshd_config, ssh.sshd_config_d, ssh.sshd_config_d_ls]
    recommendation: Set `PasswordAuthentication no` in a drop-in under /etc/ssh/sshd_config.d/ (check 50-cloud-init.conf) after confirming key access.
  - id: ssh.sshd_root_login
    title: SSH root login
    severity: critical
    sources: [ssh.sshd_config, ssh.sshd_config_d, ssh.sshd_config_d_ls]
    recommendation: Set `PermitRootLogin prohibit-password` or `no`.
  - id: ssh.sshd_empty_passwords
    title: SSH empty passwords
    severity: critical
    sources: [ssh.sshd_config, ssh.sshd_config_d, ssh.sshd_config_d_ls]
    recommendation: Set `PermitEmptyPasswords no`.
  - id: ssh.sshd_hardening
    title: Other sshd directives worth a look
    severity: info
    sources: [ssh.sshd_config, ssh.sshd_config_d, ssh.sshd_config_d_ls]
  - id: ssh.auth_failures
    title: Failed SSH authentication attempts (7 days)
    severity: warning
    sources: [ssh.auth_fail_count, ssh.auth_fail_sample]
    params: {critical_count: 100}
    recommendation: Check the sample lines for the source addresses; if external, the SSH port is exposed — close it at the router and rely on Tailscale.
  - id: ssh.pending_security_updates
    title: Pending Ubuntu security updates
    severity: warning
    sources: [ssh.updates_available]
    recommendation: "`sudo apt update && sudo apt upgrade` on ubuntu-server; enable unattended-upgrades for security pockets."
  - id: ssh.auto_upgrades_off
    title: Unattended security upgrades disabled
    severity: warning
    sources: [ssh.auto_upgrades, ssh.unit_states]
    recommendation: "`dpkg-reconfigure unattended-upgrades` and confirm the unit is active."
  - id: ssh.host_firewall
    title: Host firewall units
    severity: info
    sources: [ssh.unit_states]
  - id: ssh.fail2ban_absent
    title: fail2ban presence
    severity: info
    sources: [ssh.unit_states]
  - id: ssh.world_writable
    title: World-writable files under /etc, /usr/local, /opt
    severity: warning
    sources: [ssh.world_writable]
    recommendation: "`chmod o-w <path>` after checking what created it."
  - id: ssh.external_logins
    title: Logins from outside trusted networks (7 days)
    severity: warning
    sources: [ssh.last_logins]
    params:
      trusted_cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "fd00::/8", "::1/128"]
    recommendation: Confirm each address is yours; otherwise rotate keys and review the router's port-forwards.
  - id: ssh.login_shell_users
    title: Accounts with a login shell
    severity: info
    sources: [ssh.login_shells]
  - id: ssh.agent_sudo_scope
    title: sudo rights of the monitoring user
    severity: warning
    sources: [ssh.sudo_scope]
    params: {expected_sudo_binaries: [du, df, findmnt, lsof, ls, ss, agent-docker]}
    recommendation: Trim /etc/sudoers.d/<agent> back to the read-only set; the agent must never gain a mutating command.
  - id: ssh.docker_privileged
    title: Containers with elevated host access
    severity: warning
    sources: [ssh.docker_inspect]
    recommendation: Drop --privileged/host networking/added capabilities where the image does not need them; mount docker.sock read-only and only where required (cAdvisor).
  - id: ssh.docker_stale_images
    title: Container images older than six months
    severity: info
    sources: [ssh.docker_images]
    params: {max_age_months: 6}

  # ---------------------------------------------------------------- compound
  - id: net.no_firewall_any_layer
    title: No packet filter at any layer for ubuntu-server
    severity: warning
    sources: []
    compound: true
    recommendation: Pick one layer — the Proxmox VM firewall or ufw/nftables in the guest — and enable it with an explicit allow list.
```

- [ ] Run `.venv/bin/pytest tests/test_security_catalogue.py -q` — expect 33 passed. Run `.venv/bin/pytest -q` — expect 834 passed.
- [ ] Commit: `git add src/heim/security config/security tests/test_security_catalogue.py && git commit -m "security: pure types, validated check catalogue loader, and the v1 catalogue"`

### Task 3: Pure parsers for the raw evidence

**Files**
- Create `src/heim/security/parsers.py`, `tests/test_security_parsers.py`.

**Interfaces**
- Produces: `parse_ss_listeners(text) -> list[dict]` (`proto, local, port, process, wildcard`), `parse_sshd_config(text) -> dict[str, str]` (first-wins, lowercase keys, stops at `Match`), `unreadable_dropins(ls_text) -> list[str]`, `parse_updates_available(text) -> tuple[int, int]` (total, security), `parse_last_hosts(text) -> list[str]`, `docker_names(ps_text) -> list[str]`, `parse_docker_images(text) -> list[tuple[str, int]]` (repo:tag, age months), `apt_pending(body) -> list[dict]`, `vmids_from_resources(body) -> dict[str, str]`, `is_public_host(url) -> bool`, `ip_in_cidrs(ip, cidrs) -> bool`, `unit_states(target, text) -> dict[str, str]`, `NAME_RE`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_parsers.py
"""Parsers for the audit's raw evidence — pure, fixture-driven."""
from heim.security.parsers import (
    apt_pending, docker_names, ip_in_cidrs, is_public_host, parse_docker_images, parse_last_hosts,
    parse_ss_listeners, parse_sshd_config, parse_updates_available, unit_states, unreadable_dropins,
    vmids_from_resources,
)

SS = """tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096       127.0.0.53%lo:53      0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=14))
tcp   LISTEN 0      4096               *:8081            *:*    users:(("docker-proxy",pid=2001,fd=4))
tcp   LISTEN 0      4096            [::]:9100         [::]:*    users:(("node_exporter",pid=900,fd=3))
udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=700,fd=12))
"""


def test_ss_listeners_wildcard_and_process():
    rows = parse_ss_listeners(SS)
    by_port = {r["port"]: r for r in rows}
    assert by_port["22"]["process"] == "sshd" and by_port["22"]["wildcard"]
    assert by_port["53"]["wildcard"] is False           # loopback-scoped
    assert by_port["8081"]["wildcard"] and by_port["8081"]["process"] == "docker-proxy"
    assert by_port["9100"]["wildcard"] and by_port["9100"]["proto"] == "tcp"
    assert by_port["5353"]["proto"] == "udp"


def test_sshd_config_first_wins_and_match_stops():
    text = "PasswordAuthentication no\n# PasswordAuthentication yes\nPasswordAuthentication yes\n" \
           "PermitRootLogin=prohibit-password\nMatch User git\n  PasswordAuthentication yes\n"
    conf = parse_sshd_config(text)
    assert conf["passwordauthentication"] == "no"
    assert conf["permitrootlogin"] == "prohibit-password"
    assert "match" not in conf


def test_unreadable_dropins_from_ls():
    ls = ("total 12\ndrwxr-xr-x 2 root root 4096 Jan  1 00:00 .\n"
          "-rw-r--r-- 1 root root  100 Jan  1 00:00 50-cloud-init.conf\n"
          "-rw------- 1 root root   40 Jan  1 00:00 99-secret.conf\n")
    assert unreadable_dropins(ls) == ["99-secret.conf"]


def test_updates_available_counts():
    text = "\n12 updates can be applied immediately.\n5 of these updates are standard security updates.\n"
    assert parse_updates_available(text) == (12, 5)
    assert parse_updates_available("0 updates can be applied immediately.\n") == (0, 0)
    assert parse_updates_available("1 update can be applied immediately.\n1 of these updates is a standard security update.\n") == (1, 1)
    assert parse_updates_available("") == (0, 0)


def test_last_hosts_skips_reboot_and_trailer():
    text = ("alice  pts/0  192.168.1.20   Mon Sep 21 08:00:00 2026   still logged in\n"
            "reboot system boot 6.8.0-139-gen  Sun Sep 20 03:10:00 2026 - Sun Sep 20 03:12:00 2026 (00:02)\n"
            "alice  pts/1  100.101.102.103 Sat Sep 19 09:00:00 2026 - Sat Sep 19 09:30:00 2026 (00:30)\n"
            "bob    tty1                   Fri Sep 18 09:00:00 2026 - down (01:00)\n"
            "\nwtmp begins Tue Sep  1 00:00:00 2026\n")
    assert parse_last_hosts(text) == ["192.168.1.20", "100.101.102.103"]


def test_docker_names_and_images():
    ps = ("CONTAINER ID   IMAGE             COMMAND   CREATED       STATUS       PORTS   NAMES\n"
          "0123456789ab   grafana/grafana   \"/run.sh\" 3 weeks ago   Up 3 weeks           grafana\n"
          "abcdef012345   prom/prometheus   \"/bin/pr\" 3 weeks ago   Up 3 weeks           prometheus\n")
    assert docker_names(ps) == ["grafana", "prometheus"]
    images = ("REPOSITORY        TAG      IMAGE ID       CREATED        SIZE\n"
              "grafana/grafana   latest   aaa            3 weeks ago    400MB\n"
              "old/thing         v1       bbb            14 months ago  90MB\n"
              "ancient/thing     v0       ccc            2 years ago    90MB\n")
    assert parse_docker_images(images) == [("grafana/grafana:latest", 0), ("old/thing:v1", 14), ("ancient/thing:v0", 24)]


def test_apt_pending_and_vmids():
    body = [{"Package": "pve-firewall", "OldVersion": "6.0.4", "Version": "6.0.6"},
            {"Package": "zsh", "OldVersion": "5.9", "Version": "5.9"},
            {"Package": "qemu-server", "OldVersion": "9.0.1", "Version": "9.0.3"}]
    assert [r["Package"] for r in apt_pending(body)] == ["pve-firewall", "qemu-server"]
    res = [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"},
           {"vmid": 102, "name": "monitor-box", "status": "stopped", "type": "qemu"}]
    assert vmids_from_resources(res) == {"100": "ubuntu-server", "102": "monitor-box"}


def test_public_host_and_cidrs():
    assert is_public_host("https://myhome.example-dyndns.net:8123")
    assert not is_public_host("http://192.168.1.5:8123")
    assert not is_public_host("http://homeassistant.local:8123")
    assert not is_public_host("https://ha.tailnet.ts.net")
    assert not is_public_host("")
    cidrs = ["192.168.0.0/16", "100.64.0.0/10", "::1/128"]
    assert ip_in_cidrs("192.168.1.20", cidrs) and ip_in_cidrs("100.101.102.103", cidrs)
    assert not ip_in_cidrs("203.0.113.9", cidrs)
    assert not ip_in_cidrs("not-an-ip", cidrs)


def test_unit_states_zips_command_and_output():
    st = unit_states("systemctl is-active ufw nftables fail2ban", "inactive\nactive\ninactive\n")
    assert st == {"ufw": "inactive", "nftables": "active", "fail2ban": "inactive"}
```

- [ ] Run `.venv/bin/pytest tests/test_security_parsers.py -q` — expect `ModuleNotFoundError: No module named 'heim.security.parsers'`.
- [ ] Create `src/heim/security/parsers.py`:

```python
"""Pure parsers for the audit's raw evidence (ss, sshd_config, journald hints,
update-notifier, last, docker ps/images, PVE JSON). No I/O."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_WILDCARD = {"0.0.0.0", "*", "[::]", "::"}
_PROC_RE = re.compile(r'users:\(\("([^"]+)"')
_PRIVATE_SUFFIXES = (".local", ".lan", ".home", ".internal", ".ts.net", ".home.arpa", ".localdomain")


def parse_ss_listeners(text: str) -> list[dict]:
    """``sudo ss -tunlpH`` rows → proto/local/port/process/wildcard."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%", 1)[0]            # 127.0.0.53%lo → 127.0.0.53
        m = _PROC_RE.search(line)
        rows.append({"proto": parts[0], "local": local, "port": port,
                     "process": m.group(1) if m else "?", "wildcard": addr in _WILDCARD})
    return rows


def parse_sshd_config(text: str) -> dict[str, str]:
    """sshd semantics: the FIRST value for a keyword wins; ``Match`` blocks end
    the global section. Keys lowercased. Callers concatenate drop-ins first
    (Ubuntu's stock sshd_config Includes sshd_config.d/*.conf at the top)."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("match "):
            break
        parts = s.replace("=", " ", 1).split(None, 1)
        if len(parts) != 2:
            continue
        out.setdefault(parts[0].lower(), parts[1].strip())
    return out


def unreadable_dropins(ls_text: str) -> list[str]:
    """``ls -la`` lines for ``*.conf`` whose mode lacks the other-read bit."""
    out = []
    for line in (ls_text or "").splitlines():
        parts = line.split()
        if len(parts) >= 9 and parts[-1].endswith(".conf") and len(parts[0]) >= 10 and parts[0][7] != "r":
            out.append(parts[-1])
    return out


_UPD_TOTAL = re.compile(r"(\d+) updates? can be applied")
_UPD_SEC = re.compile(r"(\d+) of these updates? (?:is|are) (?:a )?standard security")


def parse_updates_available(text: str) -> tuple[int, int]:
    t = _UPD_TOTAL.search(text or "")
    s = _UPD_SEC.search(text or "")
    return (int(t.group(1)) if t else 0, int(s.group(1)) if s else 0)


def parse_last_hosts(text: str) -> list[str]:
    """Host column of ``last -w -F``; skips reboot rows, tty-only rows and the trailer."""
    hosts = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("reboot", "wtmp", "shutdown"):
            continue
        cand = parts[2]
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            continue
        hosts.append(cand)
    return hosts


def docker_names(ps_text: str) -> list[str]:
    """NAMES (last column) of ``docker ps``, header skipped, names validated."""
    names = []
    for line in (ps_text or "").splitlines()[1:]:
        parts = line.split()
        if parts and NAME_RE.match(parts[-1]):
            names.append(parts[-1])
    return names


_AGE = re.compile(r"(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago")
_MONTHS = {"second": 0, "minute": 0, "hour": 0, "day": 0, "week": 0, "month": 1, "year": 12}


def parse_docker_images(text: str) -> list[tuple[str, int]]:
    """``docker images`` → [(repo:tag, age in whole months)]."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        m = _AGE.search(line)
        months = int(m.group(1)) * _MONTHS[m.group(2)] if m else 0
        out.append((f"{parts[0]}:{parts[1]}", months))
    return out


def apt_pending(body: object) -> list[dict]:
    """``/nodes/<n>/apt/versions`` rows whose installed (OldVersion) differs from the candidate (Version)."""
    rows = []
    for r in body if isinstance(body, list) else []:
        if not isinstance(r, dict):
            continue
        old, new = str(r.get("OldVersion") or ""), str(r.get("Version") or "")
        if old and new and old != new:
            rows.append({"Package": str(r.get("Package") or "?"), "OldVersion": old, "Version": new})
    return rows


def vmids_from_resources(body: object) -> dict[str, str]:
    """``/cluster/resources?type=vm`` → {vmid: guest name} (qemu only)."""
    out: dict[str, str] = {}
    for r in body if isinstance(body, list) else []:
        if isinstance(r, dict) and r.get("vmid") is not None and str(r.get("type") or "qemu") == "qemu":
            out[str(r["vmid"])] = str(r.get("name") or f"vm{r['vmid']}")
    return out


def is_public_host(url: str) -> bool:
    host = (urlparse(str(url or "")).hostname or "").lower()
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return "." in host and not host.endswith(_PRIVATE_SUFFIXES)


def ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def unit_states(target: str, text: str) -> dict[str, str]:
    """``systemctl is-active a b c`` prints one state per unit, in argument order."""
    units = str(target or "").split()[2:]
    states = [l.strip() for l in (text or "").splitlines()]
    return {u: (states[i] if i < len(states) else "unknown") for i, u in enumerate(units)}
```

- [ ] Run `.venv/bin/pytest tests/test_security_parsers.py -q` — expect 9 passed. Full suite: 843 passed.
- [ ] Commit: `git add src/heim/security/parsers.py tests/test_security_parsers.py && git commit -m "security: pure parsers for ss, sshd_config, update-notifier, last, docker and PVE JSON"`

### Task 4: Evaluation core (control rule, dispatcher) and the Proxmox evaluators

**Files**
- Create `src/heim/security/evaluate.py`, `src/heim/security/evaluate_pve.py`, `tests/test_security_evaluate_pve.py`.

**Interfaces**
- Produces `EvalContext(now: datetime, instance_host_map: dict[str,str], hosts: tuple[str,...], pve_node: str, ssh_host: str, ha_host: str, vm_names: dict[str,str] = {}, expected_offline_vms: tuple[str,...] = ())` with `host_for_instance(instance) -> str`, `vm_name(vmid) -> str`.
- Produces helpers `ok(spec, host, subject)`, `fail(spec, host, subject, summary, *, detail="", severity=None)`, `note(spec, host, subject, summary, detail="")`, `unavailable(spec, host, reason)`, `default_host(spec, ctx)`, `gate_sources(spec, cat, ev) -> str` (empty = proceed), `evaluate(cat, ev, ctx) -> list[CheckResult]`.
- Produces `evaluate_pve.EVALUATORS: dict[str, Evaluator]` where `Evaluator = Callable[[CheckSpec, EvidenceBundle, EvalContext], list[CheckResult]]`, covering the 16 `pve.*` checks.
- Consumes `Catalogue`, parsers.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_evaluate_pve.py
"""Proxmox evaluators + the evaluation core (control rule, per-check isolation)."""
from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, evaluate, gate_sources
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)


def ctx(**kw) -> EvalContext:
    base = dict(now=NOW, instance_host_map={"10.0.0.2": "homelab", "10.0.0.10": "ubuntu-server", "10.0.0.4": "heim"},
                hosts=("heim", "home-assistant", "homelab", "ubuntu-server"), pve_node="homelab",
                ssh_host="ubuntu-server", ha_host="home-assistant", expected_offline_vms=("monitor-box",))
    base.update(kw)
    return EvalContext(**base)


def ev(key, body, status="ok", **kw) -> Evidence:
    return Evidence(key, status, body=body, **kw)


def bundle(*items: Evidence) -> EvidenceBundle:
    return EvidenceBundle(items={e.key: e for e in items})


def results_for(check_id, b: EvidenceBundle, c: EvalContext | None = None):
    return [r for r in evaluate(CAT, b, c or ctx()) if r.check_id == check_id]


USERS = [{"userid": "root@pam", "enable": 1}, {"userid": "auditor@pve", "enable": 1}, {"userid": "exporter@pve", "enable": 1}]


def test_tfa_missing_flags_root_only_when_control_proves_empty_is_genuine():
    b = bundle(ev("pve.access_tfa", [], status="empty"), ev("pve.access_users", USERS))
    rows = results_for("pve.tfa_missing", b)
    fails = [r for r in rows if r.status == "fail"]
    assert [r.subject for r in fails] == ["root@pam"] and fails[0].fingerprint == "homelab|pve.tfa_missing|root@pam"
    assert {r.subject for r in rows if r.status == "note"} == {"auditor@pve", "exporter@pve"}


def test_empty_list_without_a_working_control_is_unavailable_not_ok():
    b = bundle(ev("pve.access_tfa", [], status="empty"), ev("pve.access_users", None, status="denied", detail="HTTP 403"))
    rows = results_for("pve.tfa_missing", b)
    assert len(rows) == 1 and rows[0].status == "unavailable" and "not permitted" in rows[0].detail


def test_gate_sources_reports_missing_and_denied():
    spec = CAT.check("pve.acl_privileged")
    assert "not collected" in gate_sources(spec, CAT, bundle())
    b = bundle(ev("pve.access_acl", [], "empty"), ev("pve.access_roles", []), ev("pve.access_users", USERS))
    assert gate_sources(spec, CAT, b) == ""


def test_firewall_disabled_cluster_fail_and_vm_notes():
    b = bundle(ev("pve.fw_cluster_options", {"digest": "x"}), ev("pve.fw_cluster_rules", [], "empty"),
               ev("pve.fw_node_options", {"digest": "y"}), ev("pve.fw_node_rules", [], "empty"),
               ev("pve.fw_vm_options[100]", {"digest": "z"}), ev("pve.vm_config[100]", {"net0": "virtio=AA,bridge=vmbr0,firewall=1"}),
               ev("pve.resources_vm", [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"}]))
    rows = results_for("pve.firewall_disabled", b)
    assert any(r.status == "fail" and r.subject == "cluster" and r.host == "homelab" for r in rows)
    assert any(r.status == "note" and r.host == "ubuntu-server" and "firewall=1" in r.summary for r in rows)
    enabled = bundle(ev("pve.fw_cluster_options", {"enable": 1}), ev("pve.fw_cluster_rules", [{"a": 1}]),
                     ev("pve.fw_node_options", {}), ev("pve.fw_node_rules", [], "empty"))
    assert results_for("pve.firewall_disabled", enabled)[0].status == "ok"


APT = [{"Package": "proxmox-kernel-6.17", "OldVersion": "6.17.2-1", "Version": "6.17.13-21"},
       {"Package": "amd64-microcode", "OldVersion": "3.20240", "Version": "3.20250"},
       {"Package": "zsh", "OldVersion": "5.9", "Version": "5.9"}]


def test_pending_updates_and_sensitive_classes():
    b = bundle(ev("pve.apt_versions", APT))
    total = results_for("pve.pending_updates", b)
    assert total[0].status == "fail" and "2 of 3" in total[0].summary
    sens = {r.subject: r.status for r in results_for("pve.pending_updates_sensitive", b)}
    assert sens["kernel"] == "fail" and sens["microcode"] == "fail" and sens["ssh"] == "ok"
    assert results_for("pve.pending_updates", bundle(ev("pve.apt_versions", [APT[2]])))[0].status == "ok"


REPOS = {"files": [{"path": "/etc/apt/sources.list.d/debian.sources",
                    "repositories": [{"Enabled": 1, "Suites": ["trixie", "trixie-security"], "URIs": ["http://deb.debian.org/debian"]}]}],
         "standard-repos": [{"handle": "enterprise", "status": 0}, {"handle": "no-subscription", "status": 1}, {"handle": "test", "status": 0}]}


def test_repos():
    b = bundle(ev("pve.apt_repositories", REPOS))
    assert results_for("pve.repo_security", b)[0].status == "ok"
    assert all(r.status == "ok" for r in results_for("pve.repo_risky", b))
    bad = {"files": [{"repositories": [{"Enabled": 1, "Suites": ["trixie"], "URIs": ["x"]}]}],
           "standard-repos": [{"handle": "test", "status": 1}]}
    b2 = bundle(ev("pve.apt_repositories", bad))
    assert results_for("pve.repo_security", b2)[0].severity == "critical"
    assert results_for("pve.repo_risky", b2)[0].subject == "pve-test" and results_for("pve.repo_risky", b2)[0].status == "fail"


def test_cert_expiry_thresholds_and_internal_ca_note():
    day = 86400
    certs = [{"filename": "pve-ssl.pem", "notafter": int(NOW.timestamp()) + 423 * day, "issuer": "CN=Proxmox Virtual Environment,OU=abc"},
             {"filename": "pveproxy-ssl.pem", "notafter": int(NOW.timestamp()) + 20 * day, "issuer": "CN=R3"}]
    rows = results_for("pve.cert_expiry", bundle(ev("pve.certificates", certs)))
    by = {(r.subject, r.status): r for r in rows}
    assert ("pve-ssl.pem", "ok") in by and by[("pveproxy-ssl.pem", "fail")].severity == "critical"
    assert any(r.status == "note" and "internal PVE CA" in r.summary for r in rows)


def test_acl_privileged():
    roles = [{"roleid": "PAMAuditor", "privs": "Datastore.Audit,Sys.Audit,Sys.Syslog,VM.Audit"},
             {"roleid": "PVEVMAdmin", "privs": "VM.Allocate,VM.Config.CPU,VM.PowerMgmt"}]
    acl = [{"ugid": "auditor@pve", "roleid": "PAMAuditor", "path": "/", "type": "user"},
           {"ugid": "ops@pve", "roleid": "PVEVMAdmin", "path": "/vms", "type": "user"},
           {"ugid": "root@pam", "roleid": "Administrator", "path": "/", "type": "user"}]
    rows = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl), ev("pve.access_roles", roles), ev("pve.access_users", USERS)))
    assert {r.subject: r.status for r in rows} == {"auditor@pve": "ok", "ops@pve": "fail"}


RES = [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"},
       {"vmid": 102, "name": "monitor-box", "status": "stopped", "type": "qemu"},
       {"vmid": 103, "name": "heim", "status": "running", "type": "qemu"}]


def test_backup_coverage_and_last_status():
    jobs = [{"id": "j1", "enabled": 1, "vmid": "100,101"}, {"id": "j2", "enabled": 1, "vmid": "103"}]
    rows = results_for("pve.backup_coverage", bundle(ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES)))
    st = {r.host: r.status for r in rows}
    assert st == {"ubuntu-server": "ok", "heim": "ok", "monitor-box": "note"}
    uncovered = results_for("pve.backup_coverage", bundle(ev("pve.backup_jobs", [jobs[0]]), ev("pve.resources_vm", RES)))
    assert {r.host: r.status for r in uncovered}["heim"] == "fail"
    tasks = [{"upid": "u1", "type": "vzdump", "id": "103", "status": "OK", "starttime": NOW.timestamp() - 3600},
             {"upid": "u2", "type": "vzdump", "id": "100", "status": "unexpected status", "starttime": NOW.timestamp() - 7200}]
    b = bundle(ev("pve.tasks_vzdump", tasks), ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES))
    last = results_for("pve.backup_last_status", b)
    assert [r for r in last if r.status == "fail"][0].host == "ubuntu-server"
    none = results_for("pve.backup_last_status", bundle(ev("pve.tasks_vzdump", [], "empty"), ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES)))
    assert none[0].status == "fail" and "no vzdump task" in none[0].summary


def test_services_dead_and_time_sync():
    svcs = [{"name": "sshd", "state": "running"}, {"name": "pveproxy", "state": "running"}, {"name": "pvedaemon", "state": "running"},
            {"name": "pve-firewall", "state": "dead"}, {"name": "pvefw-logger", "state": "running"},
            {"name": "chrony", "state": "running"}, {"name": "systemd-timesyncd", "state": "dead"}, {"name": "corosync", "state": "dead"}]
    rows = results_for("pve.services_dead", bundle(ev("pve.services", svcs)))
    by = {r.subject: r.status for r in rows}
    assert by["pve-firewall"] == "fail" and by["time-sync"] == "ok" and "corosync" not in by


def test_auth_failures_from_journal():
    lines = ["Sep 27 01:00:00 homelab sshd[100]: Failed password for invalid user admin from 203.0.113.9 port 4 ssh2"] * 60 \
            + ["Sep 27 01:00:00 homelab pvedaemon[200]: authentication failure; rhost=203.0.113.9 user=root@pam msg=x"] \
            + ["Sep 27 01:00:00 homelab systemd[1]: Started thing."]
    rows = {r.subject: r for r in results_for("pve.auth_failures", bundle(ev("pve.journal", lines)))}
    assert rows["sshd"].status == "fail" and rows["sshd"].severity == "critical"
    assert rows["pveproxy"].status == "fail" and rows["pveproxy"].severity == "warning"
    assert results_for("pve.auth_failures", bundle(ev("pve.journal", [], "empty")))[0].status == "unavailable"


def test_vm_notes_and_secureboot():
    b = bundle(ev("pve.resources_vm", RES),
               ev("pve.vm_config[100]", {"net0": "virtio=AA,bridge=vmbr0,firewall=1", "hostpci0": "0000:03:00"}),
               ev("pve.vm_config[102]", {"onboot": 1}), ev("pve.vm_status[102]", {"status": "stopped"}),
               ev("pve.node_status", {"boot-info": {"secureboot": 0}}))
    hard = results_for("pve.vm_hardening", b)
    assert any(r.host == "ubuntu-server" and "passthrough" in r.summary for r in hard)
    assert any(r.host == "ubuntu-server" and "protection" in r.summary for r in hard)
    assert results_for("pve.stopped_vm_onboot", b)[0].host == "monitor-box"
    assert results_for("pve.secureboot", b)[0].status == "note"


def test_evaluator_exception_becomes_unavailable_not_a_crash():
    b = bundle(ev("pve.certificates", "this is not a list"))
    rows = results_for("pve.cert_expiry", b)
    assert rows and all(r.status in ("unavailable", "ok") for r in rows)
```

- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_pve.py -q` — expect `ModuleNotFoundError: No module named 'heim.security.evaluate'`.
- [ ] Create `src/heim/security/evaluate.py`:

```python
"""Evaluation core: context, result helpers, the empty-list control rule, and
the dispatcher that runs every catalogue check in isolation. Pure."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from heim.security.catalogue import Catalogue
from heim.security.parsers import vmids_from_resources
from heim.security.types import CheckResult, CheckSpec, EvidenceBundle, clean_subject

log = logging.getLogger(__name__)


@dataclass
class EvalContext:
    now: datetime
    instance_host_map: dict[str, str]
    hosts: tuple[str, ...]
    pve_node: str = "homelab"
    ssh_host: str = "ubuntu-server"
    ha_host: str = "home-assistant"
    vm_names: dict[str, str] = field(default_factory=dict)
    expected_offline_vms: tuple[str, ...] = ()

    def host_for_instance(self, instance: str) -> str:
        """``instance`` label → configured host via the settings prefix map."""
        inst = str(instance or "")
        for prefix, host in self.instance_host_map.items():
            if prefix and inst.startswith(str(prefix)):
                return host
        return inst.split(":")[0] or "unknown"

    def vm_name(self, vmid: object) -> str:
        return self.vm_names.get(str(vmid), f"vm{vmid}")


Evaluator = Callable[[CheckSpec, EvidenceBundle, EvalContext], list[CheckResult]]
Compound = Callable[[CheckSpec, list[CheckResult], EvalContext], list[CheckResult]]


def ok(spec: CheckSpec, host: str, subject: str) -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "ok", spec.severity, "")


def fail(spec: CheckSpec, host: str, subject: str, summary: str, *,
         detail: str = "", severity: str | None = None) -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "fail", severity or spec.severity,
                       summary, detail, spec.recommendation)


def note(spec: CheckSpec, host: str, subject: str, summary: str, detail: str = "") -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "note", "info", summary, detail)


def unavailable(spec: CheckSpec, host: str, reason: str) -> CheckResult:
    return CheckResult(spec.id, host, "-", "unavailable", spec.severity, f"not verified: {reason}", reason)


def default_host(spec: CheckSpec, ctx: EvalContext) -> str:
    kind = spec.id.split(".", 1)[0]
    return {"pve": ctx.pve_node, "ha": ctx.ha_host, "ssh": ctx.ssh_host, "net": ctx.ssh_host}.get(kind, "prometheus")


def gate_sources(spec: CheckSpec, cat: Catalogue, ev: EvidenceBundle) -> str:
    """'' when every non-expanding source is usable; else the reason.

    The privsep trap: a list endpoint answers 200 + [] both for "nothing
    there" and "you may not see it". An empty result therefore counts only
    when the source's declared control returned non-empty in the same run.
    """
    for key in spec.sources:
        src = cat.sources[key]
        if src.expand:
            continue                      # per-item availability is the evaluator's job
        e = ev.get(key)
        if not e.usable:
            return f"{key}: {e.status} — {e.detail or 'no data'}"
        if e.status == "empty" and src.control:
            c = ev.get(src.control)
            if c.status != "ok":
                return (f"{key} returned an empty list and its control {src.control} is {c.status} — "
                        f"cannot tell 'nothing there' from 'not permitted'")
    return ""


def _registry() -> tuple[dict[str, Evaluator], dict[str, Compound]]:
    from heim.security import evaluate_compound, evaluate_ha, evaluate_prom, evaluate_pve, evaluate_ssh
    plain: dict[str, Evaluator] = {}
    for mod in (evaluate_pve, evaluate_ha, evaluate_prom, evaluate_ssh):
        plain.update(mod.EVALUATORS)
    return plain, dict(evaluate_compound.COMPOUND)


def evaluate(cat: Catalogue, ev: EvidenceBundle, ctx: EvalContext) -> list[CheckResult]:
    """Run every catalogue check; a broken evaluator yields one `unavailable`
    row rather than taking the audit down."""
    plain, compound = _registry()
    res = ev.get("pve.resources_vm")
    if res.status == "ok":
        ctx.vm_names = vmids_from_resources(res.body)
    if not ctx.expected_offline_vms:
        ctx.expected_offline_vms = tuple(cat.params.get("expected_offline_vms") or ())
    results: list[CheckResult] = []
    for spec in cat.checks:
        if spec.compound:
            continue
        fn = plain.get(spec.id)
        if fn is None:
            results.append(unavailable(spec, default_host(spec, ctx), "no evaluator registered"))
            continue
        reason = gate_sources(spec, cat, ev)
        if reason:
            results.append(unavailable(spec, default_host(spec, ctx), reason))
            continue
        try:
            rows = fn(spec, ev, ctx)
        except Exception as exc:  # one bad payload must not sink the other 46 checks
            log.exception("evaluator %s failed", spec.id)
            rows = [unavailable(spec, default_host(spec, ctx), f"evaluator error: {type(exc).__name__}: {exc}")]
        results.extend(rows or [ok(spec, default_host(spec, ctx), "-")])
    for spec in cat.checks:
        if not spec.compound:
            continue
        fn = compound.get(spec.id)
        if fn is None:
            results.append(unavailable(spec, default_host(spec, ctx), "no compound evaluator registered"))
            continue
        try:
            results.extend(fn(spec, results, ctx))
        except Exception as exc:
            log.exception("compound evaluator %s failed", spec.id)
            results.append(unavailable(spec, default_host(spec, ctx), f"evaluator error: {type(exc).__name__}: {exc}"))
    return results
```

  Until Tasks 5–6 exist, make `_registry` tolerant: wrap the imports of `evaluate_ha`, `evaluate_prom`, `evaluate_ssh`, `evaluate_compound` in `try/except ImportError` for this task **only** and remove the guard in Task 6 (the test in Task 6 asserts every catalogue check has an evaluator).

- [ ] Create `src/heim/security/evaluate_pve.py`:

```python
"""Proxmox evaluators (pve.*). Pure; consume parsed API JSON."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.parsers import apt_pending
from heim.security.types import CheckSpec, EvidenceBundle

_MODIFY = re.compile(r"Modify|Allocate|Console|PowerMgmt|Permissions|Backup|Migrate|Snapshot|Clone|Config")
_SSHD_FAIL = re.compile(r"sshd\[\d+\]: (Failed password|Invalid user|error: maximum authentication attempts)")
_PVE_FAIL = re.compile(r"pvedaemon\[\d+\]: authentication failure")


def _list(ev: EvidenceBundle, key: str) -> list:
    b = ev.get(key).body
    return b if isinstance(b, list) else []


def _dict(ev: EvidenceBundle, key: str) -> dict:
    b = ev.get(key).body
    return b if isinstance(b, dict) else {}


def tfa_missing(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext):
    with_tfa = {str(t.get("userid")) for t in _list(ev, "pve.access_tfa") if isinstance(t, dict) and t.get("entries")}
    interactive = set(spec.params.get("interactive_users") or ["root@pam"])
    out = []
    for u in _list(ev, "pve.access_users"):
        uid = str(u.get("userid") or "")
        if not uid or str(u.get("enable", 1)) == "0":
            continue
        if uid in with_tfa:
            out.append(ok(spec, ctx.pve_node, uid))
        elif uid in interactive:
            out.append(fail(spec, ctx.pve_node, uid, f"{uid} can log in to the Proxmox UI/API with a password alone (no second factor)"))
        else:
            out.append(note(spec, ctx.pve_node, uid, f"{uid} has no second factor (token/service account — informational)"))
    return out


def firewall_disabled(spec, ev, ctx):
    out = []
    cluster = _dict(ev, "pve.fw_cluster_options")
    if str(cluster.get("enable", 0)) != "1":
        out.append(fail(spec, ctx.pve_node, "cluster", "Proxmox firewall is not enabled at the datacenter level",
                        detail=f"cluster rules: {len(_list(ev, 'pve.fw_cluster_rules'))}, node rules: {len(_list(ev, 'pve.fw_node_rules'))}"))
    else:
        out.append(ok(spec, ctx.pve_node, "cluster"))
    vm_fw = ev.expanded("pve.fw_vm_options")
    for vmid, cfg_e in ev.expanded("pve.vm_config").items():
        if not cfg_e.usable or not isinstance(cfg_e.body, dict):
            continue
        flagged = sorted(k for k, v in cfg_e.body.items() if k.startswith("net") and "firewall=1" in str(v))
        fw = vm_fw.get(vmid)
        enabled = fw is not None and fw.usable and isinstance(fw.body, dict) and str(fw.body.get("enable", 0)) == "1"
        if flagged and not enabled:
            name = ctx.vm_name(vmid)
            out.append(note(spec, name, "nic-flag", f"{name}: {', '.join(flagged)} carry firewall=1 but the VM firewall is off — the flag has no effect"))
    return out


def pending_updates(spec, ev, ctx):
    rows = apt_pending(ev.get("pve.apt_versions").body)
    total = len(_list(ev, "pve.apt_versions"))
    if not rows:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    names = sorted(r["Package"] for r in rows)
    return [fail(spec, ctx.pve_node, ctx.pve_node, f"{len(rows)} of {total} tracked packages have a newer version available",
                 detail=", ".join(names[:12]) + ("…" if len(names) > 12 else ""))]


def pending_updates_sensitive(spec, ev, ctx):
    rows = apt_pending(ev.get("pve.apt_versions").body)
    out = []
    for cls, prefixes in (spec.params.get("classes") or {}).items():
        hit = sorted({r["Package"]: f"{r['OldVersion']} → {r['Version']}" for r in rows
                      if any(r["Package"].startswith(p) for p in prefixes)}.items())
        if hit:
            out.append(fail(spec, ctx.pve_node, cls, f"{cls}: {len(hit)} security-relevant package(s) pending",
                            detail=", ".join(f"{p} {v}" for p, v in hit)))
        else:
            out.append(ok(spec, ctx.pve_node, cls))
    return out


def _enabled_repos(body: dict) -> list[dict]:
    return [r for f in body.get("files") or [] for r in (f.get("repositories") or []) if r.get("Enabled")]


def repo_security(spec, ev, ctx):
    body = _dict(ev, "pve.apt_repositories")
    has = any(any("security" in str(s) for s in r.get("Suites") or []) or
              any("security.debian.org" in str(u) for u in r.get("URIs") or []) for r in _enabled_repos(body))
    if has:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    return [fail(spec, ctx.pve_node, ctx.pve_node, "no enabled Debian security repository on the hypervisor",
                 detail=f"{len(_enabled_repos(body))} enabled repositories, none with a *-security suite")]


def repo_risky(spec, ev, ctx):
    out = []
    for std in _dict(ev, "pve.apt_repositories").get("standard-repos") or []:
        h, st = str(std.get("handle")), std.get("status")
        if h == "test":
            out.append(fail(spec, ctx.pve_node, "pve-test", "pve-test repository is enabled on a production node") if st == 1 else ok(spec, ctx.pve_node, "pve-test"))
        elif h == "enterprise":
            out.append(note(spec, ctx.pve_node, "pve-enterprise", "enterprise repository enabled — needs a subscription or apt update fails") if st == 1 else ok(spec, ctx.pve_node, "pve-enterprise"))
    return out


def cert_expiry(spec, ev, ctx):
    warn_d, crit_d = int(spec.params.get("warning_days", 90)), int(spec.params.get("critical_days", 30))
    out = []
    now = ctx.now.astimezone(timezone.utc)
    for c in _list(ev, "pve.certificates"):
        fn = str(c.get("filename") or "?")
        na = c.get("notafter")
        if not isinstance(na, (int, float)):
            out.append(unavailable(spec, ctx.pve_node, f"{fn}: no notafter"))
            continue
        days = (datetime.fromtimestamp(na, tz=timezone.utc) - now).days
        if days < crit_d:
            out.append(fail(spec, ctx.pve_node, fn, f"{fn} expires in {days} days", severity="critical"))
        elif days < warn_d:
            out.append(fail(spec, ctx.pve_node, fn, f"{fn} expires in {days} days"))
        else:
            out.append(ok(spec, ctx.pve_node, fn))
        if fn == "pve-ssl.pem" and "Proxmox Virtual Environment" in str(c.get("issuer") or ""):
            out.append(note(spec, ctx.pve_node, f"{fn}:issuer", f"{fn} is signed by the internal PVE CA — browser warnings expected; valid {days} more days"))
    return out


def acl_privileged(spec, ev, ctx):
    roles = {str(r.get("roleid")): str(r.get("privs") or "") for r in _list(ev, "pve.access_roles")}
    out = []
    for a in _list(ev, "pve.access_acl"):
        ugid, role = str(a.get("ugid") or ""), str(a.get("roleid") or "")
        if ugid.startswith("root@pam"):
            continue
        strong = sorted(p for p in roles.get(role, "").split(",") if _MODIFY.search(p))
        if strong:
            out.append(fail(spec, ctx.pve_node, ugid, f"{ugid} holds {role} at {a.get('path')} with non-audit privileges", detail=", ".join(strong)))
        else:
            out.append(ok(spec, ctx.pve_node, ugid))
    return out


def backup_coverage(spec, ev, ctx):
    jobs = [j for j in _list(ev, "pve.backup_jobs") if str(j.get("enabled", 1)) != "0"]
    covered: set[str] = set()
    cover_all = False
    excluded: set[str] = set()
    for j in jobs:
        if str(j.get("all", 0)) == "1":
            cover_all = True
            excluded |= {v.strip() for v in str(j.get("exclude") or "").split(",") if v.strip()}
        covered |= {v.strip() for v in str(j.get("vmid") or "").split(",") if v.strip()}
    out = []
    for vm in _list(ev, "pve.resources_vm"):
        vmid, name, status = str(vm.get("vmid")), str(vm.get("name") or vm.get("vmid")), str(vm.get("status") or "")
        if vmid in covered or (cover_all and vmid not in excluded):
            out.append(ok(spec, name, "backup"))
        elif status == "running":
            out.append(fail(spec, name, "backup", f"{name} (vmid {vmid}) is running but no enabled backup job includes it"))
        else:
            out.append(note(spec, name, "backup", f"{name} (vmid {vmid}) is {status or 'not running'} and has no backup job"))
    return out


def backup_last_status(spec, ev, ctx):
    horizon = ctx.now.timestamp() - int(spec.params.get("max_age_days", 8)) * 86400
    recent = [t for t in _list(ev, "pve.tasks_vzdump") if float(t.get("starttime") or 0) >= horizon]
    if not recent:
        if _list(ev, "pve.backup_jobs"):
            return [fail(spec, ctx.pve_node, ctx.pve_node, f"no vzdump task ran in the last {spec.params.get('max_age_days', 8)} days although backup jobs exist")]
        return [note(spec, ctx.pve_node, ctx.pve_node, "no backup jobs configured and no vzdump tasks")]
    out = []
    for t in recent:
        st, ident = str(t.get("status") or ""), str(t.get("id") or "job")
        if st and st != "OK":
            out.append(fail(spec, ctx.vm_name(ident) if ident.isdigit() else ctx.pve_node, ident, f"backup task for {ident} ended with: {st[:80]}"))
    return out or [ok(spec, ctx.pve_node, "vzdump")]


def failed_tasks(spec, ev, ctx):
    horizon = ctx.now.timestamp() - 7 * 86400
    bad = [t for t in _list(ev, "pve.tasks_errors") if float(t.get("starttime") or 0) >= horizon]
    if not bad:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    return [note(spec, ctx.pve_node, ctx.pve_node, f"{len(bad)} Proxmox task(s) failed in the last 7 days",
                 detail="\n".join(f"{t.get('type')} {t.get('id') or ''}: {str(t.get('status'))[:80]}" for t in bad[:8]))]


def services_dead(spec, ev, ctx):
    states = {str(s.get("name")): str(s.get("state") or "") for s in _list(ev, "pve.services")}
    out = []
    for name in spec.params.get("required_active") or []:
        st = states.get(name)
        if st is None:
            out.append(note(spec, ctx.pve_node, name, f"service {name} is not present on the hypervisor"))
        elif st == "running":
            out.append(ok(spec, ctx.pve_node, name))
        else:
            out.append(fail(spec, ctx.pve_node, name, f"security-relevant service {name} is {st}"))
    ts = spec.params.get("time_sync_any") or []
    if ts:
        if any(states.get(n) == "running" for n in ts):
            out.append(ok(spec, ctx.pve_node, "time-sync"))
        else:
            out.append(fail(spec, ctx.pve_node, "time-sync", f"no time-sync daemon running ({', '.join(ts)})"))
    return out


def auth_failures(spec, ev, ctx):
    body = ev.get("pve.journal").body
    lines = body.splitlines() if isinstance(body, str) else [str(l) for l in (body or [])]
    if not lines:
        return [unavailable(spec, ctx.pve_node, "journal returned no lines")]
    crit = int(spec.params.get("critical_count", 50))
    out = []
    for subject, rx in (("sshd", _SSHD_FAIL), ("pveproxy", _PVE_FAIL)):
        hits = [l for l in lines if rx.search(l)]
        if not hits:
            out.append(ok(spec, ctx.pve_node, subject))
            continue
        out.append(fail(spec, ctx.pve_node, subject,
                        f"{len(hits)} failed {subject} authentication attempts in the last {len(lines)} journal lines",
                        detail="\n".join(h[-160:] for h in hits[-5:]),
                        severity="critical" if len(hits) >= crit else None))
    return out


def vm_hardening(spec, ev, ctx):
    out = []
    for vmid, e in ev.expanded("pve.vm_config").items():
        if not e.usable or not isinstance(e.body, dict):
            continue
        name, cfg = ctx.vm_name(vmid), e.body
        if str(cfg.get("protection", 0)) != "1":
            out.append(note(spec, name, "protection", f"{name}: protection flag not set (accidental destroy/edit is possible)"))
        pt = sorted(k for k in cfg if k.startswith(("hostpci", "usb")))
        if pt:
            out.append(note(spec, name, "passthrough", f"{name}: device passthrough present ({', '.join(pt)})"))
        if "agent" not in cfg:
            out.append(note(spec, name, "agent", f"{name}: QEMU guest agent not configured"))
    return out


def stopped_vm_onboot(spec, ev, ctx):
    out = []
    status = ev.expanded("pve.vm_status")
    for vmid, e in ev.expanded("pve.vm_config").items():
        st = status.get(vmid)
        if not (e.usable and isinstance(e.body, dict) and st is not None and st.usable and isinstance(st.body, dict)):
            continue
        name = ctx.vm_name(vmid)
        if str(st.body.get("status")) == "stopped" and str(e.body.get("onboot", 0)) == "1":
            out.append(note(spec, name, "onboot", f"{name} is stopped but onboot=1 — it would start on the next host boot"))
        elif str(st.body.get("status")) == "running" and name in ctx.expected_offline_vms:
            out.append(note(spec, name, "running", f"{name} is running although it is expected to be powered off"))
    return out


def secureboot(spec, ev, ctx):
    info = _dict(ev, "pve.node_status").get("boot-info") or {}
    if str(info.get("secureboot", 0)) == "1":
        return [ok(spec, ctx.pve_node, "secureboot")]
    return [note(spec, ctx.pve_node, "secureboot", "Secure Boot is not enabled on the hypervisor")]


EVALUATORS = {
    "pve.tfa_missing": tfa_missing, "pve.firewall_disabled": firewall_disabled,
    "pve.pending_updates": pending_updates, "pve.pending_updates_sensitive": pending_updates_sensitive,
    "pve.repo_security": repo_security, "pve.repo_risky": repo_risky, "pve.cert_expiry": cert_expiry,
    "pve.acl_privileged": acl_privileged, "pve.backup_coverage": backup_coverage,
    "pve.backup_last_status": backup_last_status, "pve.failed_tasks": failed_tasks,
    "pve.services_dead": services_dead, "pve.auth_failures": auth_failures,
    "pve.vm_hardening": vm_hardening, "pve.stopped_vm_onboot": stopped_vm_onboot, "pve.secureboot": secureboot,
}
```

- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_pve.py -q` — expect 13 passed. Full suite: 856 passed.
- [ ] Commit: `git add src/heim/security/evaluate.py src/heim/security/evaluate_pve.py tests/test_security_evaluate_pve.py && git commit -m "security: evaluation core with the empty-list control rule, and the Proxmox evaluators"`

### Task 5: Home Assistant and Prometheus evaluators

**Files**
- Create `src/heim/security/evaluate_ha.py`, `src/heim/security/evaluate_prom.py`, `tests/test_security_evaluate_ha_prom.py`.

**Interfaces**
- Produces `evaluate_ha.EVALUATORS` (8 `ha.*` checks) and `evaluate_prom.EVALUATORS` (6 `prom.*` checks), same `Evaluator` signature as Task 4.
- Consumes `is_public_host` (parsers), `EvalContext.host_for_instance`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_evaluate_ha_prom.py
from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, evaluate
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)
CTX = dict(now=NOW, instance_host_map={"10.0.0.2": "homelab", "10.0.0.10": "ubuntu-server", "10.0.0.4": "heim"},
           hosts=("heim", "home-assistant", "homelab", "ubuntu-server"))


def rows_for(check_id, *items):
    b = EvidenceBundle(items={e.key: e for e in items})
    return [r for r in evaluate(CAT, b, EvalContext(**CTX)) if r.check_id == check_id]


def upd(eid, on=True, title="", installed="1", latest="2"):
    return {"entity_id": eid, "state": "on" if on else "off",
            "attributes": {"title": title, "installed_version": installed, "latest_version": latest}}


STATES = [
    upd("update.home_assistant_core_update", title="Home Assistant Core", installed="2026.9.1", latest="2026.9.3"),
    upd("update.vaultwarden_update", title="Vaultwarden"),
    upd("update.spotify_connect_update", title="Spotify Connect"),
    upd("update.grafana_update", on=False, title="Grafana"),
    {"entity_id": "sensor.proxmox_web_api_certificate_expiry", "state": "423", "attributes": {}},
    {"entity_id": "sensor.n8n_certificate_expiry", "state": "unknown", "attributes": {}},
    {"entity_id": "sensor.loki_certificate_expiry", "state": "unavailable", "attributes": {}},
    {"entity_id": "sensor.jellyfin_certificate_expiry", "state": "9", "attributes": {}},
    {"entity_id": "persistent_notification.http_login", "state": "notifying",
     "attributes": {"title": "Login attempt failed", "message": "Login attempt or request with invalid authentication from 203.0.113.9"}},
]
PUBLIC_CFG = {"version": "2026.9.1", "safe_mode": False, "recovery_mode": False,
              "external_url": "https://myhome.example-dyndns.net:8123", "allowlist_external_dirs": ["/media", "/config/www", "/backup"]}


def test_ha_sensitive_updates_and_other_count():
    sens = rows_for("ha.pending_updates_sensitive", Evidence("ha.states", "ok", body=STATES))
    assert {r.subject for r in sens if r.status == "fail"} == {"update.home_assistant_core_update", "update.vaultwarden_update"}
    assert all(r.host == "home-assistant" for r in sens)
    other = rows_for("ha.pending_updates_other", Evidence("ha.states", "ok", body=STATES))
    assert other[0].status == "note" and "1 " in other[0].summary


def test_ha_core_update_exposed_is_critical_only_when_public_and_pending():
    hit = rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=STATES), Evidence("ha.config", "ok", body=PUBLIC_CFG))
    assert hit[0].status == "fail" and hit[0].severity == "critical" and "2026.9.3" in hit[0].summary
    lan = dict(PUBLIC_CFG, external_url="http://192.168.1.5:8123")
    assert rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=STATES), Evidence("ha.config", "ok", body=lan))[0].status == "ok"
    patched = [s for s in STATES if s["entity_id"] != "update.home_assistant_core_update"]
    assert rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=patched), Evidence("ha.config", "ok", body=PUBLIC_CFG))[0].status == "ok"


def test_ha_config_checks():
    cfg = Evidence("ha.config", "ok", body=PUBLIC_CFG)
    assert rows_for("ha.external_url", cfg)[0].status == "note"
    assert rows_for("ha.safe_mode", cfg)[0].status == "ok"
    assert rows_for("ha.safe_mode", Evidence("ha.config", "ok", body=dict(PUBLIC_CFG, safe_mode=True)))[0].status == "fail"
    dirs = rows_for("ha.external_dirs", cfg)
    assert dirs[0].status == "note" and "/backup" in dirs[0].summary


def test_ha_cert_sensors_and_login_notifications():
    rows = rows_for("ha.cert_expiry", Evidence("ha.states", "ok", body=STATES))
    by = {r.subject: r for r in rows}
    assert by["sensor.proxmox_web_api_certificate_expiry"].status == "ok"
    assert by["sensor.jellyfin_certificate_expiry"].severity == "critical"
    assert by["unpopulated"].status == "note" and "2 of 4" in by["unpopulated"].summary
    login = rows_for("ha.login_notifications", Evidence("ha.states", "ok", body=STATES))
    assert login[0].status == "fail" and login[0].subject == "persistent_notification.http_login"


def vec(*samples):
    return [{"metric": m, "value": [1.0, str(v)]} for m, v in samples]


def test_prom_reboot_failed_units_time_sync_targets():
    rr = rows_for("prom.reboot_required", Evidence("prom.reboot_required", "ok", body=vec(({"instance": "10.0.0.10:9100"}, 1), ({"instance": "10.0.0.4:9100"}, 0))))
    assert {r.host: r.status for r in rr} == {"ubuntu-server": "fail", "heim": "ok"}
    fu = rows_for("prom.failed_units", Evidence("prom.failed_units", "ok", body=vec(({"instance": "10.0.0.2:9100", "name": "openipmi.service"}, 1))))
    assert fu[0].status == "fail" and fu[0].fingerprint == "homelab|prom.failed_units|openipmi.service"
    ts = rows_for("prom.time_sync", Evidence("prom.timex", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 0))))
    assert ts[0].status == "fail"
    up = rows_for("prom.targets_down", Evidence("prom.up", "ok", body=vec(({"job": "cadvisor", "instance": "10.0.0.10:8081"}, 0), ({"job": "home-assistant", "instance": "x"}, 1))))
    assert {r.subject: r.status for r in up} == {"cadvisor": "fail", "home-assistant": "ok"}


def test_prom_apt_pending_and_collector_gap():
    rows = rows_for("prom.apt_pending",
                    Evidence("prom.apt_pending", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 281))),
                    Evidence("prom.apt_present", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 1), ({"instance": "10.0.0.10:9100"}, 1), ({"instance": "10.0.0.4:9100"}, 1))))
    by = {(r.host, r.status) for r in rows}
    assert ("homelab", "fail") in by and ("ubuntu-server", "note") in by and ("heim", "note") in by


def test_prom_os_eol():
    body = vec(({"instance": "10.0.0.10:9100", "id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.4 LTS"}, 1),
               ({"instance": "10.0.0.4:9100", "id": "debian", "version_id": "13", "pretty_name": "Debian GNU/Linux 13"}, 1),
               ({"instance": "10.0.0.2:9100", "id": "gentoo", "version_id": "", "pretty_name": "Gentoo"}, 1))
    rows = rows_for("prom.os_eol", Evidence("prom.os_info", "ok", body=body))
    by = {r.host: r for r in rows}
    assert by["ubuntu-server"].status == "ok" and by["heim"].status == "ok"
    assert by["homelab"].status == "note" and "no EOL entry" in by["homelab"].summary
```

- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_ha_prom.py -q` — expect failures with `unavailable … no evaluator registered` (the registry import guard from Task 4 swallows the missing modules).
- [ ] Create `src/heim/security/evaluate_ha.py`:

```python
"""Home Assistant evaluators (ha.*). Pure; consume /api/config and /api/states JSON."""
from __future__ import annotations

import re

from heim.security.evaluate import EvalContext, fail, note, ok
from heim.security.parsers import is_public_host
from heim.security.types import CheckSpec, EvidenceBundle

_LOGIN = re.compile(r"login|ip ban|banned", re.I)


def _states(ev: EvidenceBundle) -> list[dict]:
    b = ev.get("ha.states").body
    return [s for s in (b if isinstance(b, list) else []) if isinstance(s, dict)]


def _config(ev: EvidenceBundle) -> dict:
    b = ev.get("ha.config").body
    return b if isinstance(b, dict) else {}


def _updates_on(ev) -> list[dict]:
    return [s for s in _states(ev) if str(s.get("entity_id", "")).startswith("update.") and str(s.get("state")) == "on"]


def _matches(spec: CheckSpec, s: dict) -> bool:
    pats = [str(p).lower() for p in spec.params.get("sensitive_patterns") or []]
    eid = str(s.get("entity_id", "")).lower()
    title = str((s.get("attributes") or {}).get("title") or "").lower()
    return any(p in eid or p in title for p in pats)


def pending_updates_sensitive(spec, ev, ctx: EvalContext):
    out = []
    for s in _updates_on(ev):
        if not _matches(spec, s):
            continue
        a = s.get("attributes") or {}
        out.append(fail(spec, ctx.ha_host, s["entity_id"],
                        f"{a.get('title') or s['entity_id']}: {a.get('installed_version')} → {a.get('latest_version')} available"))
    return out or [ok(spec, ctx.ha_host, "sensitive-updates")]


def pending_updates_other(spec, ev, ctx):
    others = [s for s in _updates_on(ev) if not _matches_any_sensitive(ev, s)]
    if not others:
        return [ok(spec, ctx.ha_host, "other")]
    names = ", ".join(str((s.get("attributes") or {}).get("title") or s["entity_id"]) for s in others[:10])
    return [note(spec, ctx.ha_host, "other", f"{len(others)} other update(s) pending", detail=names)]


#: Mirrors the catalogue's sensitive_patterns so the "other" count never
#: depends on another check's params (the two checks are independent rows).
_SENSITIVE_DEFAULT = ["core", "operating_system", "supervisor", "vaultwarden", "bitwarden", "letsencrypt",
                      "let_s_encrypt", "ssh", "adguard", "nginx", "proxy", "wireguard", "tailscale", "cloudflared"]


def _matches_any_sensitive(ev, s: dict) -> bool:
    eid = str(s.get("entity_id", "")).lower()
    title = str((s.get("attributes") or {}).get("title") or "").lower()
    return any(p in eid or p in title for p in _SENSITIVE_DEFAULT)


def core_update_exposed(spec, ev, ctx):
    cfg = _config(ev)
    core_id = str(spec.params.get("core_entity") or "update.home_assistant_core_update")
    core = [s for s in _updates_on(ev) if s.get("entity_id") == core_id]
    if core and is_public_host(str(cfg.get("external_url") or "")):
        a = core[0].get("attributes") or {}
        return [fail(spec, ctx.ha_host, ctx.ha_host,
                     f"Home Assistant core {a.get('installed_version')} is reachable at a public URL while {a.get('latest_version')} is available")]
    return [ok(spec, ctx.ha_host, ctx.ha_host)]


def external_url(spec, ev, ctx):
    url = str(_config(ev).get("external_url") or "")
    if is_public_host(url):
        return [note(spec, ctx.ha_host, "external_url", "Home Assistant is reachable from the internet via its external URL (DynDNS)")]
    return [ok(spec, ctx.ha_host, "external_url")]


def safe_mode(spec, ev, ctx):
    cfg = _config(ev)
    modes = [m for m in ("safe_mode", "recovery_mode") if cfg.get(m)]
    if modes:
        return [fail(spec, ctx.ha_host, ctx.ha_host, f"Home Assistant is running in {' and '.join(modes)}")]
    return [ok(spec, ctx.ha_host, ctx.ha_host)]


def cert_expiry(spec, ev, ctx):
    warn_d, crit_d = int(spec.params.get("warning_days", 30)), int(spec.params.get("critical_days", 14))
    out, unknown, total = [], 0, 0
    for s in _states(ev):
        eid = str(s.get("entity_id", ""))
        if "certificate_expiry" not in eid:
            continue
        total += 1
        try:
            days = float(s.get("state"))
        except (TypeError, ValueError):
            unknown += 1
            continue
        if days < crit_d:
            out.append(fail(spec, ctx.ha_host, eid, f"{eid}: certificate expires in {days:.0f} days", severity="critical"))
        elif days < warn_d:
            out.append(fail(spec, ctx.ha_host, eid, f"{eid}: certificate expires in {days:.0f} days"))
        else:
            out.append(ok(spec, ctx.ha_host, eid))
    if unknown:
        out.append(note(spec, ctx.ha_host, "unpopulated",
                        f"{unknown} of {total} certificate-expiry sensors report no value — certificate monitoring is configured but not working for them"))
    return out or [ok(spec, ctx.ha_host, "no-cert-sensors")]


def login_notifications(spec, ev, ctx):
    out = []
    for s in _states(ev):
        eid = str(s.get("entity_id", ""))
        if not eid.startswith("persistent_notification."):
            continue
        a = s.get("attributes") or {}
        text = f"{a.get('title', '')} {a.get('message', '')}"
        if _LOGIN.search(text):
            out.append(fail(spec, ctx.ha_host, eid, f"{a.get('title') or eid}", detail=str(a.get("message") or "")[:300]))
    return out or [ok(spec, ctx.ha_host, "none")]


def external_dirs(spec, ev, ctx):
    allowed = set(spec.params.get("allowed") or [])
    dirs = [str(d) for d in _config(ev).get("allowlist_external_dirs") or []]
    extra = sorted(d for d in dirs if d not in allowed)
    if extra:
        return [note(spec, ctx.ha_host, "external_dirs", f"allowlist_external_dirs includes {', '.join(extra)}")]
    return [ok(spec, ctx.ha_host, "external_dirs")]


EVALUATORS = {
    "ha.pending_updates_sensitive": pending_updates_sensitive, "ha.pending_updates_other": pending_updates_other,
    "ha.core_update_exposed": core_update_exposed, "ha.external_url": external_url, "ha.safe_mode": safe_mode,
    "ha.cert_expiry": cert_expiry, "ha.login_notifications": login_notifications, "ha.external_dirs": external_dirs,
}
```


- [ ] Create `src/heim/security/evaluate_prom.py`:

```python
"""Prometheus evaluators (prom.*). Pure; consume /api/v1/query result vectors."""
from __future__ import annotations

from datetime import date

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.types import CheckSpec, EvidenceBundle


def _vec(ev: EvidenceBundle, key: str) -> list[dict]:
    b = ev.get(key).body
    return [s for s in (b if isinstance(b, list) else []) if isinstance(s, dict) and "metric" in s]


def _val(s: dict) -> float:
    try:
        return float((s.get("value") or [0, "nan"])[1])
    except (TypeError, ValueError):
        return float("nan")


def _host(ctx: EvalContext, s: dict) -> str:
    return ctx.host_for_instance(str(s["metric"].get("instance", "")))


def reboot_required(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.reboot_required"):
        h = _host(ctx, s)
        out.append(fail(spec, h, h, f"{h} needs a reboot for an installed kernel/library update to take effect") if _val(s) >= 1 else ok(spec, h, h))
    return out or [unavailable(spec, "prometheus", "node_reboot_required has no series")]


def apt_pending(spec, ev, ctx):
    out, seen = [], set()
    for s in _vec(ev, "prom.apt_pending"):
        h = _host(ctx, s)
        seen.add(h)
        n = _val(s)
        out.append(fail(spec, h, h, f"{h}: {int(n)} pending apt upgrade rows (arch/origin cross-tab) reported by node_exporter") if n > 0 else ok(spec, h, h))
    for s in _vec(ev, "prom.apt_present"):
        h = _host(ctx, s)
        if h not in seen:
            out.append(note(spec, h, "collector-absent",
                            f"{h}: node_exporter has no apt_upgrades_pending series — the apt textfile collector is not installed, so pending updates are unobservable here"))
    return out or [unavailable(spec, "prometheus", "no node_exporter instances found")]


def failed_units(spec, ev, ctx):
    expected = set(spec.params.get("expected_failed") or [])
    out = []
    for s in _vec(ev, "prom.failed_units"):
        h, unit = _host(ctx, s), str(s["metric"].get("name") or "?")
        out.append(ok(spec, h, unit) if unit in expected else fail(spec, h, unit, f"{h}: systemd unit {unit} is in failed state"))
    return out or [ok(spec, "all", "none-failed")]


def time_sync(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.timex"):
        h = _host(ctx, s)
        out.append(fail(spec, h, h, f"{h}: clock is not synchronised (node_timex_sync_status=0)") if _val(s) == 0 else ok(spec, h, h))
    return out or [unavailable(spec, "prometheus", "node_timex_sync_status has no series")]


def targets_down(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.up"):
        job = str(s["metric"].get("job") or s["metric"].get("instance") or "?")
        out.append(fail(spec, _host(ctx, s), job, f"Prometheus target {job} ({s['metric'].get('instance', '')}) is down — a blind spot for this audit") if _val(s) == 0 else ok(spec, _host(ctx, s), job))
    return out or [unavailable(spec, "prometheus", "up has no series")]


def os_eol(spec, ev, ctx):
    table = {str(k).lower(): str(v) for k, v in (spec.params.get("os_eol") or {}).items()}
    warn_days = int(spec.params.get("warning_days", 180))
    review_by = str(spec.params.get("review_by") or "")
    out = []
    today = ctx.now.date()
    if review_by and today.isoformat() > review_by:
        out.append(note(spec, "all", "eol-table", f"the os_eol table in checks.yaml is past its review_by date ({review_by}) — verify the dates"))
    for s in _vec(ev, "prom.os_info"):
        m, h = s["metric"], _host(ctx, s)
        key = f"{m.get('id', '')} {m.get('version_id', '')}".strip().lower()
        pretty = str(m.get("pretty_name") or key)
        eol = table.get(key)
        if not eol:
            out.append(note(spec, h, key or "unknown", f"{h}: {pretty} has no EOL entry in checks.yaml"))
            continue
        days = (date.fromisoformat(eol) - today).days
        if days < 0:
            out.append(fail(spec, h, key, f"{h}: {pretty} reached end of life on {eol}", severity="critical"))
        elif days < warn_days:
            out.append(fail(spec, h, key, f"{h}: {pretty} reaches end of life in {days} days ({eol})"))
        else:
            out.append(ok(spec, h, key))
    return out or [unavailable(spec, "prometheus", "node_os_info has no series")]


EVALUATORS = {
    "prom.reboot_required": reboot_required, "prom.apt_pending": apt_pending, "prom.failed_units": failed_units,
    "prom.time_sync": time_sync, "prom.targets_down": targets_down, "prom.os_eol": os_eol,
}
```

- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_ha_prom.py -q` — expect 7 passed. Full suite: 863 passed.
- [ ] Commit: `git add src/heim/security/evaluate_ha.py src/heim/security/evaluate_prom.py tests/test_security_evaluate_ha_prom.py && git commit -m "security: Home Assistant and Prometheus evaluators"`

### Task 6: SSH and compound evaluators; registry completeness

**Files**
- Create `src/heim/security/evaluate_ssh.py`, `src/heim/security/evaluate_compound.py`, `tests/test_security_evaluate_ssh.py`.
- Modify `src/heim/security/evaluate.py` `_registry()` — remove the temporary `ImportError` guard.

**Interfaces**
- Produces `evaluate_ssh.EVALUATORS` (16 `ssh.*` checks) and `evaluate_compound.COMPOUND` (`net.no_firewall_any_layer`).
- Consumes parsers; SSH `Evidence` carries `exit_code`, `stderr`, `target`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_evaluate_ssh.py
import json
from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, _registry, evaluate
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)
CTX = dict(now=NOW, instance_host_map={}, hosts=("heim", "home-assistant", "homelab", "ubuntu-server"))
H = "ubuntu-server"


def ssh(key, text, exit_code=0, stderr=""):
    target = CAT.sources[key.split("[")[0]].target
    status = "ok" if str(text).strip() else "empty"
    return Evidence(key, status, body=text, exit_code=exit_code, stderr=stderr, target=target)


def rows_for(check_id, *items, ctx=None):
    b = EvidenceBundle(items={e.key: e for e in items})
    return [r for r in evaluate(CAT, b, ctx or EvalContext(**CTX)) if r.check_id == check_id]


def test_every_catalogue_check_has_an_evaluator():
    plain, compound = _registry()
    for c in CAT.checks:
        assert c.id in (compound if c.compound else plain), c.id


SS = ("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
      "tcp LISTEN 0 4096 *:8081 *:* users:((\"docker-proxy\",pid=2,fd=4))\n"
      "tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:((\"dockerd\",pid=3,fd=4))\n"
      "tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:((\"postgres\",pid=4,fd=4))\n"
      "tcp LISTEN 0 4096 [::]:8096 [::]:* users:((\"jellyfin\",pid=5,fd=4))\n")


def test_listeners_expected_unexpected_critical_and_control():
    rows = {r.subject: r for r in rows_for("ssh.listeners_unexpected", ssh("ssh.listeners", SS))}
    assert rows["22/sshd"].status == "ok" and rows["8081/docker-proxy"].status == "ok"
    assert rows["2375/dockerd"].severity == "critical"
    assert rows["8096/jellyfin"].status == "fail" and rows["8096/jellyfin"].severity == "warning"
    assert "5432/postgres" not in rows                              # loopback-bound
    no22 = rows_for("ssh.listeners_unexpected", ssh("ssh.listeners", "tcp LISTEN 0 1 *:80 *:* users:((\"x\",pid=1,fd=1))\n"))
    assert no22[0].status == "unavailable"


MAIN = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nX11Forwarding yes\n"
DROPIN = "PasswordAuthentication yes\n"
LS_OK = "total 4\n-rw-r--r-- 1 root root 30 Jan 1 00:00 50-cloud-init.conf\n"
LS_SECRET = "total 4\n-rw------- 1 root root 30 Jan 1 00:00 99-secret.conf\n"


def test_sshd_checks_dropins_win_and_unreadable_dropin_is_unavailable():
    b = [ssh("ssh.sshd_config", MAIN), ssh("ssh.sshd_config_d", DROPIN), ssh("ssh.sshd_config_d_ls", LS_OK)]
    assert rows_for("ssh.sshd_password_auth", *b)[0].status == "fail"
    assert rows_for("ssh.sshd_root_login", *b)[0].status == "ok"
    assert rows_for("ssh.sshd_empty_passwords", *b)[0].status == "ok"
    hard = rows_for("ssh.sshd_hardening", *b)
    assert any(r.subject == "x11forwarding" for r in hard) and any(r.subject == "allowusers" for r in hard)
    root = [ssh("ssh.sshd_config", "PermitRootLogin yes\n"), ssh("ssh.sshd_config_d", ""), ssh("ssh.sshd_config_d_ls", "total 0\n")]
    assert rows_for("ssh.sshd_root_login", *root)[0].severity == "critical"
    secret = [ssh("ssh.sshd_config", MAIN), ssh("ssh.sshd_config_d", ""), ssh("ssh.sshd_config_d_ls", LS_SECRET)]
    assert rows_for("ssh.sshd_password_auth", *secret)[0].status == "unavailable"


def test_auth_failures_count_sample_and_permission_hint():
    ok_rows = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "0\n", exit_code=1), ssh("ssh.auth_fail_sample", ""))
    assert ok_rows[0].status == "ok"
    hit = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "137\n"), ssh("ssh.auth_fail_sample", "Failed password for root from 203.0.113.9 port 1 ssh2\n"))
    assert hit[0].status == "fail" and hit[0].severity == "critical" and "203.0.113.9" in hit[0].detail
    hint = "Hint: You are currently not seeing messages from other users and the system.\n"
    denied = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "0\n", exit_code=1, stderr=hint), ssh("ssh.auth_fail_sample", "", stderr=hint))
    assert denied[0].status == "unavailable" and "systemd-journal" in denied[0].detail


def test_updates_auto_upgrades_and_units():
    upd = rows_for("ssh.pending_security_updates", ssh("ssh.updates_available", "12 updates can be applied immediately.\n5 of these updates are standard security updates.\n"))
    assert upd[0].status == "fail" and "5 standard security" in upd[0].summary
    assert rows_for("ssh.pending_security_updates", ssh("ssh.updates_available", "", exit_code=1))[0].status == "unavailable"
    units_on = ssh("ssh.unit_states", "inactive\ninactive\ninactive\nactive\nactive\n", exit_code=3)
    au = rows_for("ssh.auto_upgrades_off", ssh("ssh.auto_upgrades", 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'), units_on)
    assert au[0].status == "ok"
    au_off = rows_for("ssh.auto_upgrades_off", ssh("ssh.auto_upgrades", 'APT::Periodic::Unattended-Upgrade "0";\n'), units_on)
    assert au_off[0].status == "fail"
    assert rows_for("ssh.host_firewall", units_on)[0].status == "note"
    assert rows_for("ssh.fail2ban_absent", units_on)[0].status == "note"


def test_world_writable_external_logins_users_sudo():
    ww = rows_for("ssh.world_writable", ssh("ssh.world_writable", "/etc/cron.d/oops\n/opt/app/config.ini\n"))
    assert {r.subject for r in ww} == {"/etc/cron.d/oops", "/opt/app/config.ini"} and all(r.status == "fail" for r in ww)
    assert rows_for("ssh.world_writable", ssh("ssh.world_writable", ""))[0].status == "ok"
    last = ("alice pts/0 192.168.1.20 Mon Sep 21 08:00:00 2026 still logged in\n"
            "alice pts/1 203.0.113.9 Sat Sep 19 09:00:00 2026 - Sat Sep 19 09:30:00 2026 (00:30)\n")
    ext = rows_for("ssh.external_logins", ssh("ssh.last_logins", last))
    assert ext[0].status == "fail" and ext[0].subject == "external" and "203.0.113.9" in ext[0].detail
    users = rows_for("ssh.login_shell_users", ssh("ssh.login_shells", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n"))
    assert users[0].status == "note" and "2 account" in users[0].summary
    sudo_ok = "User agent may run the following commands on host:\n    (root) NOPASSWD: /usr/bin/du, /usr/bin/df, /usr/bin/findmnt, /usr/bin/lsof, /usr/bin/ls, /usr/bin/ss, /usr/local/bin/agent-docker\n"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", sudo_ok))[0].status == "ok"
    sudo_bad = sudo_ok + "    (ALL) NOPASSWD: ALL\n"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", sudo_bad))[0].status == "fail"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", "", exit_code=1, stderr="sudo: a password is required"))[0].status == "unavailable"


def test_docker_inspect_and_images():
    cad = json.dumps([{"Name": "/cadvisor", "HostConfig": {"Privileged": True, "Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"], "NetworkMode": "bridge", "CapAdd": None}}])
    graf = json.dumps([{"Name": "/grafana", "HostConfig": {"Privileged": False, "Binds": ["grafana-data:/var/lib/grafana"], "NetworkMode": "bridge", "CapAdd": None}}])
    rows = {r.subject: r for r in rows_for("ssh.docker_privileged", ssh("ssh.docker_inspect[cadvisor]", cad), ssh("ssh.docker_inspect[grafana]", graf))}
    assert rows["cadvisor"].status == "fail" and "privileged" in rows["cadvisor"].summary and "docker.sock" in rows["cadvisor"].summary
    assert rows["grafana"].status == "ok"
    imgs = ("REPOSITORY TAG IMAGE ID CREATED SIZE\n"
            "grafana/grafana latest aaa 3 weeks ago 400MB\n"
            "old/thing v1 bbb 14 months ago 90MB\n")
    stale = rows_for("ssh.docker_stale_images", ssh("ssh.docker_images", imgs))
    assert [r.subject for r in stale if r.status == "note"] == ["old/thing:v1"]


def test_compound_no_firewall_any_layer():
    fw_off = [Evidence("pve.fw_cluster_options", "ok", body={"digest": "x"}), Evidence("pve.fw_cluster_rules", "empty", body=[]),
              Evidence("pve.fw_node_options", "ok", body={}), Evidence("pve.fw_node_rules", "empty", body=[])]
    units = ssh("ssh.unit_states", "inactive\ninactive\ninactive\nactive\nactive\n", exit_code=3)
    rows = rows_for("net.no_firewall_any_layer", *fw_off, units)
    assert rows[0].status == "fail" and rows[0].host == H
    fw_on = [Evidence("pve.fw_cluster_options", "ok", body={"enable": 1}), Evidence("pve.fw_cluster_rules", "ok", body=[{"a": 1}]),
             Evidence("pve.fw_node_options", "ok", body={}), Evidence("pve.fw_node_rules", "empty", body=[])]
    assert rows_for("net.no_firewall_any_layer", *fw_on, units)[0].status == "ok"
```

- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_ssh.py -q` — expect failures (`test_every_catalogue_check_has_an_evaluator` and `unavailable` rows).
- [ ] Create `src/heim/security/evaluate_ssh.py`:

```python
"""ubuntu-server evaluators (ssh.*) over the fixed SSH lines. Pure.

Every evaluator distinguishes "nothing found" from "could not look": a
permission hint on stderr, a non-zero exit on a file read, or output that
lacks a known-present marker (sshd on :22) yields `unavailable`, never `ok`.
"""
from __future__ import annotations

import json
import re

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.parsers import (
    ip_in_cidrs, parse_docker_images, parse_last_hosts, parse_ss_listeners, parse_sshd_config,
    parse_updates_available, unit_states, unreadable_dropins,
)
from heim.security.types import CheckSpec, Evidence, EvidenceBundle

_JOURNAL_HINT = ("not seeing messages", "No journal files")
_RISKY_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"}


def _text(e: Evidence) -> str:
    return str(e.body or "")


def listeners_unexpected(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext):
    rows = parse_ss_listeners(_text(ev.get("ssh.listeners")))
    if not any(r["port"] == "22" for r in rows):
        return [unavailable(spec, ctx.ssh_host, "ss output shows no sshd listener on :22 — output not trustworthy (permission or format)")]
    expected = {str(k): str(v) for k, v in (spec.params.get("expected_ports") or {}).items()}
    critical = {str(k): str(v) for k, v in (spec.params.get("critical_ports") or {}).items()}
    out, seen = [], set()
    for r in rows:
        if not r["wildcard"]:
            continue
        key = f"{r['port']}/{r['process']}"
        if key in seen:
            continue
        seen.add(key)
        if r["port"] in critical:
            out.append(fail(spec, ctx.ssh_host, key, f"{r['process']} listens on all interfaces at :{r['port']} ({critical[r['port']]})", detail=r["local"], severity="critical"))
        elif r["port"] in expected:
            out.append(ok(spec, ctx.ssh_host, key))
        else:
            out.append(fail(spec, ctx.ssh_host, key, f"{r['process']} listens on all interfaces at :{r['port']} ({r['proto']}) and is not in expected_ports", detail=r["local"]))
    return out or [ok(spec, ctx.ssh_host, "no-wildcard-listeners")]


def _effective_sshd(ev: EvidenceBundle) -> tuple[dict | None, str]:
    main = ev.get("ssh.sshd_config")
    if main.status != "ok" or (main.exit_code not in (0, None)):
        return None, f"/etc/ssh/sshd_config unreadable ({main.detail or main.stderr.strip() or 'empty'})"
    hidden = unreadable_dropins(_text(ev.get("ssh.sshd_config_d_ls")))
    if hidden:
        return None, f"drop-in(s) {', '.join(hidden)} are not world-readable — the effective sshd config cannot be determined without sudo cat"
    # Ubuntu Includes sshd_config.d/*.conf at the top of sshd_config, and sshd keeps the FIRST value.
    return parse_sshd_config(_text(ev.get("ssh.sshd_config_d")) + "\n" + _text(main)), ""


def sshd_password_auth(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    v = conf.get("passwordauthentication", "yes").lower()
    if v != "no":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"sshd accepts password authentication (PasswordAuthentication {v})")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_root_login(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    v = conf.get("permitrootlogin", "prohibit-password").lower()
    if v == "yes":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "sshd permits root login with a password (PermitRootLogin yes)")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_empty_passwords(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    if conf.get("permitemptypasswords", "no").lower() == "yes":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "sshd permits empty passwords")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_hardening(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    out = []
    if conf.get("x11forwarding", "no").lower() == "yes":
        out.append(note(spec, ctx.ssh_host, "x11forwarding", "X11Forwarding is enabled"))
    try:
        if int(conf.get("maxauthtries", "6")) > 6:
            out.append(note(spec, ctx.ssh_host, "maxauthtries", f"MaxAuthTries is {conf['maxauthtries']} (default 6)"))
    except ValueError:
        pass
    if "allowusers" not in conf and "allowgroups" not in conf:
        out.append(note(spec, ctx.ssh_host, "allowusers", "neither AllowUsers nor AllowGroups restricts who may log in"))
    if conf.get("port", "22") != "22":
        out.append(note(spec, ctx.ssh_host, "port", f"sshd listens on port {conf['port']}"))
    return out or [ok(spec, ctx.ssh_host, "hardening")]


def auth_failures(spec, ev, ctx):
    cnt, sample = ev.get("ssh.auth_fail_count"), ev.get("ssh.auth_fail_sample")
    hint = f"{cnt.stderr} {sample.stderr}"
    if any(h in hint for h in _JOURNAL_HINT):
        return [unavailable(spec, ctx.ssh_host, "the SSH user cannot read the system journal — add it to the systemd-journal group (owner-side step 1) or leave this check unverified")]
    text = _text(cnt).strip().splitlines()
    try:
        n = int(text[-1]) if text else 0
    except ValueError:
        return [unavailable(spec, ctx.ssh_host, f"unparseable count output: {_text(cnt)[:60]!r}")]
    if n == 0:
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    crit = int(spec.params.get("critical_count", 100))
    return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"{n} failed SSH authentication attempts logged in the last 7 days",
                 detail=_text(sample)[-1200:], severity="critical" if n >= crit else None)]


def pending_security_updates(spec, ev, ctx):
    e = ev.get("ssh.updates_available")
    if e.status != "ok" or e.exit_code not in (0, None):
        return [unavailable(spec, ctx.ssh_host, "/var/lib/update-notifier/updates-available is not readable (is update-notifier-common installed?)")]
    total, sec = parse_updates_available(_text(e))
    if sec > 0:
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"{sec} standard security updates pending ({total} updates in total)")]
    if total > 0:
        return [note(spec, ctx.ssh_host, "non-security", f"{total} non-security updates pending")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def _units(ev: EvidenceBundle) -> dict[str, str]:
    e = ev.get("ssh.unit_states")
    return unit_states(e.target, _text(e))


def auto_upgrades_off(spec, ev, ctx):
    conf = _text(ev.get("ssh.auto_upgrades"))
    if not re.search(r'Unattended-Upgrade\s+"1"', conf):
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "unattended-upgrades is not enabled in /etc/apt/apt.conf.d/20auto-upgrades")]
    if _units(ev).get("unattended-upgrades") not in ("active", "activating"):
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "unattended-upgrades is configured but its unit is not active")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def host_firewall(spec, ev, ctx):
    st = _units(ev)
    if st.get("ufw") == "active" or st.get("nftables") == "active":
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [note(spec, ctx.ssh_host, ctx.ssh_host, "no host firewall unit is active (ufw, nftables)")]


def fail2ban_absent(spec, ev, ctx):
    if _units(ev).get("fail2ban") == "active":
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [note(spec, ctx.ssh_host, ctx.ssh_host, "fail2ban is not active")]


def world_writable(spec, ev, ctx):
    paths = [p.strip() for p in _text(ev.get("ssh.world_writable")).splitlines() if p.strip().startswith("/")]
    if not paths:
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [fail(spec, ctx.ssh_host, p, f"world-writable file {p}") for p in paths[:20]]


def external_logins(spec, ev, ctx):
    cidrs = [str(c) for c in spec.params.get("trusted_cidrs") or []]
    ext = sorted({ip for ip in parse_last_hosts(_text(ev.get("ssh.last_logins"))) if not ip_in_cidrs(ip, cidrs)})
    if ext:
        return [fail(spec, ctx.ssh_host, "external", f"{len(ext)} login source address(es) outside the trusted networks in the last 7 days", detail=", ".join(ext))]
    return [ok(spec, ctx.ssh_host, "external")]


def login_shell_users(spec, ev, ctx):
    users = [l.split(":", 1)[0] for l in _text(ev.get("ssh.login_shells")).splitlines() if ":" in l]
    if not users:
        return [ok(spec, ctx.ssh_host, "users")]
    return [note(spec, ctx.ssh_host, "users", f"{len(users)} account(s) have a login shell", detail=", ".join(users[:20]))]


def agent_sudo_scope(spec, ev, ctx):
    e = ev.get("ssh.sudo_scope")
    if e.status != "ok" or e.exit_code not in (0, None):
        return [unavailable(spec, ctx.ssh_host, f"sudo -n -l did not answer ({e.stderr.strip()[:80] or 'non-zero exit'})")]
    allowed = set(spec.params.get("expected_sudo_binaries") or [])
    extra = []
    for line in _text(e).splitlines():
        s = line.strip()
        if not s.startswith("("):
            continue
        cmds = s.split(":", 1)[-1] if ":" in s else s.split(")", 1)[-1]
        for cmd in cmds.split(","):
            c = cmd.strip()
            if not c:
                continue
            base = c.split()[0].rsplit("/", 1)[-1]
            if base == "ALL" or base not in allowed:
                extra.append(c)
    if extra:
        return [fail(spec, ctx.ssh_host, "agent-user", "the monitoring user's sudo rights exceed the read-only set", detail=", ".join(extra[:10]))]
    return [ok(spec, ctx.ssh_host, "agent-user")]


def docker_privileged(spec, ev, ctx):
    out = []
    for name, e in ev.expanded("ssh.docker_inspect").items():
        if e.status != "ok":
            out.append(unavailable(spec, ctx.ssh_host, f"inspect {name}: {e.detail or e.status}"))
            continue
        try:
            data = json.loads(_text(e))
            hc = (data[0] if isinstance(data, list) else data).get("HostConfig") or {}
        except (ValueError, AttributeError, IndexError, TypeError):
            out.append(unavailable(spec, ctx.ssh_host, f"inspect {name}: unparseable JSON"))
            continue
        risks = []
        if hc.get("Privileged"):
            risks.append("privileged")
        if any("/var/run/docker.sock" in str(b) for b in hc.get("Binds") or []):
            risks.append("docker.sock mounted")
        if str(hc.get("NetworkMode")) == "host":
            risks.append("host network")
        caps = {str(c).upper().removeprefix("CAP_") for c in hc.get("CapAdd") or []}
        if caps & _RISKY_CAPS:
            risks.append("cap_add " + ",".join(sorted(caps & _RISKY_CAPS)))
        out.append(fail(spec, ctx.ssh_host, name, f"container {name}: {', '.join(risks)}") if risks else ok(spec, ctx.ssh_host, name))
    return out or [unavailable(spec, ctx.ssh_host, "no container was inspected")]


def docker_stale_images(spec, ev, ctx):
    max_m = int(spec.params.get("max_age_months", 6))
    stale = [(name, m) for name, m in parse_docker_images(_text(ev.get("ssh.docker_images"))) if m >= max_m]
    if not stale:
        return [ok(spec, ctx.ssh_host, "images")]
    return [note(spec, ctx.ssh_host, name, f"image {name} was built {m} months ago") for name, m in stale[:15]]


EVALUATORS = {
    "ssh.listeners_unexpected": listeners_unexpected, "ssh.sshd_password_auth": sshd_password_auth,
    "ssh.sshd_root_login": sshd_root_login, "ssh.sshd_empty_passwords": sshd_empty_passwords,
    "ssh.sshd_hardening": sshd_hardening, "ssh.auth_failures": auth_failures,
    "ssh.pending_security_updates": pending_security_updates, "ssh.auto_upgrades_off": auto_upgrades_off,
    "ssh.host_firewall": host_firewall, "ssh.fail2ban_absent": fail2ban_absent, "ssh.world_writable": world_writable,
    "ssh.external_logins": external_logins, "ssh.login_shell_users": login_shell_users,
    "ssh.agent_sudo_scope": agent_sudo_scope, "ssh.docker_privileged": docker_privileged,
    "ssh.docker_stale_images": docker_stale_images,
}
```

- [ ] Create `src/heim/security/evaluate_compound.py`:

```python
"""Checks derived from other checks' results (no evidence of their own). Pure."""
from __future__ import annotations

from heim.security.evaluate import EvalContext, fail, ok
from heim.security.types import CheckResult, CheckSpec


def no_firewall_any_layer(spec: CheckSpec, results: list[CheckResult], ctx: EvalContext) -> list[CheckResult]:
    pve_off = any(r.check_id == "pve.firewall_disabled" and r.subject == "cluster" and r.status == "fail" for r in results)
    guest_off = any(r.check_id == "ssh.host_firewall" and r.status == "note" for r in results)
    if pve_off and guest_off:
        return [fail(spec, ctx.ssh_host, ctx.ssh_host,
                     f"no packet filter is active at any layer for {ctx.ssh_host}: Proxmox firewall off, no ufw/nftables in the guest")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


COMPOUND = {"net.no_firewall_any_layer": no_firewall_any_layer}
```

- [ ] In `src/heim/security/evaluate.py` `_registry()`, delete the `try/except ImportError` added in Task 4 so a missing module is a hard failure again.
- [ ] Run `.venv/bin/pytest tests/test_security_evaluate_ssh.py -q` — expect 8 passed. Full suite: 871 passed.
- [ ] Commit: `git add src/heim/security/evaluate_ssh.py src/heim/security/evaluate_compound.py src/heim/security/evaluate.py tests/test_security_evaluate_ssh.py && git commit -m "security: ubuntu-server SSH evaluators, compound firewall check, complete evaluator registry"`

### Task 7: Week-over-week diff and the two store reads

**Files**
- Create `src/heim/security/diff.py`, `tests/test_security_diff.py`.
- Modify `src/heim/incidents/store.py:777` (insert after `recent_findings`).

**Interfaces**
- Produces `AuditDiff(new: list[CheckResult], persisting: list[CheckResult], resolved: list[dict], carried: list[dict])` and `diff_findings(current: list[CheckResult], previous: list[dict], unavailable_check_ids: set[str]) -> AuditDiff`; `finding_rows(diff) -> list[dict]` (the rows to insert: new/persisting via `as_finding`, carried copied with `trend="carried"`).
- Produces `IncidentStore.findings_for_run(run_id: int) -> list[dict]` and `IncidentStore.finding_run_count(fingerprint: str, source: str) -> int`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_diff.py
from heim.incidents.store import IncidentStore
from heim.security.diff import diff_findings, finding_rows
from heim.security.types import CheckResult


def fr(check, subject, host="ubuntu-server", sev="warning"):
    return CheckResult(check, host, subject, "fail", sev, f"{check} {subject}", "d", "r")


def prev(check, subject, host="ubuntu-server", sev="warning", trend="new"):
    return {"host": host, "metric": check, "severity": sev, "trend": trend, "summary": "s", "detail": "d",
            "recommendation": "r", "fingerprint": f"{host}|{check}|{subject}"}


def test_diff_new_persisting_resolved():
    cur = [fr("ssh.world_writable", "/etc/a"), fr("ssh.world_writable", "/etc/b")]
    old = [prev("ssh.world_writable", "/etc/a"), prev("ssh.world_writable", "/etc/z")]
    d = diff_findings(cur, old, set())
    assert [r.subject for r in d.new] == ["/etc/b"]
    assert [r.subject for r in d.persisting] == ["/etc/a"]
    assert [r["fingerprint"] for r in d.resolved] == ["ubuntu-server|ssh.world_writable|/etc/z"]
    assert d.carried == []


def test_unavailable_check_carries_last_weeks_findings_instead_of_resolving_them():
    old = [prev("ssh.auth_failures", "ubuntu-server"), prev("pve.tfa_missing", "root@pam", host="homelab")]
    d = diff_findings([fr("pve.tfa_missing", "root@pam", host="homelab")], old, {"ssh.auth_failures"})
    assert d.resolved == []
    assert [c["fingerprint"] for c in d.carried] == ["ubuntu-server|ssh.auth_failures|ubuntu-server"]
    rows = finding_rows(d)
    trends = {r["fingerprint"]: r["trend"] for r in rows}
    assert trends["homelab|pve.tfa_missing|root@pam"] == "persisting"
    assert trends["ubuntu-server|ssh.auth_failures|ubuntu-server"] == "carried"
    carried = [r for r in rows if r["trend"] == "carried"][0]
    assert "not re-verified" in carried["detail"]


def test_first_run_everything_is_new():
    d = diff_findings([fr("a.b", "x")], [], set())
    assert len(d.new) == 1 and not d.persisting and not d.resolved


def test_store_reads(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    r1 = s.insert_run(kind="security_audit", run_at="2026-09-21T06:00:00")
    s.insert_findings(r1, "2026-09-21T06:00:00", "security_audit",
                      [{"host": "h", "metric": "m", "severity": "warning", "trend": "new", "summary": "s", "detail": "d", "recommendation": "r"}],
                      ["h|m|x"])
    r2 = s.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00")
    s.insert_findings(r2, "2026-09-28T06:00:00", "security_audit",
                      [{"host": "h", "metric": "m", "severity": "warning", "trend": "persisting", "summary": "s", "detail": "d", "recommendation": "r"}],
                      ["h|m|x"])
    rows = s.findings_for_run(r2)
    assert len(rows) == 1 and rows[0]["fingerprint"] == "h|m|x" and rows[0]["trend"] == "persisting"
    assert s.finding_run_count("h|m|x", "security_audit") == 2
    assert s.finding_run_count("h|m|x", "daily") == 0
    assert s.runs(limit=1, kind="security_audit")[0]["id"] == r2
```

- [ ] Run `.venv/bin/pytest tests/test_security_diff.py -q` — expect `ModuleNotFoundError: No module named 'heim.security.diff'`.
- [ ] Create `src/heim/security/diff.py`:

```python
"""Week-over-week diff of audit findings. Pure.

Fingerprints (host|check_id|subject) are the join key, so a finding whose
wording changed is still the same finding. A check that could not run this
week neither confirms nor resolves anything: its previous findings are
CARRIED (kept, marked unverified) rather than silently resolved.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from heim.security.types import CheckResult


@dataclass
class AuditDiff:
    new: list[CheckResult] = field(default_factory=list)
    persisting: list[CheckResult] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)     # previous finding rows no longer present
    carried: list[dict] = field(default_factory=list)      # previous rows whose check was unavailable

    @property
    def current(self) -> list[CheckResult]:
        return self.new + self.persisting


def diff_findings(current: list[CheckResult], previous: list[dict],
                  unavailable_check_ids: set[str]) -> AuditDiff:
    prev_by_fp = {str(p.get("fingerprint") or ""): p for p in previous if p.get("fingerprint")}
    cur_fps = {r.fingerprint for r in current}
    d = AuditDiff()
    for r in current:
        (d.persisting if r.fingerprint in prev_by_fp else d.new).append(r)
    for fp, p in prev_by_fp.items():
        if fp in cur_fps:
            continue
        if str(p.get("metric") or "") in unavailable_check_ids:
            d.carried.append(dict(p))
        else:
            d.resolved.append(dict(p))
    return d


def finding_rows(diff: AuditDiff) -> list[dict]:
    """The rows to persist for this run (``store.insert_findings`` shape)."""
    rows = [r.as_finding("new") for r in diff.new] + [r.as_finding("persisting") for r in diff.persisting]
    for p in diff.carried:
        row = {k: str(p.get(k) or "") for k in ("host", "metric", "severity", "summary", "recommendation", "fingerprint")}
        row["trend"] = "carried"
        row["detail"] = f"not re-verified this run (source unavailable). Last detail: {str(p.get('detail') or '')[:400]}"
        row["subject"] = row["fingerprint"].split("|")[-1]
        rows.append(row)
    return rows
```

- [ ] In `src/heim/incidents/store.py`, insert after `recent_findings` (line 777):

```python
    def findings_for_run(self, run_id: int) -> list[dict]:
        """Every finding row of one run (the security audit diffs against these)."""
        cur = self._db.execute("SELECT * FROM findings WHERE run_id = ? ORDER BY id", (int(run_id),))
        return [dict(r) for r in cur.fetchall()]

    def finding_run_count(self, fingerprint: str, source: str) -> int:
        """How many runs of ``source`` have reported ``fingerprint`` (weeks seen)."""
        row = self._db.execute(
            "SELECT COUNT(DISTINCT run_id) AS n FROM findings WHERE fingerprint = ? AND source = ?",
            (str(fingerprint), str(source)),
        ).fetchone()
        return int(row["n"] or 0) if row is not None else 0
```

- [ ] Run `.venv/bin/pytest tests/test_security_diff.py -q` — expect 4 passed. Full suite: 875 passed.
- [ ] Commit: `git add src/heim/security/diff.py src/heim/incidents/store.py tests/test_security_diff.py && git commit -m "security: week-over-week diff with carried findings; store reads for a run's findings"`

### Task 8: Deterministic report, digests, Loki events, and the audit email

**Files**
- Create `src/heim/security/report.py`, `tests/test_security_report.py`.
- Modify `src/heim/reports/render.py:200` (insert after `investigation_email`).

**Interfaces**
- Produces `render_audit_report(results: list[CheckResult], diff: AuditDiff, *, generated_at: str, weeks: dict[str, int]) -> str` (starts with `## Summary`), `coverage_gaps(results) -> list[str]`, `demote_headings(md: str) -> str`, `brief_sections(results, diff) -> dict[str, str]` (`table`, `notes`, `coverage`, `resolved`, `excerpts`), `telegram_digest(diff, results, *, generated_at, assessment: str, reason: str) -> str` (≤ 3500 chars), `ha_attributes(diff, results, *, generated_at, report_md) -> tuple[str, dict]`, `finding_events(rows: list[dict]) -> list[dict]`, `overall_of(rows: list[dict]) -> str`.
- Produces `heim.reports.render.security_audit_email(*, report_md, incomplete, generated_at, n_findings, n_new, n_resolved, n_steps, input_tokens, output_tokens) -> tuple[str, str]`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_report.py
from heim.reports.render import salvage, security_audit_email
from heim.security.diff import AuditDiff, finding_rows
from heim.security.report import (
    brief_sections, coverage_gaps, demote_headings, finding_events, ha_attributes, overall_of,
    render_audit_report, telegram_digest,
)
from heim.security.types import CheckResult

GEN = "2026-09-28T06:00:00.000+02:00"


def res(check, host, subject, status="fail", sev="warning", summary="x", detail="dd"):
    return CheckResult(check, host, subject, status, sev, summary, detail=detail, recommendation="rr")


CRIT = res("ha.core_update_exposed", "home-assistant", "home-assistant", sev="critical", summary="core outdated and public")
WARN = res("pve.tfa_missing", "homelab", "root@pam", summary="root without TFA")
NOTE = res("pve.secureboot", "homelab", "secureboot", status="note", sev="info", summary="Secure Boot off")
UNAV = res("ssh.auth_failures", "ubuntu-server", "-", status="unavailable", summary="not verified: journal denied", detail="journal denied")
OKR = res("prom.time_sync", "heim", "heim", status="ok", summary="")
RESULTS = [CRIT, WARN, NOTE, UNAV, OKR]
DIFF = AuditDiff(new=[CRIT], persisting=[WARN],
                 resolved=[{"fingerprint": "ubuntu-server|ssh.world_writable|/etc/x", "metric": "ssh.world_writable", "host": "ubuntu-server", "severity": "warning"}],
                 carried=[{"fingerprint": "ubuntu-server|ssh.auth_failures|ubuntu-server", "metric": "ssh.auth_failures",
                           "host": "ubuntu-server", "severity": "warning", "summary": "137 failed", "detail": "old", "recommendation": "r"}])


def test_report_contract_and_sections():
    md = render_audit_report(RESULTS, DIFF, generated_at=GEN, weeks={WARN.fingerprint: 3})
    assert md.startswith("## Summary")
    assert not salvage(md, "").incomplete
    for h in ("## Findings", "## Resolved since the previous audit", "## Details and recommendations", "## Notes", "## Coverage gaps", "## Passed checks"):
        assert h in md, h
    assert "critical" in md and "root@pam" in md and "3w" in md and "carried" in md
    assert "ssh.world_writable" in md.split("## Resolved")[1]
    assert "journal denied" in md.split("## Coverage gaps")[1]
    assert "prom.time_sync" in md.split("## Passed checks")[1]
    assert md.index("core outdated") < md.index("root without TFA")     # critical first


def test_report_with_nothing_found():
    md = render_audit_report([OKR], AuditDiff(), generated_at=GEN, weeks={})
    assert md.startswith("## Summary") and "No findings" in md


def test_coverage_and_demote_and_brief():
    assert coverage_gaps(RESULTS) == ["ssh.auth_failures — journal denied"]
    assert demote_headings("## Summary\ntext\n### Sub\n# Top") == "### Summary\ntext\n#### Sub\n## Top"
    b = brief_sections(RESULTS, DIFF)
    assert set(b) == {"table", "notes", "coverage", "resolved", "excerpts"}
    assert "| critical |" in b["table"] and "root@pam" in b["table"] and "Secure Boot" in b["notes"]
    assert "ssh.auth_failures" in b["coverage"] and "ssh.world_writable" in b["resolved"]


def test_digest_is_bounded_and_mentions_assessment_state():
    d = telegram_digest(DIFF, RESULTS, generated_at=GEN, assessment="complete", reason="")
    assert d.startswith("🛡️") and "1 new" in d and "1 resolved" in d and "1 critical" in d and len(d) <= 3500
    d2 = telegram_digest(DIFF, RESULTS, generated_at=GEN, assessment="incomplete", reason="the model declined the request")
    assert "⚠️ AI assessment unavailable" in d2 and "declined" in d2
    big = AuditDiff(new=[res("ssh.world_writable", "ubuntu-server", f"/etc/{i}", summary="w" * 200) for i in range(60)])
    assert len(telegram_digest(big, [], generated_at=GEN, assessment="skipped", reason="")) <= 3500


def test_ha_attributes_and_loki_events_and_overall():
    state, attrs = ha_attributes(DIFF, RESULTS, generated_at=GEN, report_md="## Summary\n\nx")
    assert state == "1 new · 1 persisting · 1 resolved · 1 carried"
    assert attrs["critical"] == 1 and attrs["warning"] == 1 and attrs["friendly_name"] == "PAM Weekly Security Audit"
    assert attrs["report"].startswith("## Summary")
    rows = finding_rows(DIFF)
    evs = finding_events(rows)
    assert len(evs) == 3 and {e["event"] for e in evs} == {"finding"}
    assert {e["labels"]["category"] for e in evs} == {"security"}
    assert {e["labels"]["severity"] for e in evs} == {"crit", "warn"}
    assert all(e["fields"]["source"] == "security_audit" and e["fields"]["fingerprint"] for e in evs)
    assert overall_of(rows) == "critical" and overall_of([]) == "ok"


def test_security_audit_email_subject_and_body():
    subject, html = security_audit_email(report_md="## Summary\n\nhello", incomplete=False, generated_at=GEN,
                                         n_findings=2, n_new=1, n_resolved=1, n_steps=2, input_tokens=1234, output_tokens=56)
    assert subject.startswith("🛡️ Weekly Security Audit — 2 findings, 1 new, 1 resolved — 2026-09-28")
    assert "hello" in html and "1,234" in html
    subject2, _ = security_audit_email(report_md="## Summary\n\nx", incomplete=True, generated_at=GEN,
                                       n_findings=1, n_new=0, n_resolved=0, n_steps=0, input_tokens=0, output_tokens=0)
    assert subject2.endswith("(AI assessment unavailable)") and "1 finding," in subject2
```

- [ ] Run `.venv/bin/pytest tests/test_security_report.py -q` — expect `ModuleNotFoundError: No module named 'heim.security.report'`.
- [ ] Create `src/heim/security/report.py`:

```python
"""The deterministic audit report and its derivatives (digest, HA sensor,
Loki events, brief sections for the model). Pure.

The report is complete without any model output: it starts with '## Summary'
(the same contract reports/render.salvage enforces), so a declined or failed
assessment costs the owner one appendix, not the audit.
"""
from __future__ import annotations

import re

from heim.security.diff import AuditDiff
from heim.security.types import CheckResult

_RANK = {"critical": 0, "warning": 1, "info": 2}
_LOKI_SEV = {"critical": "crit", "warning": "warn", "info": "info"}
_SEV_SCORE = {"critical": 3, "warning": 2, "info": 1}
TELEGRAM_MAX = 3500
HA_REPORT_MAX = 12000
EXCERPT_MAX = 3000


def _cell(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _sorted(rows: list[CheckResult]) -> list[CheckResult]:
    return sorted(rows, key=lambda r: (_RANK.get(r.severity, 9), r.host, r.check_id, r.subject))


def coverage_gaps(results: list[CheckResult]) -> list[str]:
    seen: dict[str, str] = {}
    for r in results:
        if r.status == "unavailable" and r.check_id not in seen:
            seen[r.check_id] = r.detail or r.summary.removeprefix("not verified: ")
    return [f"{cid} — {why}" for cid, why in sorted(seen.items())]


def overall_of(rows: list[dict]) -> str:
    sevs = {str(r.get("severity") or "") for r in rows}
    return "critical" if "critical" in sevs else "warning" if "warning" in sevs else "ok"


def demote_headings(md: str) -> str:
    return re.sub(r"^(#{1,5}) ", r"#\1 ", md or "", flags=re.M)


def render_audit_report(results: list[CheckResult], diff: AuditDiff, *,
                        generated_at: str, weeks: dict[str, int]) -> str:
    findings = _sorted(diff.new) + _sorted(diff.persisting)
    new_fps = {r.fingerprint for r in diff.new}
    crit = sum(1 for r in findings if r.severity == "critical")
    warn = sum(1 for r in findings if r.severity == "warning")
    gaps = coverage_gaps(results)
    notes = _sorted([r for r in results if r.status == "note"])
    passed = sorted({r.check_id for r in results if r.status == "ok"} - {r.check_id for r in results if r.status == "fail"})

    L = ["## Summary", "",
         f"Weekly read-only security audit generated {generated_at}. {len(results)} check rows evaluated; "
         f"**{len(findings)} findings** ({crit} critical, {warn} warning): {len(diff.new)} new, "
         f"{len(diff.persisting)} persisting, {len(diff.resolved)} resolved since the previous audit, "
         f"{len(diff.carried)} carried forward unverified. {len(gaps)} check(s) could not run.", ""]
    if not findings and not diff.carried:
        L += ["No findings. Every check that ran passed.", ""]

    L += ["## Findings", "", "| # | Severity | Host | Check | Subject | Status | Seen | Summary |",
          "|---|---|---|---|---|---|---|---|"]
    n = 0
    for r in findings:
        n += 1
        trend = "new" if r.fingerprint in new_fps else "persisting"
        L.append(f"| {n} | {r.severity} | {r.host} | `{r.check_id}` | {_cell(r.subject)} | {trend} | "
                 f"{weeks.get(r.fingerprint, 1)}w | {_cell(r.summary)} |")
    for p in diff.carried:
        n += 1
        L.append(f"| {n} | {p.get('severity')} | {p.get('host')} | `{p.get('metric')}` | "
                 f"{_cell(str(p.get('fingerprint', '')).split('|')[-1])} | carried | "
                 f"{weeks.get(str(p.get('fingerprint')), 1)}w | {_cell(p.get('summary'))} (not re-verified) |")
    if n == 0:
        L.append("| – | – | – | – | – | – | – | none |")

    L += ["", "## Resolved since the previous audit", ""]
    L += [f"- ✅ `{p.get('metric')}` on {p.get('host')} — {_cell(str(p.get('fingerprint', '')).split('|')[-1])}"
          for p in diff.resolved] or ["- none"]

    L += ["", "## Details and recommendations", ""]
    for r in findings:
        L += [f"### {r.host} · `{r.check_id}` · {_cell(r.subject)}", "", r.summary, ""]
        if r.detail:
            L += ["```", r.detail[:1500], "```", ""]
        if r.recommendation:
            L += [f"**Recommended (human action — this audit is read-only):** {r.recommendation}", ""]
    if not findings:
        L += ["(no findings)", ""]

    L += ["## Notes (informational, not findings)", ""]
    L += [f"- {r.host} · `{r.check_id}` · {_cell(r.summary)}" for r in notes] or ["- none"]

    L += ["", "## Coverage gaps", ""]
    L += [f"- `{g.split(' — ')[0]}` — {g.split(' — ', 1)[1]}" for g in gaps] or ["- none — every check ran"]

    L += ["", "## Passed checks", "", f"{len(passed)} checks passed: " + (", ".join(f"`{c}`" for c in passed) or "none"), ""]
    return "\n".join(L)


def brief_sections(results: list[CheckResult], diff: AuditDiff) -> dict[str, str]:
    """The text blocks the model's brief is rendered from (bounded)."""
    new_fps = {r.fingerprint for r in diff.new}
    table = ["| severity | host | check | subject | status | summary |", "|---|---|---|---|---|---|"]
    for r in _sorted(diff.new) + _sorted(diff.persisting):
        table.append(f"| {r.severity} | {r.host} | {r.check_id} | {_cell(r.subject)} | "
                     f"{'new' if r.fingerprint in new_fps else 'persisting'} | {_cell(r.summary)} |")
    for p in diff.carried:
        table.append(f"| {p.get('severity')} | {p.get('host')} | {p.get('metric')} | "
                     f"{_cell(str(p.get('fingerprint', '')).split('|')[-1])} | carried (unverified) | {_cell(p.get('summary'))} |")
    if len(table) == 2:
        table.append("| – | – | – | – | – | no findings |")
    notes = [f"- {r.host} · {r.check_id} · {_cell(r.summary)}" for r in _sorted([r for r in results if r.status == "note"])] or ["- none"]
    coverage = [f"- {g}" for g in coverage_gaps(results)] or ["- none"]
    resolved = [f"- {p.get('metric')} on {p.get('host')} ({str(p.get('fingerprint', '')).split('|')[-1]})" for p in diff.resolved] or ["- none"]
    excerpts = []
    for r in _sorted(diff.new) + _sorted(diff.persisting):
        if r.detail:
            excerpts.append(f"[{r.check_id} · {r.subject}]\n{r.detail[:600]}")
    ex = "\n\n".join(excerpts)
    return {"table": "\n".join(table), "notes": "\n".join(notes), "coverage": "\n".join(coverage),
            "resolved": "\n".join(resolved), "excerpts": ex[:EXCERPT_MAX] + ("\n…" if len(ex) > EXCERPT_MAX else "") or "(none)"}


def telegram_digest(diff: AuditDiff, results: list[CheckResult], *, generated_at: str,
                    assessment: str, reason: str) -> str:
    cur = diff.current
    crit = sum(1 for r in cur if r.severity == "critical")
    gaps = len(coverage_gaps(results))
    L = [f"🛡️ Weekly security audit — {generated_at[:10]}",
         f"{len(cur)} findings · {crit} critical · {len(diff.new)} new · {len(diff.persisting)} persisting · "
         f"{len(diff.resolved)} resolved · {len(diff.carried)} carried · {gaps} checks unavailable", ""]
    for r in _sorted(diff.new)[:8]:
        L.append(f"🆕 [{r.severity}] {r.host} · {r.check_id} · {r.summary[:120]}")
    if len(diff.new) > 8:
        L.append(f"… +{len(diff.new) - 8} more new")
    for p in diff.resolved[:3]:
        L.append(f"✅ resolved: {p.get('host')} · {p.get('metric')}")
    if assessment == "incomplete":
        L += ["", f"⚠️ AI assessment unavailable — {reason}"]
    elif assessment == "failed":
        L += ["", f"⚠️ AI assessment failed — {reason}"]
    elif assessment == "skipped":
        L += ["", "ℹ️ AI assessment skipped (--no-llm)"]
    L += ["", "Full report by email · dashboard: /investigations?trigger=security_audit"]
    text = "\n".join(L)
    return text if len(text) <= TELEGRAM_MAX else text[:TELEGRAM_MAX - 2] + " …"


def ha_attributes(diff: AuditDiff, results: list[CheckResult], *, generated_at: str,
                  report_md: str) -> tuple[str, dict]:
    cur = diff.current
    state = f"{len(diff.new)} new · {len(diff.persisting)} persisting · {len(diff.resolved)} resolved · {len(diff.carried)} carried"
    attrs = {
        "friendly_name": "PAM Weekly Security Audit", "icon": "mdi:shield-search",
        "findings": len(cur), "new": len(diff.new), "persisting": len(diff.persisting),
        "resolved": len(diff.resolved), "carried": len(diff.carried),
        "critical": sum(1 for r in cur if r.severity == "critical"),
        "warning": sum(1 for r in cur if r.severity == "warning"),
        "unavailable_checks": len(coverage_gaps(results)),
        "updated": generated_at, "report": (report_md or "").strip()[:HA_REPORT_MAX],
    }
    return state, attrs


def finding_events(rows: list[dict]) -> list[dict]:
    """Loki ``finding`` events (existing event type) tagged category=security."""
    out = []
    for r in rows:
        sev = str(r.get("severity") or "info")
        out.append({
            "event": "finding",
            "labels": {"severity": _LOKI_SEV.get(sev, "info"), "host": str(r.get("host") or "all"), "category": "security"},
            "fields": {
                "metric": str(r.get("metric") or ""), "trend": str(r.get("trend") or ""),
                "summary": str(r.get("summary") or "")[:150], "action": str(r.get("recommendation") or "")[:120],
                "detail": str(r.get("detail") or ""), "recommendation": str(r.get("recommendation") or ""),
                "sevScore": _SEV_SCORE.get(sev, 0), "fingerprint": str(r.get("fingerprint") or ""),
                "source": "security_audit",
            },
        })
    return out
```

- [ ] In `src/heim/reports/render.py`, insert after `investigation_email` (line 200):

```python
def security_audit_email(
    *,
    report_md: str,
    incomplete: bool,
    generated_at: str,
    n_findings: int,
    n_new: int,
    n_resolved: int,
    n_steps: int,
    input_tokens: int,
    output_tokens: int,
) -> tuple[str, str]:
    """The weekly security-audit email. Reuses the investigation template: the
    body is the deterministic report plus the model's appendix, and
    ``incomplete`` means only that the appendix is missing."""
    subject = (
        f"🛡️ Weekly Security Audit — {n_findings} finding{'s' if n_findings != 1 else ''}, "
        f"{n_new} new, {n_resolved} resolved — {generated_at[:10]}"
        + (" (AI assessment unavailable)" if incomplete else "")
    )
    html = _env.get_template("investigation.html.j2").render(
        host="homelab · all hosts",
        generated_at=generated_at.replace("T", " ")[:16],
        incomplete=incomplete,
        body=_md_to_html(report_md),
        n_steps=n_steps,
        input_tokens=f"{input_tokens:,}",
        output_tokens=f"{output_tokens:,}",
    )
    return subject, html
```

- [ ] Run `.venv/bin/pytest tests/test_security_report.py -q` — expect 6 passed. Full suite: 881 passed.
- [ ] Commit: `git add src/heim/security/report.py src/heim/reports/render.py tests/test_security_report.py && git commit -m "security: deterministic audit report, Telegram digest, HA attributes, Loki finding events, audit email"`

### Task 9: Evidence fetchers (the I/O half): fixed GET paths, PromQL, guard-validated SSH

**Files**
- Create `src/heim/pipelines/security_sources.py`, `tests/test_security_sources.py`.

**Interfaces**
- Produces `classify_http(key, status_code, text, *, unwrap="data", target="") -> Evidence` (pure), `prom_evidence(key, status_code, text, target) -> Evidence` (pure), `async fetch_pve(cfg, sources, *, node) -> list[Evidence]`, `async fetch_ha(cfg, sources, *, host) -> list[Evidence]`, `async fetch_prom(cfg, sources) -> list[Evidence]`, `async fetch_ssh(cfg, sources, *, ssh_host) -> list[Evidence]`, `async collect_evidence(cfg: Config, cat: Catalogue, *, now_iso: str) -> EvidenceBundle`.
- Constants `HTTP_TIMEOUT_S = 30`, `SSH_CONNECT_TIMEOUT_S = 20`, `SSH_CLIP_BYTES = 65536`, `KIND_TIMEOUT_S = 300`; reuses `heim.tools.ssh_diagnostic.COMMAND_TIMEOUT_S`.
- Consumes `env("PROXMOX_TOKEN")`, `env("HA_TOKEN")`, `cfg.hosts[...].api/.ssh`, `cfg.settings.prometheus.url`, `guard_command`, `validate_pve_path`, `docker_names`, `vmids_from_resources`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_sources.py
"""Fetchers: GET-only, statuses classified, expansions, timeouts. Network is
faked by monkeypatching the module's httpx.AsyncClient / asyncssh.connect."""
import asyncio
import json
import shutil
from pathlib import Path

import pytest

from heim.config import load_config
from heim.pipelines import security_sources as src
from heim.security.catalogue import load_catalogue
from heim.security.types import SourceSpec

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    monkeypatch.setenv("PROXMOX_TOKEN", "user@pve!tok=secret")
    monkeypatch.setenv("HA_TOKEN", "hatoken")
    return load_config(croot)


class _Resp:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text


def fake_httpx(monkeypatch, router):
    """router(url, params) -> (status, text) ; records every call (GET only exists)."""
    calls = []

    class FakeClient:
        def __init__(self, **kw):
            self.kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, params=None, headers=None):
            calls.append({"url": url, "params": params, "headers": headers, "timeout": self.kw.get("timeout")})
            status, text = router(url, params)
            return _Resp(status, text)

    monkeypatch.setattr(src.httpx, "AsyncClient", FakeClient)
    return calls


def test_classify_http_statuses():
    assert src.classify_http("k", 200, json.dumps({"data": []})).status == "empty"
    assert src.classify_http("k", 200, json.dumps({"data": [1]})).status == "ok"
    assert src.classify_http("k", 403, "").status == "denied"
    assert src.classify_http("k", 404, "").status == "error"
    assert src.classify_http("k", 596, "").status == "error"
    assert src.classify_http("k", 200, "<html>").status == "error"
    raw = src.classify_http("k", 200, json.dumps({"version": "2026.9.1"}), unwrap="")
    assert raw.status == "ok" and raw.body["version"] == "2026.9.1"
    prom = src.prom_evidence("p", 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": [{"metric": {}, "value": [1, "1"]}]}}), "up")
    assert prom.status == "ok" and len(prom.body) == 1 and prom.target == "up"
    assert src.prom_evidence("p", 200, json.dumps({"status": "error", "error": "bad"}), "x").status == "error"
    assert src.prom_evidence("p", 200, json.dumps({"status": "success", "data": {"result": []}}), "x").status == "empty"


async def test_fetch_pve_expands_vmids_and_marks_denied(cfg, monkeypatch):
    def router(url, params):
        if url.endswith("/cluster/resources?type=vm"):
            return 200, json.dumps({"data": [{"vmid": 100, "name": "ubuntu-server", "type": "qemu"}, {"vmid": 103, "name": "heim", "type": "qemu"}]})
        if url.endswith("/access/tfa"):
            return 200, json.dumps({"data": []})
        if "/qemu/" in url and url.endswith("/config"):
            return 200, json.dumps({"data": {"net0": "virtio=x,firewall=1"}})
        if url.endswith("/apt/update"):
            return 403, "Permission check failed"
        return 200, json.dumps({"data": {"ok": 1}})
    calls = fake_httpx(monkeypatch, router)
    sources = [SourceSpec("pve.resources_vm", "pve", "/api2/json/cluster/resources?type=vm"),
               SourceSpec("pve.access_tfa", "pve", "/api2/json/access/tfa", control="pve.access_users"),
               SourceSpec("pve.vm_config", "pve", "/api2/json/nodes/homelab/qemu/{vmid}/config", expand="vmid")]
    out = {e.key: e for e in await src.fetch_pve(cfg, sources, node="homelab")}
    assert out["pve.resources_vm"].status == "ok"
    assert out["pve.access_tfa"].status == "empty"
    assert out["pve.vm_config[100]"].status == "ok" and out["pve.vm_config[103]"].body["net0"].endswith("firewall=1")
    assert all(c["headers"]["Authorization"].startswith("PVEAPIToken=") for c in calls)
    assert all(c["timeout"] == src.HTTP_TIMEOUT_S for c in calls)
    assert all("/api2/json/" in c["url"] for c in calls)


async def test_fetch_pve_without_token_is_denied_not_a_crash(cfg, monkeypatch):
    monkeypatch.delenv("PROXMOX_TOKEN")
    out = await src.fetch_pve(cfg, [SourceSpec("pve.version", "pve", "/api2/json/version")], node="homelab")
    assert out[0].status == "denied" and "PROXMOX_TOKEN" in out[0].detail


async def test_fetch_ha_and_prom(cfg, monkeypatch):
    def router(url, params):
        if url.endswith("/api/config"):
            return 200, json.dumps({"version": "2026.9.1"})
        if url.endswith("/api/states"):
            return 200, json.dumps([])
        if url.endswith("/api/v1/query"):
            return 200, json.dumps({"status": "success", "data": {"result": [{"metric": {"instance": "a"}, "value": [1, "0"]}]}})
        return 500, "boom"
    calls = fake_httpx(monkeypatch, router)
    ha = {e.key: e for e in await src.fetch_ha(cfg, [SourceSpec("ha.config", "ha", "/api/config"), SourceSpec("ha.states", "ha", "/api/states")], host="home-assistant")}
    assert ha["ha.config"].status == "ok" and ha["ha.states"].status == "empty"
    pr = await src.fetch_prom(cfg, [SourceSpec("prom.up", "prom", "up")])
    assert pr[0].status == "ok" and pr[0].target == "up"
    assert [c["params"] for c in calls if c["params"]] == [{"query": "up"}]


class _SshResult:
    def __init__(self, stdout, stderr="", exit_status=0):
        self.stdout, self.stderr, self.exit_status = stdout, stderr, exit_status


class _Conn:
    def __init__(self, script):
        self.script, self.ran, self.closed = script, [], False

    async def run(self, command, check=False):
        self.ran.append(command)
        r = self.script(command)
        if isinstance(r, Exception):
            raise r
        return r

    def close(self):
        self.closed = True


async def test_fetch_ssh_runs_guarded_lines_and_expands_containers(cfg, monkeypatch):
    def script(cmd):
        if cmd == "sudo agent-docker ps":
            return _SshResult("CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\nabc img cmd 1d Up  grafana\ndef img cmd 1d Up  bad;name\n")
        if cmd.startswith("sudo agent-docker inspect "):
            return _SshResult(json.dumps([{"HostConfig": {}}]))
        if cmd.startswith("journalctl"):
            return _SshResult("0\n", stderr="Hint: You are currently not seeing messages from other users and the system.\n", exit_status=1)
        return _SshResult("x\n")
    conn = _Conn(script)

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    monkeypatch.setattr(src, "SSH_CONNECT_TIMEOUT_S", 5)
    sources = [SourceSpec("ssh.docker_ps", "ssh", "sudo agent-docker ps"),
               SourceSpec("ssh.docker_inspect", "ssh", "sudo agent-docker inspect {container}", expand="container"),
               SourceSpec("ssh.auth_fail_count", "ssh", "journalctl --no-pager -u ssh -o cat | grep -c -E 'Failed password'")]
    out = {e.key: e for e in await src.fetch_ssh(cfg, sources, ssh_host="ubuntu-server")}
    assert out["ssh.docker_ps"].status == "ok"
    assert "ssh.docker_inspect[grafana]" in out and not any("bad" in k for k in out)   # invalid name never runs
    assert out["ssh.auth_fail_count"].exit_code == 1 and "not seeing messages" in out["ssh.auth_fail_count"].stderr
    assert out["ssh.auth_fail_count"].target.startswith("journalctl")
    assert conn.closed and all(not c.startswith("rm") for c in conn.ran)


async def test_fetch_ssh_connect_failure_marks_every_source(cfg, monkeypatch):
    async def fake_connect(*a, **k):
        raise OSError("no route to host")
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = await src.fetch_ssh(cfg, [SourceSpec("ssh.listeners", "ssh", "sudo ss -tunlpH")], ssh_host="ubuntu-server")
    assert out[0].status == "error" and "no route" in out[0].detail


async def test_fetch_ssh_host_without_shell(cfg):
    out = await src.fetch_ssh(cfg, [SourceSpec("ssh.listeners", "ssh", "sudo ss -tunlpH")], ssh_host="heim")
    assert out[0].status == "error" and "no ssh" in out[0].detail.lower()


async def test_collect_evidence_bounds_each_kind(cfg, monkeypatch):
    cat = load_catalogue(ROOT / "config" / "security" / "checks.yaml")

    async def slow(*a, **k):
        await asyncio.sleep(10)
        return []

    async def quick_pve(cfg_, sources, *, node):
        return [src.Evidence(s.key, "ok", body={"x": 1}) for s in sources if not s.expand]
    monkeypatch.setattr(src, "fetch_pve", quick_pve)
    monkeypatch.setattr(src, "fetch_ha", slow)
    monkeypatch.setattr(src, "fetch_prom", slow)
    monkeypatch.setattr(src, "fetch_ssh", slow)
    monkeypatch.setattr(src, "KIND_TIMEOUT_S", 0.05)
    bundle = await src.collect_evidence(cfg, cat, now_iso="2026-09-28T06:00:00")
    assert bundle.get("pve.version").status == "ok"
    assert bundle.get("ha.config").status == "timeout" and bundle.get("ssh.listeners").status == "timeout"
    assert bundle.collected_at == "2026-09-28T06:00:00"
```

- [ ] Run `.venv/bin/pytest tests/test_security_sources.py -q` — expect `ImportError` (module missing).
- [ ] Create `src/heim/pipelines/security_sources.py`:

```python
"""Evidence fetchers for the weekly security audit — the I/O half.

Everything here is a READ: httpx GET against Proxmox / Home Assistant /
Prometheus, and guard-validated shell lines over one SSH connection. Targets
come from the validated catalogue only; expansions ({vmid}, {container}) are
re-validated after substitution. Every failure becomes an Evidence status the
evaluators turn into `unavailable`, never an exception up the pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging

import asyncssh
import httpx

from heim.config import Config, env
from heim.guards import guard_command
from heim.security.catalogue import Catalogue, CatalogueError, validate_pve_path
from heim.security.parsers import NAME_RE, docker_names, vmids_from_resources
from heim.security.types import Evidence, EvidenceBundle, SourceSpec
from heim.tools.base import clip
from heim.tools.ssh_diagnostic import COMMAND_TIMEOUT_S

log = logging.getLogger(__name__)

HTTP_TIMEOUT_S = 30
SSH_CONNECT_TIMEOUT_S = 20
SSH_CLIP_BYTES = 65536
KIND_TIMEOUT_S = 300
MAX_CONTAINERS = 40


# ------------------------------------------------------------------ pure bits

def classify_http(key: str, status_code: int, text: str, *, unwrap: str = "data", target: str = "") -> Evidence:
    """HTTP answer → Evidence. 401/403 = denied (the token lacks the privilege),
    404 = error (not on this version), 2xx = ok or EMPTY — the caller's control
    rule decides whether empty means anything."""
    if status_code in (401, 403):
        return Evidence(key, "denied", http_status=status_code, target=target,
                        detail=f"HTTP {status_code}: the token lacks the privilege for this path")
    if status_code == 404:
        return Evidence(key, "error", http_status=404, target=target, detail="HTTP 404: endpoint not available on this version")
    if status_code >= 400:
        return Evidence(key, "error", http_status=status_code, target=target, detail=f"HTTP {status_code}")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return Evidence(key, "error", http_status=status_code, target=target, detail="response was not JSON")
    body = parsed.get(unwrap) if unwrap and isinstance(parsed, dict) and unwrap in parsed else parsed
    empty = body is None or body == [] or body == {} or body == ""
    return Evidence(key, "empty" if empty else "ok", body=body, http_status=status_code, target=target)


def prom_evidence(key: str, status_code: int, text: str, target: str) -> Evidence:
    if status_code >= 400:
        return Evidence(key, "error", http_status=status_code, target=target, detail=f"HTTP {status_code}")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return Evidence(key, "error", http_status=status_code, target=target, detail="response was not JSON")
    if not isinstance(parsed, dict) or parsed.get("status") != "success":
        return Evidence(key, "error", http_status=status_code, target=target,
                        detail=f"prometheus: {str((parsed or {}).get('error') if isinstance(parsed, dict) else parsed)[:120]}")
    result = (parsed.get("data") or {}).get("result") or []
    return Evidence(key, "ok" if result else "empty", body=result, http_status=status_code, target=target)


def _all(sources: list[SourceSpec], status: str, detail: str) -> list[Evidence]:
    return [Evidence(s.key, status, detail=detail, target=s.target) for s in sources]


# ---------------------------------------------------------------------- HTTP

async def fetch_pve(cfg: Config, sources: list[SourceSpec], *, node: str) -> list[Evidence]:
    host = cfg.hosts.get(node)
    if host is None or host.api is None:
        return _all(sources, "error", f"host {node} has no api config")
    token = env("PROXMOX_TOKEN")
    if not token:
        return _all(sources, "denied", "PROXMOX_TOKEN is not set — the Proxmox part of the audit is disabled")
    base = host.api.url.rstrip("/")
    headers = {"Authorization": f"PVEAPIToken={token}"}
    out: list[Evidence] = []

    async def get(key: str, path: str) -> Evidence:
        try:
            path = validate_pve_path(path, key=key)
        except CatalogueError as exc:
            return Evidence(key, "blocked", detail=str(exc), target=path)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, verify=host.api.verify_ssl) as client:
                r = await client.get(base + path, headers=headers)
        except httpx.TimeoutException:
            return Evidence(key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=path)
        except httpx.HTTPError as exc:
            return Evidence(key, "error", detail=f"{type(exc).__name__}: {exc}", target=path)
        return classify_http(key, r.status_code, r.text, target=path)

    plain = [s for s in sources if not s.expand]
    for e in await asyncio.gather(*(get(s.key, s.target) for s in plain)):
        out.append(e)
    vm_sources = [s for s in sources if s.expand == "vmid"]
    if vm_sources:
        res = next((e for e in out if e.key == "pve.resources_vm"), None)
        if res is None:
            res = await get("pve.resources_vm", "/api2/json/cluster/resources?type=vm")
            out.append(res)
        vmids = sorted(vmids_from_resources(res.body)) if res.status == "ok" else []
        if not vmids:
            out.extend(Evidence(s.key, "error", detail="VM list unavailable — per-VM sources not fetched", target=s.target) for s in vm_sources)
        else:
            jobs = [(f"{s.key}[{v}]", s.target.replace("{vmid}", v)) for s in vm_sources for v in vmids]
            out.extend(await asyncio.gather(*(get(k, p) for k, p in jobs)))
    return out


async def fetch_ha(cfg: Config, sources: list[SourceSpec], *, host: str) -> list[Evidence]:
    h = cfg.hosts.get(host)
    base_url = h.api.url if (h and h.api) else (cfg.settings.home_assistant.url if cfg.settings.home_assistant else "")
    if not base_url:
        return _all(sources, "error", f"host {host} has no api url")
    token = env("HA_TOKEN")
    if not token:
        return _all(sources, "denied", "HA_TOKEN is not set — the Home Assistant part of the audit is disabled")
    base = base_url.rstrip("/")
    verify = h.api.verify_ssl if (h and h.api) else True

    async def get(s: SourceSpec) -> Evidence:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, verify=verify) as client:
                r = await client.get(base + s.target, headers={"Authorization": f"Bearer {token}"})
        except httpx.TimeoutException:
            return Evidence(s.key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=s.target)
        except httpx.HTTPError as exc:
            return Evidence(s.key, "error", detail=f"{type(exc).__name__}: {exc}", target=s.target)
        return classify_http(s.key, r.status_code, r.text, unwrap="", target=s.target)

    return list(await asyncio.gather(*(get(s) for s in sources)))


async def fetch_prom(cfg: Config, sources: list[SourceSpec]) -> list[Evidence]:
    base = cfg.settings.prometheus.url.rstrip("/")

    async def get(s: SourceSpec) -> Evidence:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
                r = await client.get(f"{base}/api/v1/query", params={"query": s.target})
        except httpx.TimeoutException:
            return Evidence(s.key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=s.target)
        except httpx.HTTPError as exc:
            return Evidence(s.key, "error", detail=f"{type(exc).__name__}: {exc}", target=s.target)
        return prom_evidence(s.key, r.status_code, r.text, s.target)

    return list(await asyncio.gather(*(get(s) for s in sources)))


# ----------------------------------------------------------------------- SSH

async def fetch_ssh(cfg: Config, sources: list[SourceSpec], *, ssh_host: str) -> list[Evidence]:
    host = cfg.hosts.get(ssh_host)
    if host is None or host.ssh is None:
        return _all(sources, "error", f"host {ssh_host} has no ssh config — no shell for the audit")
    ssh = host.ssh
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(ssh.host, port=ssh.port, username=ssh.user,
                             client_keys=[ssh.resolved_key_path()], known_hosts=None),
            SSH_CONNECT_TIMEOUT_S)
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as exc:
        return _all(sources, "error", f"ssh unavailable: {type(exc).__name__}: {exc}")

    async def run(key: str, line: str) -> Evidence:
        g = guard_command(line)
        if not g.allowed:
            return Evidence(key, "blocked", detail=g.reason or "guard", target=line)
        try:
            r = await asyncio.wait_for(conn.run(g.normalized, check=False), COMMAND_TIMEOUT_S)
        except asyncio.TimeoutError:
            return Evidence(key, "timeout", detail=f"no answer in {COMMAND_TIMEOUT_S}s", target=line)
        except (OSError, asyncssh.Error) as exc:
            return Evidence(key, "error", detail=f"{type(exc).__name__}: {exc}", target=line)
        stdout = clip(str(r.stdout or ""), SSH_CLIP_BYTES)
        return Evidence(key, "ok" if stdout.strip() else "empty", body=stdout, exit_code=r.exit_status,
                        stderr=clip(str(r.stderr or ""), 2048), target=line)

    out: list[Evidence] = []
    try:
        for s in sources:
            if not s.expand:
                out.append(await run(s.key, s.target))
        for s in sources:
            if s.expand != "container":
                continue
            ps = next((e for e in out if e.key == "ssh.docker_ps"), None)
            if ps is None or ps.status != "ok":
                out.append(Evidence(s.key, "error", detail="container list unavailable — per-container sources not fetched", target=s.target))
                continue
            for name in docker_names(str(ps.body or ""))[:MAX_CONTAINERS]:
                if not NAME_RE.match(name):
                    continue
                out.append(await run(f"{s.key}[{name}]", s.target.replace("{container}", name)))
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------- orchestrate

async def _bounded(coro, sources: list[SourceSpec], kind: str) -> list[Evidence]:
    try:
        return await asyncio.wait_for(coro, KIND_TIMEOUT_S)
    except asyncio.TimeoutError:
        return _all(sources, "timeout", f"{kind} collection exceeded {KIND_TIMEOUT_S}s")
    except Exception as exc:  # a fetcher bug must degrade one kind, not the audit
        log.exception("%s collection failed", kind)
        return _all(sources, "error", f"{type(exc).__name__}: {exc}")


async def collect_evidence(cfg: Config, cat: Catalogue, *, now_iso: str) -> EvidenceBundle:
    pve, ha, prom, ssh = (cat.by_kind(k) for k in ("pve", "ha", "prom", "ssh"))
    gathered = await asyncio.gather(
        _bounded(fetch_pve(cfg, pve, node=cat.pve_node), pve, "pve"),
        _bounded(fetch_ha(cfg, ha, host=cat.ha_host), ha, "ha"),
        _bounded(fetch_prom(cfg, prom), prom, "prom"),
        _bounded(fetch_ssh(cfg, ssh, ssh_host=cat.ssh_host), ssh, "ssh"),
    )
    bundle = EvidenceBundle(collected_at=now_iso)
    for items in gathered:
        for e in items:
            bundle.items[e.key] = e
    log.info("security audit evidence: %d items (%s)", len(bundle.items),
             ", ".join(f"{k}={sum(1 for e in bundle.items.values() if e.key.startswith(k + '.') and e.usable)}"
                       for k in ("pve", "ha", "prom", "ssh")))
    return bundle
```

- [ ] Run `.venv/bin/pytest tests/test_security_sources.py -q` — expect 8 passed. Full suite: 889 passed.
- [ ] Commit: `git add src/heim/pipelines/security_sources.py tests/test_security_sources.py && git commit -m "security: GET-only evidence fetchers with status classification, expansion and per-kind timeouts"`

### Task 10: The `security_auditor` agent, its prompts, and the prompt-hygiene test

**Files**
- Create `config/agents/security_auditor.yaml`, `config/prompts/security_auditor.md.j2`, `config/prompts/briefs/security_audit.md.j2`.
- Create `src/heim/pipelines/security_audit.py` (prompt builders only in this task; the pipeline body comes in Task 11).
- Create `tests/test_security_prompt.py`.

**Interfaces**
- Produces `build_audit_system_prompt(rt: Runtime, jenv: Environment) -> str` and `build_audit_brief(rt: Runtime, jenv: Environment, results: list[CheckResult], diff: AuditDiff, *, generated_at: str) -> str`; constants `AUDIT_KIND = "security_audit"`, `AGENT_NAME = "security_auditor"`, `AUDIT_HOST = "all"`, `ATTACK_TERMS`.
- Consumes `cfg.agents["security_auditor"]`, `cfg.hosts[*].facts`, `expand_env`, `brief_sections`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_prompt.py
import shutil
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines.security_audit import (
    AGENT_NAME, ATTACK_TERMS, AUDIT_KIND, build_audit_brief, build_audit_system_prompt,
)
from heim.runtime import Runtime
from heim.security.diff import AuditDiff
from heim.security.types import CheckResult

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def rt(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "s.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def test_agent_config_is_loaded_with_the_intended_budget_and_tools(rt):
    a = rt.config.agents[AGENT_NAME]
    assert a.model == "claude-sonnet-5" and a.max_tokens == 8192
    assert a.soft_step_budget == 4 and a.hard_step_cap == 6
    assert set(a.tools) == {"prometheus_query", "discover_metrics", "proxmox_api"}
    assert "ssh_diagnostic" not in a.tools
    assert a.model in rt.config.settings.model_prices          # priced, not an em dash
    assert AUDIT_KIND == "security_audit"


def test_system_prompt_renders_facts_budget_and_output_contract(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    text = build_audit_system_prompt(rt, jenv)
    assert "## Summary" in text and "~4 tool calls" in text
    assert "ubuntu-server" in text and "heim" in text          # host facts injected
    assert "${" not in text                                    # env expanded
    assert "read-only" in text.lower() and "never change" in text.lower()


def test_brief_carries_table_diff_coverage_and_excerpts(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    crit = CheckResult("ha.core_update_exposed", "home-assistant", "home-assistant", "fail", "critical", "core outdated and public", detail="2026.9.1 → 2026.9.3", recommendation="update")
    unav = CheckResult("ssh.auth_failures", "ubuntu-server", "-", "unavailable", "warning", "not verified: journal denied", detail="journal denied")
    diff = AuditDiff(new=[crit], resolved=[{"fingerprint": "homelab|pve.repo_risky|pve-test", "metric": "pve.repo_risky", "host": "homelab"}])
    brief = build_audit_brief(rt, jenv, [crit, unav], diff, generated_at="2026-09-28T06:00:00Z")
    assert "1 new" in brief and "1 resolved" in brief
    assert "| critical | home-assistant | ha.core_update_exposed" in brief
    assert "ssh.auth_failures — journal denied" in brief
    assert "pve.repo_risky" in brief and "2026.9.3" in brief
    assert brief.rstrip().endswith("'## Summary'.")


def test_prompts_contain_no_attack_vocabulary(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    system = build_audit_system_prompt(rt, jenv).lower()
    brief = build_audit_brief(rt, jenv, [], AuditDiff(), generated_at="2026-09-28T06:00:00Z").lower()
    for term in ATTACK_TERMS:
        assert term not in system, f"system prompt contains {term!r}"
        assert term not in brief, f"brief contains {term!r}"
    assert set(ATTACK_TERMS) >= {"exploit", "attack", "brute", "penetration", "pentest", "payload", "intrusion", "crack", "bypass"}
```

- [ ] Run `.venv/bin/pytest tests/test_security_prompt.py -q` — expect `ImportError` (module missing).
- [ ] Create `config/agents/security_auditor.yaml`:

```yaml
name: security_auditor
model: claude-sonnet-5
max_tokens: 8192        # adaptive thinking counts toward max_tokens (same reason as the investigator)
soft_step_budget: 4     # the prompt says most weeks need no tool call at all
hard_step_cap: 6        # verification only — every check was already run by deterministic code
prompt: security_auditor.md.j2
tools:
  - prometheus_query
  - discover_metrics
  - proxmox_api
# Deliberately NO ssh_diagnostic: the model never chooses a shell command in
# the audit. Every SSH read is a fixed, guard-validated line in
# config/security/checks.yaml executed by HEIM code, not by the model.
```

- [ ] Create `config/prompts/security_auditor.md.j2`:

```
You are a senior SRE reviewing the configuration hygiene of a small homelab that its operator owns and administers. Now: {{ now }}. This review is defensive and strictly read-only: deterministic code has already run every check and produced the table in the user message. Your job is to explain what those results mean for THIS setup, rank what deserves the operator's attention first, and recommend safe steps a human can take. You never change anything, and you never look for issues beyond the table.

[FACTS — the systems under review]
{{ facts }}

[WHAT YOU MAY DO]
- Use 'prometheus_query' and 'discover_metrics' to add context to a listed result (how long a unit has been failed, when a reboot flag appeared, whether a target has been flapping). Instant queries by default; pass lookback (24h/3d) for a range.
- Use 'proxmox_api' (read-only GET) for hypervisor context: /api2/json/nodes/homelab/journal?lastentries=200, /api2/json/nodes/homelab/tasks?limit=20, /api2/json/nodes/homelab/qemu/<vmid>/config, /api2/json/cluster/resources. Other paths are blocked by the guard — do not retry a blocked path; note it and move on.
- Treat a row marked UNAVAILABLE or CARRIED as "not verified this week" — never as passed or failed.

[WHAT YOU MUST NOT DO]
- Do not invent findings. Anything not in the table is out of scope; if you believe a useful check is missing, say so under '## Tooling feedback'.
- Do not change a row's severity. You may argue, in words, that a finding matters more or less for this operator.
- Do not recommend or imply any action you performed. All remediation is for a human, later, deliberately.

[BUDGET] Conclude within ~{{ soft_step_budget }} tool calls; most weeks none are needed. A short report that trusts the table beats a long one that repeats it.

[OUTPUT] Your final message MUST begin with the line '## Summary' — no preamble, no greeting. Sections, in this order:
'## Summary' — 3-5 sentences: what changed this week and the single most important item.
'## Priorities' — numbered, at most 5: finding · why it matters in this setup · the first step.
'## What changed' — one line each for new, resolved and carried items, or "nothing changed".
'## Recommended remediation' — numbered, concrete, safe, for a human to perform.
'## Confidence' — high / medium / low, with one sentence on why.
OPTIONAL last section '## Tooling feedback': 0-3 lines, each 'tool_name: one concrete suggestion' (exact names: prometheus_query, discover_metrics, proxmox_api) or 'security_audit: <a check that should exist>'. Omit the section when you have nothing concrete. All timestamps in UTC (Z).
```

- [ ] Create `config/prompts/briefs/security_audit.md.j2`:

```
Weekly configuration-hygiene review of the operator's own homelab, generated {{ generated_at }}. Every row below was produced by deterministic code; statuses are final. Explain, prioritise and recommend — do not re-detect.

WEEK-OVER-WEEK: {{ n_new }} new · {{ n_persisting }} persisting · {{ n_resolved }} resolved · {{ n_carried }} carried (source unavailable this run)

FINDINGS (status fail, severity critical/warning):
{{ table }}

NOTES (informational facts — not findings):
{{ notes }}

COVERAGE GAPS (checks that could not run — say they were not verified; do not guess):
{{ coverage }}

RESOLVED since the previous audit:
{{ resolved }}

EVIDENCE EXCERPTS (clipped):
{{ excerpts }}

Write the report now, starting with '## Summary'.
```

- [ ] Create `src/heim/pipelines/security_audit.py` with the constants and the two builders (the pipeline function is added in Task 11):

```python
"""The weekly read-only security audit pipeline.

Flow (run_security_audit, Task 11): catalogue → collect evidence (I/O) →
evaluate (pure) → drop suppressed → diff against the previous audit → persist
run + findings → deterministic report → ONE bounded model pass that explains
and prioritises (never detects) → deliver (email, Telegram digest, HA sensor,
Loki). A declined/failed model pass costs the report its '## AI assessment'
appendix and nothing else.

This module holds the prompt builders as well, so the prompt-hygiene test
can render exactly what the model will see.
"""
from __future__ import annotations

from jinja2 import Environment

from heim.config import expand_env
from heim.runtime import Runtime
from heim.security.diff import AuditDiff
from heim.security.report import brief_sections
from heim.security.types import CheckResult

AUDIT_KIND = "security_audit"          # runs.kind · findings.source · investigations.trigger
AGENT_NAME = "security_auditor"        # config/agents/security_auditor.yaml · investigations.agent_name
AUDIT_HOST = "all"                     # investigations.host for the run-level row

#: Words that make a defensive review read like an offensive one to a safety
#: classifier. tests/test_security_prompt.py fails if a rendered prompt
#: contains any of them; keep the templates in the vocabulary of hygiene.
ATTACK_TERMS = ("exploit", "attack", "brute", "penetration", "pentest", "payload", "intrusion", "crack", "bypass")


def build_audit_system_prompt(rt: Runtime, jenv: Environment) -> str:
    cfg = rt.config
    agent = cfg.agents[AGENT_NAME]
    facts = "\n".join(h.facts.strip() for h in sorted(cfg.hosts.values(), key=lambda h: h.name) if h.facts.strip())
    return expand_env(
        jenv.get_template(agent.prompt).render(now=rt.now_iso(), facts=facts,
                                               soft_step_budget=agent.soft_step_budget),
        source=agent.prompt,
    )


def build_audit_brief(rt: Runtime, jenv: Environment, results: list[CheckResult], diff: AuditDiff, *,
                      generated_at: str) -> str:
    sections = brief_sections(results, diff)
    return expand_env(
        jenv.get_template("briefs/security_audit.md.j2").render(
            generated_at=generated_at, n_new=len(diff.new), n_persisting=len(diff.persisting),
            n_resolved=len(diff.resolved), n_carried=len(diff.carried), **sections),
        source="briefs/security_audit.md.j2",
    )
```

- [ ] Run `.venv/bin/pytest tests/test_security_prompt.py -q` — expect 4 passed. Full suite: 893 passed. If `test_prompts_contain_no_attack_vocabulary` fails, fix the *template wording*, never the term list.
- [ ] Commit: `git add config/agents/security_auditor.yaml config/prompts/security_auditor.md.j2 config/prompts/briefs/security_audit.md.j2 src/heim/pipelines/security_audit.py tests/test_security_prompt.py && git commit -m "security: security_auditor agent (Sonnet 5, 3 API tools, cap 6), prompts, and prompt-hygiene test"`

### Task 11: The pipeline — collect, evaluate, diff, persist, assess, deliver

**Files**
- Modify `src/heim/pipelines/security_audit.py` (created in Task 10): extend the import block and append `run_security_audit`, `_assessment`, `_deliver` after `build_audit_brief`.
- Create `tests/test_security_pipeline.py`.

**Interfaces**
- Produces `async run_security_audit(rt: Runtime, *, llm: bool = True) -> dict` returning `{"run_id", "investigation_id", "checks", "findings", "new", "persisting", "resolved", "carried", "unavailable", "assessment": "complete"|"incomplete"|"failed"|"skipped", "cost", "subject", "duration_s"}`; raises `RuntimeError` when every source was unreachable.
- Produces `async _assessment(rt, *, run_id, results, diff, finding_rows, generated_at) -> tuple[int, str | None, AgentResult | None, str, str]` → `(inv_id, assessment_md, result, status, reason)`.
- Consumes `load_catalogue`, `collect_evidence`, `evaluate`, `diff_findings`, `finding_rows`, `render_audit_report`, `salvage`, `run_agent`, `load_tools`, `ToolContext`, `cost_of`, `security_audit_email`, `telegram_digest`, `ha_attributes`, `finding_events`, `overall_of`, and from `pipelines/investigate.py`: `_step_recorder`, `_action`, `_transcript_json`, `record_tool_feedback`, `findings_text`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_pipeline.py
"""End-to-end pipeline with stubbed collectors and a stubbed model."""
import json
import shutil
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult, AgentStep
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines import security_audit as pipe
from heim.runtime import Runtime
from heim.security.types import Evidence, EvidenceBundle

ROOT = Path(__file__).resolve().parent.parent
USERS = [{"userid": "root@pam", "enable": 1}, {"userid": "auditor@pve", "enable": 1}]
GOOD = ("## Summary\n\nOne new critical item.\n\n## Priorities\n\n1. HA core\n\n## What changed\n\nnew: 1\n\n"
        "## Recommended remediation\n\n1. Update HA core.\n\n## Confidence\n\nhigh — the table is unambiguous.\n\n"
        "## Tooling feedback\n\nsecurity_audit: check PVE token expiry\n")


@pytest.fixture()
def rt(tmp_path, monkeypatch):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def _bundle(*, tfa_empty=True, ha_public=True):
    items = [
        Evidence("pve.access_users", "ok", body=USERS),
        Evidence("pve.access_tfa", "empty" if tfa_empty else "ok", body=[] if tfa_empty else [{"userid": "root@pam", "entries": [{"type": "totp"}]}]),
        Evidence("ha.config", "ok", body={"safe_mode": False, "recovery_mode": False,
                                          "external_url": "https://x.example-dyndns.net:8123" if ha_public else "http://10.0.0.3:8123"}),
        Evidence("ha.states", "ok", body=[{"entity_id": "update.home_assistant_core_update", "state": "on",
                                           "attributes": {"title": "Home Assistant Core", "installed_version": "2026.9.1", "latest_version": "2026.9.3"}}]),
        Evidence("prom.reboot_required", "ok", body=[{"metric": {"instance": "10.0.0.10:9100"}, "value": [1, "0"]}]),
    ]
    return EvidenceBundle(items={e.key: e for e in items}, collected_at="t")


def _stub_collect(monkeypatch, bundle):
    async def fake(cfg, cat, *, now_iso):
        return bundle
    monkeypatch.setattr(pipe, "collect_evidence", fake)


def _stub_agent(monkeypatch, *, output=GOOD, stop_reason="end_turn", raises=None, steps=1):
    seen = {}

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None, collect_transcript=False):
        seen.update(cfg=cfg, system=system, user_prompt=user_prompt, tools=[t.name for t in tools])
        if raises is not None:
            raise raises
        if on_step is not None:
            for i in range(steps):
                on_step(i + 1, "prometheus_query", {"promql": "up"}, '{"ok": true}', 12.0, 100, 20)
        return AgentResult(output, [AgentStep("prometheus_query", {}, "")] * steps, 5000, 900, stop_reason)
    monkeypatch.setattr(pipe, "run_agent", fake_run_agent)
    return seen


async def test_full_run_persists_reports_and_delivers(rt, monkeypatch, tmp_path):
    _stub_collect(monkeypatch, _bundle())
    seen = _stub_agent(monkeypatch)
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "complete" and res["new"] == 3 and res["persisting"] == 0
    # store: run + findings + investigation, no double-counted tokens
    run = rt.store.runs(limit=1, kind="security_audit")[0]
    assert run["id"] == res["run_id"] and run["overall"] == "critical" and run["input_tokens"] == 0
    rows = rt.store.findings_for_run(run["id"])
    assert {r["fingerprint"] for r in rows} == {"homelab|pve.tfa_missing|root@pam", "home-assistant|ha.core_update_exposed|home-assistant",
                                             "home-assistant|ha.pending_updates_sensitive|update.home_assistant_core_update"}
    assert all(r["source"] == "security_audit" and r["trend"] == "new" for r in rows)
    inv = rt.store.investigation(res["investigation_id"])
    assert inv["agent_name"] == "security_auditor" and inv["trigger"] == "security_audit" and inv["host"] == "all"
    assert inv["status"] == "complete" and inv["input_tokens"] == 5000 and inv["cost"] > 0 and inv["n_steps"] == 1
    assert inv["report_md"].startswith("## Summary") and "## AI assessment" in inv["report_md"] and "### Priorities" in inv["report_md"]
    assert len(rt.store.steps(inv["id"])) == 1
    assert rt.store.tool_feedback(inv["id"])[0]["tool"] == "security_audit"
    # the model saw the diff and the table, and held no SSH tool
    assert "3 new" in seen["user_prompt"] and "0 resolved" in seen["user_prompt"]
    assert "ha.core_update_exposed" in seen["user_prompt"] and "ssh_diagnostic" not in seen["tools"]
    # delivery: dry-run email written, subject reflects counts
    assert res["subject"].startswith("🛡️ Weekly Security Audit — 3 findings, 3 new, 0 resolved")
    assert list((tmp_path / "out").glob("*.html"))
    assert res["unavailable"] > 30            # everything not in the stub bundle is a coverage gap, not a pass


async def test_second_run_diffs_and_resolves(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch)
    await pipe.run_security_audit(rt)
    _stub_collect(monkeypatch, _bundle(tfa_empty=False))            # root@pam now has TFA
    res = await pipe.run_security_audit(rt)
    assert res["resolved"] == 1 and res["persisting"] == 2 and res["new"] == 0
    rows = rt.store.findings_for_run(res["run_id"])
    assert [r["trend"] for r in rows] == ["persisting", "persisting"]
    assert rt.store.finding_run_count("home-assistant|ha.core_update_exposed|home-assistant", "security_audit") == 2


async def test_unavailable_check_carries_instead_of_resolving(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch)
    await pipe.run_security_audit(rt)
    b = _bundle()
    del b.items["pve.access_tfa"]                                    # source vanished this week
    _stub_collect(monkeypatch, b)
    res = await pipe.run_security_audit(rt)
    assert res["resolved"] == 0 and res["carried"] == 1
    carried = [r for r in rt.store.findings_for_run(res["run_id"]) if r["trend"] == "carried"]
    assert carried and carried[0]["fingerprint"] == "homelab|pve.tfa_missing|root@pam"


async def test_suppressed_fingerprint_is_dropped_everywhere(rt, monkeypatch):
    rt.store.suppress("homelab|pve.tfa_missing|root@pam", until="", reason="LAN only, accepted")
    _stub_collect(monkeypatch, _bundle())
    seen = _stub_agent(monkeypatch)
    res = await pipe.run_security_audit(rt)
    assert res["findings"] == 2
    # Suppression is fingerprint-scoped (§0.5): it hides the one suppressed
    # FINDING's own line from the model's brief...
    assert "root@pam can log in to the Proxmox UI/API with a password alone" not in seen["user_prompt"]
    # ...but the informational note row for a different account under the
    # same check id is a fact, not a finding, and legitimately stays visible.
    assert "auditor@pve has no second factor" in seen["user_prompt"]
    assert all(r["metric"] != "pve.tfa_missing" for r in rt.store.findings_for_run(res["run_id"]))


async def test_refusal_degrades_the_appendix_only(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch, output="", stop_reason="refusal", steps=0)
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "incomplete"
    inv = rt.store.investigation(res["investigation_id"])
    assert inv["status"] == "incomplete" and "declined" in inv["incomplete_reason"]
    assert inv["report_md"].startswith("## Summary") and "root@pam" in inv["report_md"]
    assert "_Unavailable —" in inv["report_md"] and "declined" in inv["report_md"]
    assert res["subject"].endswith("(AI assessment unavailable)")
    assert len(rt.store.findings_for_run(res["run_id"])) == 3         # findings persisted regardless


async def test_model_exception_marks_investigation_failed_but_delivers(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch, raises=RuntimeError("api down"))
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "failed"
    assert rt.store.investigation(res["investigation_id"])["status"] == "failed"
    assert res["subject"].startswith("🛡️")


async def test_no_llm_skips_the_model_entirely(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    called = {"n": 0}

    async def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("model must not be called")
    monkeypatch.setattr(pipe, "run_agent", boom)
    res = await pipe.run_security_audit(rt, llm=False)
    assert res["assessment"] == "skipped" and res["investigation_id"] == 0 and called["n"] == 0
    assert rt.store.runs(limit=1, kind="security_audit")[0]["model_used"] == ""
    assert not rt.store.investigations()


async def test_everything_unreachable_raises(rt, monkeypatch):
    _stub_collect(monkeypatch, EvidenceBundle(items={}, collected_at="t"))
    _stub_agent(monkeypatch)
    with pytest.raises(RuntimeError, match="unreachable"):
        await pipe.run_security_audit(rt)
    assert not rt.store.runs(limit=1, kind="security_audit")
```

- [ ] Run `.venv/bin/pytest tests/test_security_pipeline.py -q` — expect `AttributeError: module 'heim.pipelines.security_audit' has no attribute 'run_security_audit'`.
- [ ] Extend `src/heim/pipelines/security_audit.py`. Replace the import block with:

```python
import json
import logging
import time
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from heim.agent.runner import AgentResult, run_agent
from heim.config import expand_env
from heim.costing import cost_of
from heim.pipelines.investigate import (
    _action, _step_recorder, _transcript_json, findings_text, record_tool_feedback,
)
from heim.pipelines.security_sources import collect_evidence
from heim.reports.render import salvage, security_audit_email
from heim.runtime import Runtime
from heim.security.catalogue import load_catalogue
from heim.security.diff import AuditDiff, diff_findings, finding_rows
from heim.security.evaluate import EvalContext, evaluate
from heim.security.report import (
    brief_sections, coverage_gaps, demote_headings, finding_events, ha_attributes, overall_of,
    render_audit_report, telegram_digest,
)
from heim.security.types import CheckResult
from heim.tools.base import ToolContext, load_tools

log = logging.getLogger(__name__)
```

  and append after `build_audit_brief`:

```python
async def run_security_audit(rt: Runtime, *, llm: bool = True) -> dict:
    """One weekly audit. Raises only when NO source answered; every other
    failure degrades one section of the report and is written into it."""
    cfg = rt.config
    t0 = time.time()
    generated_at = rt.now_iso()
    cat = load_catalogue(cfg.security_checks_path)

    # 1. collect (I/O, bounded) → 2. evaluate (pure)
    evidence = await collect_evidence(cfg, cat, now_iso=generated_at)
    ctx = EvalContext(now=rt.now(), instance_host_map=dict(cfg.settings.instance_host_map),
                      hosts=tuple(cfg.hosts), pve_node=cat.pve_node, ssh_host=cat.ssh_host, ha_host=cat.ha_host)
    if not any(e.usable for e in evidence.items.values()):
        raise RuntimeError("every source was unreachable — no audit possible this run")
    results = evaluate(cat, evidence, ctx)

    # 3. suppressions + week-over-week diff
    suppressed = rt.store.active_suppressions(generated_at)
    findings = [r for r in results if r.is_finding and r.fingerprint not in suppressed]
    unavailable_ids = {r.check_id for r in results if r.status == "unavailable"}
    prev_runs = rt.store.runs(limit=1, kind=AUDIT_KIND)
    previous = rt.store.findings_for_run(int(prev_runs[0]["id"])) if prev_runs else []
    previous = [p for p in previous if str(p.get("fingerprint") or "") not in suppressed]
    diff = diff_findings(findings, previous, unavailable_ids)
    rows = finding_rows(diff)
    weeks = {r["fingerprint"]: rt.store.finding_run_count(r["fingerprint"], AUDIT_KIND) + 1 for r in rows}

    # 4. deterministic report → 5. persist (tokens/cost live on the investigation row only)
    report_md = render_audit_report(results, diff, generated_at=generated_at, weeks=weeks)
    gaps = coverage_gaps(results)
    run_id = rt.store.insert_run(
        kind=AUDIT_KIND, run_at=generated_at, overall=overall_of(rows),
        model_used=cfg.agents[AGENT_NAME].model if (llm and AGENT_NAME in cfg.agents) else "",
        duration_s=round(time.time() - t0, 3),
        counts_json=json.dumps({"checks": len(results), "findings": len(rows), "new": len(diff.new),
                                "persisting": len(diff.persisting), "resolved": len(diff.resolved),
                                "carried": len(diff.carried), "unavailable": len(gaps),
                                "critical": sum(1 for r in rows if r["severity"] == "critical"),
                                "warning": sum(1 for r in rows if r["severity"] == "warning")}),
        headline=f"{len(rows)} findings · {len(diff.new)} new · {len(diff.resolved)} resolved",
        summary=report_md.split("\n\n", 2)[1] if "\n\n" in report_md else "",
    )
    rt.store.insert_findings(run_id, generated_at, AUDIT_KIND, rows, [r["fingerprint"] for r in rows])

    # 6. the model pass — explains, never detects; optional and degradable
    inv_id, assessment_md, agent_result, status, reason = 0, None, None, "skipped", ""
    if llm and AGENT_NAME in cfg.agents:
        inv_id, assessment_md, agent_result, status, reason = await _assessment(
            rt, run_id=run_id, results=results, diff=diff, rows=rows, generated_at=generated_at)
    if assessment_md:
        final_md = f"{report_md}\n\n## AI assessment\n\n{demote_headings(assessment_md)}"
    else:
        why = {"skipped": "skipped (--no-llm)", "failed": f"failed — {reason}"}.get(status, reason or "no assessment")
        final_md = f"{report_md}\n\n## AI assessment\n\n_Unavailable — {why}._"
    if inv_id:
        rt.store.update_investigation(inv_id, report_md=final_md)

    # 7. deliver
    subject = await _deliver(rt, run_id=run_id, final_md=final_md, diff=diff, results=results, rows=rows, inv_id=inv_id,
                             agent_result=agent_result, status=status, reason=reason, generated_at=generated_at)
    cost = cost_of(cfg.agents[AGENT_NAME].model, agent_result.input_tokens, agent_result.output_tokens,
                   cfg.settings.model_prices) if agent_result is not None else 0.0
    return {
        "run_id": run_id, "investigation_id": inv_id, "checks": len(results), "findings": len(rows),
        "new": len(diff.new), "persisting": len(diff.persisting), "resolved": len(diff.resolved),
        "carried": len(diff.carried), "unavailable": len(gaps), "assessment": status,
        "cost": float(cost or 0.0), "subject": subject, "duration_s": round(time.time() - t0, 1),
    }


async def _assessment(rt: Runtime, *, run_id: int, results: list[CheckResult], diff: AuditDiff,
                      rows: list[dict], generated_at: str) -> tuple[int, str | None, AgentResult | None, str, str]:
    cfg = rt.config
    agent_cfg = cfg.agents[AGENT_NAME]
    jenv = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    brief = build_audit_brief(rt, jenv, results, diff, generated_at=generated_at)
    ftext = findings_text(rows)
    inv_id = rt.store.create_investigation(
        fingerprint=f"{AUDIT_HOST}|{AUDIT_KIND}|run-{run_id}", host=AUDIT_HOST, host_role="audit",
        agent_name=AGENT_NAME, model=agent_cfg.model, trigger=AUDIT_KIND, status="running",
        started_at=generated_at, brief_md=brief, findings_json=json.dumps(rows, ensure_ascii=False, default=str),
    )
    await rt.emit_loki([_action(AUDIT_HOST, "audit_started", f"run-{run_id}", "Weekly security audit assessment started", rt.now_iso())])
    try:
        async with rt.investigation_slot():
            system = build_audit_system_prompt(rt, jenv)
            ctx = ToolContext(config=cfg, tag="security-audit", feed=rt.feed, audit=rt.audit)
            tools = load_tools(agent_cfg.tools, cfg, ctx)
            result = await run_agent(agent_cfg, system=system, user_prompt=brief, tools=tools,
                                     on_step=_step_recorder(rt, inv_id),
                                     collect_transcript=cfg.settings.store_transcripts)
    except Exception as exc:
        log.exception("security audit assessment failed")
        reason = f"{type(exc).__name__}: {exc}"
        rt.store.update_investigation(inv_id, status="failed", finished_at=rt.now_iso(), incomplete_reason=reason)
        return inv_id, None, None, "failed", reason
    report = salvage(result.output_text, ftext, stop_reason=result.stop_reason)
    record_tool_feedback(rt, inv_id, report.report_md if not report.incomplete else result.output_text)
    cost = cost_of(agent_cfg.model, result.input_tokens, result.output_tokens, cfg.settings.model_prices)
    rt.store.update_investigation(
        inv_id, status="incomplete" if report.incomplete else "complete",
        incomplete_reason=(report.reason or "") if report.incomplete else "",
        report_md=report.report_md, input_tokens=result.input_tokens, output_tokens=result.output_tokens,
        n_steps=len(result.steps), cost=float(cost or 0.0),
        transcript_json=_transcript_json(result.transcript), finished_at=rt.now_iso(),
    )
    if report.incomplete:
        return inv_id, None, result, "incomplete", report.reason or "no '## Summary' in the model output"
    return inv_id, report.report_md, result, "complete", ""


async def _deliver(rt: Runtime, *, run_id: int, final_md: str, diff: AuditDiff, results: list[CheckResult], rows: list[dict],
                   inv_id: int, agent_result: AgentResult | None, status: str, reason: str, generated_at: str) -> str:
    incomplete = status in ("incomplete", "failed")
    n_steps = len(agent_result.steps) if agent_result else 0
    tok_in = agent_result.input_tokens if agent_result else 0
    tok_out = agent_result.output_tokens if agent_result else 0
    subject, html = security_audit_email(report_md=final_md, incomplete=incomplete, generated_at=generated_at,
                                         n_findings=len(rows), n_new=len(diff.new), n_resolved=len(diff.resolved),
                                         n_steps=n_steps, input_tokens=tok_in, output_tokens=tok_out)
    await rt.send_email(subject, html)
    await rt.notify(telegram_digest(diff, results, generated_at=generated_at, assessment=status, reason=reason))
    new_crit = [r for r in diff.new if r.severity == "critical"]
    if new_crit:
        await rt.notify("🔴 New critical security finding(s) this week:\n" +
                        "\n".join(f"• {r.host} · {r.check_id} · {r.summary[:160]}" for r in new_crit[:5]))
    state, attrs = ha_attributes(diff, results, generated_at=generated_at, report_md=final_md)
    await rt.push_ha("security_audit", state, attrs)
    events = finding_events(rows)
    if inv_id:
        events.append({"event": "investigation", "labels": {"host": AUDIT_HOST, "status": "incomplete" if incomplete else "complete"},
                       "fields": {"fingerprint": f"{AUDIT_HOST}|{AUDIT_KIND}|run-{run_id}", "rootCause": "", "confidence": "",
                                  "impact": f"{len(rows)} findings, {len(diff.new)} new", "remediation": [], "recommendedActions": [],
                                  "tokenEstimate": tok_in + tok_out, "nSteps": n_steps, "detectedAt": "", "resolvedAt": ""}})
    events.append(_action(AUDIT_HOST, "report", f"run-{run_id}", "Weekly security audit report generated", rt.now_iso()))
    await rt.emit_loki(events)
    return subject
```

- [ ] Run `.venv/bin/pytest tests/test_security_pipeline.py -q` — expect 8 passed. Full suite: 901 passed.
- [ ] Commit: `git add src/heim/pipelines/security_audit.py tests/test_security_pipeline.py && git commit -m "security: weekly audit pipeline — collect, evaluate, diff, persist, degradable model assessment, delivery"`

### Task 12: Daemon job and the `heim security-audit` CLI verb

**Files**
- Modify `src/heim/daemon.py:29-30` (imports), `:42` (after `BACKUP_MINUTE`), `:58` (after `_poll_job`), `:199-201` (after the backup `add_job`), `:222-229` (startup log).
- Modify `src/heim/cli.py:16-17` (docstring), `_cmd_check` (after the `queries:` line), `:480` (after `_cmd_daemon`), `:547` (parser), `:559` (handler map).
- Create `tests/test_security_daemon_cli.py`.

**Interfaces**
- Produces `heim.daemon.weekly_trigger(spec: str, tz: str) -> CronTrigger`, `async heim.daemon._security_audit_job(rt: Runtime) -> None`.
- Produces `async heim.cli._cmd_security_audit(args) -> int` for `heim security-audit [--dry-run] [--no-llm]`.
- Consumes `parse_weekly`, `run_security_audit`, `build_runtime`, `load_catalogue`.

**Steps**
- [ ] Write the failing tests:

```python
# tests/test_security_daemon_cli.py
import shutil
from argparse import Namespace
from pathlib import Path

import pytest

from heim import cli, daemon
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def rt(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = cfg.settings.email = cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def test_weekly_trigger_fields():
    trig = daemon.weekly_trigger("mon 06:00", "Europe/Berlin")
    fields = {f.name: str(f) for f in trig.fields}
    assert fields["day_of_week"] == "mon" and fields["hour"] == "6" and fields["minute"] == "0"
    assert str(trig.timezone) == "Europe/Berlin"


async def test_security_audit_job_notifies_on_failure_and_never_raises(rt, monkeypatch):
    async def boom(rt_, **kw):
        raise RuntimeError("every source was unreachable")
    monkeypatch.setattr(daemon, "run_security_audit", boom)
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    await daemon._security_audit_job(rt)                      # must not raise
    assert sent and sent[0].startswith("🔴 HEIM weekly security audit FAILED") and "unreachable" in sent[0]


async def test_security_audit_job_success_is_quiet(rt, monkeypatch):
    async def fine(rt_, **kw):
        return {"findings": 0}
    monkeypatch.setattr(daemon, "run_security_audit", fine)
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    await daemon._security_audit_job(rt)
    assert sent == []                                          # the pipeline delivers its own digest


def test_cli_parser_has_the_verb():
    p = cli._build_parser()
    a = p.parse_args(["security-audit", "--dry-run", "--no-llm"])
    assert a.cmd == "security-audit" and a.dry_run and a.no_llm
    assert not p.parse_args(["security-audit"]).no_llm


async def test_cli_handler_runs_pipeline_with_flags(rt, monkeypatch, capsys):
    calls = {}

    async def fake_run(rt_, *, llm=True):
        calls["llm"] = llm
        calls["dry_run"] = rt_.dry_run
        return {"run_id": 1, "findings": 2, "assessment": "skipped"}
    monkeypatch.setattr("heim.pipelines.security_audit.run_security_audit", fake_run)
    monkeypatch.setattr("heim.runtime.build_runtime", lambda dry_run=False: rt)
    rc = await cli._cmd_security_audit(Namespace(dry_run=True, no_llm=True))
    assert rc == 0 and calls == {"llm": False, "dry_run": True}
    assert '"findings": 2' in capsys.readouterr().out
```

- [ ] Run `.venv/bin/pytest tests/test_security_daemon_cli.py -q` — expect `AttributeError: module 'heim.daemon' has no attribute 'weekly_trigger'`.
- [ ] Edit `src/heim/daemon.py`. Imports (after line 30 `from heim.pipelines.poller import run_poll`):

```python
from heim.pipelines.security_audit import run_security_audit
from heim.config import parse_weekly
```

  After `BACKUP_MINUTE = 30` (line 42):

```python
#: Grace for the weekly audit: a restart within the hour still runs it; later
#: than that the week is skipped (the next Monday is soon enough for hygiene).
AUDIT_MISFIRE_GRACE_S = 3600


def weekly_trigger(spec: str, tz: str) -> CronTrigger:
    """``"mon 06:00"`` → the APScheduler cron trigger for that weekly slot."""
    day, hour, minute = parse_weekly(spec)
    return CronTrigger(day_of_week=day, hour=hour, minute=minute, timezone=tz)
```

  After `_poll_job` (line 67):

```python
async def _security_audit_job(rt: Runtime) -> None:
    """Weekly read-only security audit. Same contract as _daily_job: never
    raise into the scheduler; a failure is one Telegram line. Success is
    silent here because the pipeline delivers its own digest."""
    try:
        result = await run_security_audit(rt)
        log.info("security audit complete: %s", result)
    except Exception as exc:
        log.exception("security audit failed")
        await rt.notify(f"🔴 HEIM weekly security audit FAILED: {type(exc).__name__}: {exc}")
```

  In `run_daemon`, after the `nightly-backup` `add_job` (line 201):

```python
    audit_spec = rt.config.settings.schedules.security_audit
    if audit_spec:
        scheduler.add_job(_security_audit_job, weekly_trigger(audit_spec, tz), args=[rt],
                          name="security-audit", misfire_grace_time=AUDIT_MISFIRE_GRACE_S)
```

  In the startup `log.info` (lines 222-229) extend the format with `", security audit %s"` and the args with `audit_spec or "off"`.

- [ ] Edit `src/heim/cli.py`. Docstring: after the `heim dashboard` line (16) add `    heim security-audit [--dry-run]    run the weekly read-only security audit once` and `                        [--no-llm]     (collectors + deterministic report only, no model call)`. In `_cmd_check`, after the `queries:` line:

```python
    from heim.security.catalogue import CatalogueError, load_catalogue
    try:
        cat = load_catalogue(cfg.security_checks_path)
        line(True, f"security checks: {len(cat.checks)} checks over {len(cat.sources)} sources "
                   f"in {cfg.security_checks_path.name}")
    except (CatalogueError, OSError) as exc:
        line(False, "security checks", str(exc))
```

  After `_cmd_daemon` (line 485):

```python
async def _cmd_security_audit(args) -> int:
    from heim.pipelines.security_audit import run_security_audit
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=args.dry_run)
    result = await run_security_audit(rt, llm=not args.no_llm)
    print(json.dumps(result, indent=2, default=str))
    return 0
```

  In `_build_parser`, before `sub.add_parser("daemon", …)`:

```python
    sa = sub.add_parser("security-audit", help="run the weekly read-only security audit once")
    sa.add_argument("--dry-run", action="store_true")
    sa.add_argument("--no-llm", action="store_true",
                    help="collectors + deterministic report only — no model call, zero cost")
```

  In `main()`'s handler dict add `"security-audit": _cmd_security_audit,`.

- [ ] Run `.venv/bin/pytest tests/test_security_daemon_cli.py -q` — expect 5 passed. Full suite: 906 passed.
- [ ] Commit: `git add src/heim/daemon.py src/heim/cli.py tests/test_security_daemon_cli.py && git commit -m "security: weekly daemon job (mon 06:00, never raises) and heim security-audit CLI verb"`

### Task 13: Dashboard trigger filter, docs, and the test-count baseline

**Files**
- Modify `src/heim/dashboard/app.py:1010` (`_TRIGGERS`).
- Modify `AGENTS.md:30` (test count), `:44` (Ops row), `:53` (count), `:468` (before `### Non-goals`: new roadmap item), `:478` (count); `README.md:113` (count); `docs/ARCHITECTURE.md:29-44` (new data-flow block after the Investigation block) and the provenance table (after line 60).
- Create `tests/test_security_dashboard.py`.

**Interfaces**
- `_TRIGGERS = ["daily", "poller", "manual", "security_audit"]` — the `/investigations` trigger filter offers the audit before its first run.

**Steps**
- [ ] Write the failing test:

```python
# tests/test_security_dashboard.py
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    run_id = store.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00", overall="warning")
    rows = [{"host": "homelab", "metric": "pve.tfa_missing", "severity": "warning", "trend": "new",
             "summary": "root@pam can log in with a password alone", "detail": "d", "recommendation": "add TOTP",
             "fingerprint": "homelab|pve.tfa_missing|root@pam"}]
    store.insert_findings(run_id, "2026-09-28T06:00:00", "security_audit", rows, [r["fingerprint"] for r in rows])
    store.create_investigation(fingerprint="all|security_audit|run-1", host="all", host_role="audit",
                               agent_name="security_auditor", model="claude-sonnet-5", trigger="security_audit",
                               status="complete", started_at="2026-09-28T06:00:00", finished_at="2026-09-28T06:04:00",
                               report_md="## Summary\n\nweekly audit\n\n## AI assessment\n\n### Summary\n\nfine",
                               findings_json=json.dumps(rows), brief_md="brief")
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def test_trigger_filter_offers_and_applies_security_audit(client):
    page = client.get("/investigations").text
    assert 'value="security_audit"' in page
    filtered = client.get("/investigations?trigger=security_audit").text
    assert "security_audit" in filtered and "all" in filtered


def test_detail_page_shows_agent_and_findings(client):
    inv_id = 1
    html = client.get(f"/investigations/{inv_id}").text
    assert "security_auditor" in html and "pve.tfa_missing" in html and "weekly audit" in html


def test_findings_page_lists_the_audit_row_with_a_verdict_form(client):
    html = client.get("/findings").text
    assert "pve.tfa_missing" in html and "root@pam" in html and "/actions/verdict" in html
```

- [ ] Run `.venv/bin/pytest tests/test_security_dashboard.py -q` — expect the first test to fail on `value="security_audit"` (the other two should already pass — they prove zero dashboard code is needed beyond the filter).
- [ ] Edit `src/heim/dashboard/app.py:1010` to `_TRIGGERS = ["daily", "poller", "manual", "security_audit"]`.
- [ ] Docs. `AGENTS.md`: in the feature inventory add a row after `| Ops |`:

  `| Security audit | Weekly (Mon 06:00) read-only configuration-hygiene audit: 47 deterministic checks over the Proxmox API (audit-only token), Home Assistant REST, Prometheus and fixed guard-validated SSH lines · stable fingerprints \`host\|check_id\|subject\` · week-over-week new/persisting/resolved/carried · findings reuse the verdict/suppression machinery · one bounded Sonnet 5 pass (3 API tools, no SSH, cap 6) explains and prioritises, never detects · degradable: a refusal costs only the \`## AI assessment\` appendix · \`heim security-audit [--dry-run] [--no-llm]\` |`

  Before `### Non-goals` (line 468) add:

  ```
  ### 5.9 Weekly security audit — ✅ implemented

  `pipelines/security_audit.py` + the pure `security/` package + `config/security/checks.yaml`.
  Detection is deterministic code; the model only explains. Collectors have their own GET-only
  PVE allowlist (`security.catalogue.PVE_AUDIT_ALLOW`) wider than the model's `proxmox_guard`;
  the model's guards are unchanged. Results live in `runs(kind=security_audit)`,
  `findings(source=security_audit)` and `investigations(agent_name=security_auditor)`. See the
  plan's owner-side steps for the checks that need a journal group or an apt collector.
  ```

  Replace `596` at lines 30, 53 and 478 with the number `.venv/bin/pytest -q` reports after this task (expected 909); same for `README.md:113`. In `docs/ARCHITECTURE.md`, after the Investigation data-flow block add:

  ~~~~
  ### Weekly security audit (`heim security-audit`, Monday 06:00 in the daemon)
  ```
  config/security/checks.yaml ─► security.catalogue (validates every read: guard_command, guard_ha_path, PVE_AUDIT_ALLOW)
                             ─► pipelines.security_sources.collect_evidence (GET / PromQL / fixed SSH lines, bounded)
                             ─► security.evaluate (pure; empty-list control rule; ok/fail/note/unavailable)
                             ─► store.active_suppressions · security.diff (new/persisting/resolved/carried)
                             ─► store.insert_run(kind=security_audit) + insert_findings(source=security_audit)
                             ─► security.report.render_audit_report ('## Summary' first, model-free)
                             ─► agent.runner over agents/security_auditor.yaml (prometheus_query, discover_metrics, proxmox_api)
                                → reports.salvage → '## AI assessment' appendix, or a one-line reason
                             ─► email + Telegram digest (+ 🔴 for new criticals) + sensor.pam_security_audit + Loki finding/investigation/action
  ```
  ~~~~

  and add provenance-table rows: `| — (new) Security audit catalogue/evaluators | \`security/*\` | test_security_* |` and `| — (new) Security audit pipeline | \`pipelines/security_audit.py\`, \`pipelines/security_sources.py\` | test_security_pipeline, test_security_sources |`.

- [ ] Run `.venv/bin/pytest -q` — expect 909 passed. Run `.venv/bin/heim check` (dry, read-only) and confirm the `security checks: 47 checks over 47 sources in checks.yaml` line. Then the first real run: `.venv/bin/heim security-audit --dry-run --no-llm` — confirm the report under `out/`, and use its Coverage gaps section to decide owner-side steps 1–2 and to fill `expected_ports`.
- [ ] Commit: `git add src/heim/dashboard/app.py AGENTS.md README.md docs/ARCHITECTURE.md tests/test_security_dashboard.py && git commit -m "security: dashboard trigger filter, docs, and test baseline for the weekly audit"`

---

## Self-review

### Spec coverage

| Design requirement | Where |
|---|---|
| Read-only end to end; no mutating tool; model has no SSH | Task 2 (loader rejects non-reads), Task 9 (GET only), Task 10 (agent tools = 3 APIs), tests `test_ssh_lines_that_fail`, `test_agent_config_…` |
| No new privilege by default; guards unchanged; audit-only PVE allowlist in code | Task 2 `PVE_AUDIT_ALLOW`; no task touches `guards/` |
| No offensive activity / no scanning | Design §6; fetchers only address configured hosts (Task 9) |
| Fingerprint stability `host\|check_id\|subject` | Task 2 `CheckResult.fingerprint`, `clean_subject`; Task 7 diff joins on it |
| Existing false-positive verdicts + suppressions work | Task 11 `active_suppressions` filter + `test_suppressed_fingerprint_is_dropped_everywhere`; Task 13 `/findings` verdict form test |
| Fire-and-forget side channels | Task 11 `_deliver` uses `rt.send_email/notify/push_ha/emit_loki` only |
| `## Summary` contract + `salvage()` refusal/max_tokens handling | Task 8 report test via `salvage`; Task 11 `_assessment` + `test_refusal_degrades_the_appendix_only` |
| Refusal handled visibly | Task 8 digest + email subject; Task 11 investigations row `incomplete` |
| No external CVE lookups | Design decisions; no task adds egress |
| Config is data; `${VAR}` identity; no secrets | Task 2 catalogue YAML, Task 10 agent/prompt YAML, Task 1 settings key |
| Deterministic collectors vs one LLM pass; LLM never detects | Tasks 4–6 evaluators; Task 10 prompt; Task 11 only appends narrative |
| Check catalogue grounded in live dossier with availability | Design §2; Task 2 YAML |
| Data flow | Design §3; Task 11 |
| Schedule decision (Mon 06:00) | Task 1 default, Task 12 trigger |
| Storage decision (reuse tables, no migration) | Tasks 7, 11 |
| Delivery decision (email full, Telegram digest, HA sensor, Loki `finding`) | Tasks 8, 11 |
| Critical → report only + 🔴 line | Task 11 `_deliver` |
| No approval gate | Task 11 never calls `run_investigation`; Design §4 |
| Model/budget/cost | Task 10 YAML; Design §4 estimate |
| `heim` / `monitor-box` handling | Design §1; Task 4 `stopped_vm_onboot` uses `expected_offline_vms` |
| Failure modes: refusal, timeout, host down, 200-with-empty-list | Task 4 `gate_sources`, Task 9 `_bounded`/`classify_http`, Task 7 carried, Task 11 raise-when-nothing-usable, Task 12 job notify |
| Manual/dry-run invocation | Task 12 `heim security-audit --dry-run --no-llm` |
| Dashboard visibility | Task 13 |
| Docs + test count 788 → 909 | Task 13 |

### Placeholders I could not avoid

- **Expected test totals** (801, 834, 843, 856, 863, 871, 875, 881, 889, 893, 901, 906, 909) assume the test counts written here; if a task's parametrised count differs, take the number pytest prints and carry it forward — the docs step uses the final printed number.
- **`today\*` availability** for `/nodes/homelab/journal`, `sshd_config` readability, `update-notifier` presence, journal group membership and `sudo -n -l`: verified by the first `--no-llm` run's Coverage gaps section, by design rather than by assumption.
- **`os_eol` dates** in the catalogue are approximate vendor dates with a `review_by` guard; the owner should confirm them.
- **`expected_ports`** ships with only the five listeners the live dossier proves (22, 9090, 9100, 3100, 8081); the first run is a triage run.
