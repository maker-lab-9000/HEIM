# Tooling feedback → GitHub issues — design

Date: 2026-11-08 · Status: draft for approval

## Why

The investigator and the security auditor already say what would have made their
tools better (`## Tooling feedback`, `## Audit feedback`). Those lines land in the
`tool_feedback` table and on the Tools page, and then sink into history. The
operator wants a **continuous-improvement loop**: an agent notices a gap, the gap
becomes a tracked GitHub issue in the HEIM repo, someone fixes it and closes the
issue, and later runs stop raising it.

## Goals

- HEIM files issues **on its own** — no operator click.
- **One open issue per tool** (plus one for the security audit itself). Every new
  suggestion for that tool becomes a **comment** on its open issue. Never a
  duplicate issue.
- The agents can **look at the open issues** through a new read-only tool,
  `github_issues`, and use them: skip what is already filed, or add to it.
- Closing an issue means "done": the next suggestion for that tool opens a fresh
  issue.

## Non-goals

- Agents never write to GitHub themselves; no mutating tool (AGENTS.md invariant 4).
- No similarity matching between suggestions (grouping is by tool, by decision).
- No automatic closing, labelling beyond the fixed labels, or assignment.
- No issues from replays, dry runs, or CLI one-offs that are not the daemon's
  normal pipelines (see "When it files").

## Anti-goals (would be a failure even if it works)

- An issue thread that fills with "+1"/"already covered" comments.
- A real IP, username, chat id or other `.env` identity value posted to GitHub.
- A GitHub outage or bad token that slows, fails or blocks an investigation.

## Decisions taken with the operator

| Question | Ruling |
|---|---|
| Who decides what becomes an issue | HEIM, automatically |
| Grouping | One open issue per tool; new suggestions are comments |
| Agents and open issues | They query them via a read-only `github_issues` tool, called only when the agent thinks it is worth it (cheaper than injecting into every prompt; accepted cost: it may sometimes repeat something already filed — that repeat becomes one comment, not a new issue) |

## How it works

### 1. Reading — the `github_issues` tool

- New `config/tools/github_issues.yaml` + `src/heim/tools/github_issues.py`,
  listed in both `investigator.yaml` and `security_auditor.yaml`.
- GET-only, **hard-scoped** to one repo (`settings.github.repo`, e.g.
  `${HEIM_GITHUB_REPO}`) and to issues labelled `heim-feedback`. Arguments:
  optional `tool` (filters by the `tool:<name>` label), optional `state`
  (`open` default, or `closed` to see what was already fixed), optional
  `number` to read one issue with its latest comments.
- Output: number, title, state, labels, and the body plus the last 5 comments,
  each clipped; whole result under the tools' usual 8 KB clip.
- Auth: **`HEIM_GITHUB_READ_TOKEN`**, a fine-grained token with *Issues: read*
  on that one repo — read-only by guard (GET + fixed path) **and** by privilege,
  as invariant 4 requires.
- Not configured (no repo or no read token) → the tool is not offered to the
  agent at all, and the prompt line about it is omitted.

### 2. What the agent writes

Prompt change (investigator `[OUTPUT]` block and the auditor's `## Audit
feedback` instructions): before writing feedback, the agent *may* call
`github_issues`. Each `## Tooling feedback` line stays `tool_name: suggestion`.
If a suggestion is already filed, the agent either omits it or writes
`tool_name: covered by #N` — or adds genuinely new detail to it in a normal line.

### 3. Writing — the outbox, drained by the daemon

- Pipelines never call GitHub. After `record_tool_feedback` stores a line, it also
  writes a row to a new **`feedback_outbox`** table: `(id, target,
  investigation_id, body, created_at, posted_at, attempts, error)`.
  `target` is the tool name, or `security_audit` for `## Audit feedback`.
- Lines of the form `covered by #N` (nothing else) are stored as feedback but
  **not** put in the outbox — no "+1" comments.
- Unknown tool names (not in `cfg.tools`) go to target `general`.
- The daemon's poll cycle drains the outbox (a few rows per cycle), using
  **`HEIM_GITHUB_TOKEN`** (fine-grained, *Issues: read & write*, that repo only):
  1. Look up `feedback_issues(target → number, state)`. If there is a stored
     number, GET it; if it is still open, **comment** on it.
  2. If there is none, or it was closed, **open** a new issue titled
     `Tooling feedback: <target>` with labels `heim-feedback`, `tool:<target>`,
     and store its number.
  3. Comment/issue body: the suggestion, then a line naming the source
     (`investigation #123 · <model> · <date>`), no links to the LAN dashboard.
- Failure → `attempts += 1`, `error` kept, retried next cycle; after 10 attempts
  the row stops retrying and shows as failed. Never raises into the poll cycle
  (fire-and-forget side channel, AGENTS.md §2). The dead-man ping is unaffected.
- Not configured (no repo or no write token) → nothing is queued; the feature is
  off, like an empty `deadman_url`.

### 4. Scrubbing before posting

Every body passes a pure `scrub()` before it leaves: IPv4/IPv6 addresses and every
non-empty value of the `.env` identity variables HEIM interpolates (the same set
`${VAR}` resolution uses) are replaced with `‹redacted›`. Tested with real-looking
values; the scrub runs in the poster, so an outbox row written before a `.env`
change is still scrubbed with the current values.

### When it files

| Source | Files? |
|---|---|
| Daemon investigation (any trigger: daily, poller, threshold, uptime, dashboard, queue, retry) | yes |
| Weekly security audit (daemon) | yes |
| `--dry-run` anything | no |
| `heim replay` | no (offline by contract) |
| CLI one-off `heim investigate` / `heim security-audit` without `--dry-run` | yes — it is a real run whose feedback is real |

### 5. Dashboard

- `/tools/<name>`: the feedback panel shows the tool's issue — `#42 · open ·
  7 comments` linked to GitHub — and any outbox rows still waiting or failed
  (lamp + word, per design.md).
- `/tools` list: a small `Issue #42` next to tools that have one.
- No new write actions on the dashboard.

## Constraints

- AGENTS.md invariant 4 (read-only agent), §2 fire-and-forget channels, no
  secrets or identity in the tree; repo and both tokens come from `.env`.
- `design.md` lamps-and-words, CSS cap 36,864 bytes.
- Golden modules untouched.
- `settings.yaml` (both copies) document `github.repo` and the two token vars,
  commented, off by default.

## Left to the builder

- HTTP client details (httpx, as the other tools), retry spacing, rows per drain.
- Exact prompt wording, within the rules above.
- Store migrations follow the existing `_ADDED_COLUMNS` / `CREATE IF NOT EXISTS`
  pattern; prune posted outbox rows with the other history.

## Calls I made (operator to check)

- Two tokens (read for the agent's tool, write for the poster) rather than one.
- An outbox drained by the daemon rather than posting inline from the pipeline.
- The security audit gets its own issue (`security_audit`), and unknown tool names
  go to `general`.
- `covered by #N` lines are not posted.
- Scrubbing of IPs and `.env` identity values before anything leaves.
