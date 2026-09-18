# Dashboard Leftovers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close out the HEIM dashboard's deferred items: list pagination, the Recommendations page, light mode, and per-investigation model choice.

**Architecture:** All four are dashboard-layer changes on the existing FastAPI + Jinja + htmx app (`src/heim/dashboard/`), plus one new SQLite action table for recommendation states. No pipeline/daemon changes. Pure logic gets unit tests; routes get TestClient tests.

**Tech Stack:** Python 3.11+, FastAPI, Jinja2, htmx (vendored), sqlite3, pytest.

**Spec:** `docs/design/dashboard-ui.md` §8 (pagination), §9 (recommendations), §10 (light mode), §5.1 (model choice). §1–4 define the design system every task must match.

## Global Constraints

- Run everything with the repo venv: `.venv/bin/pytest -q` — the FULL suite must stay green after every task (baseline when this plan was written: 557 + whatever the replay slice added; take the number from the first run).
- The dashboard writes ONLY action tables. This plan adds exactly one: `recommendation_states`. Never write pipeline tables (incidents/findings/runs/investigations/steps).
- Buttons are the existing quiet `.btn` style: mono-caps, `--line` border, ember hover. Copy is sentence case, plain verbs (see spec §5 for the button language).
- Every page works without JS; htmx is enhancement only.
- CSS lives in `src/heim/dashboard/static/heim.css`; a test guards its byte size — if you exceed the current cap, raise the cap in that test by the minimum needed with a one-line comment (current cap and file size: read them from `tests/` before assuming).
- Fingerprints contain `|` and `/` — they travel in form fields / query params via proper URL encoding, never in URL path segments.
- Meaning is never color-alone: pills and badges always carry icon+label or dot+name.
- New store methods follow the existing style in `src/heim/incidents/store.py` (sync sqlite3, `_ADDED_COLUMNS`/`_SCHEMA` migration patterns, column allowlists on `**fields` writers).

---

### Task 1: "Load 50 more" pagination on investigations, incidents, findings

**Files:**
- Modify: `src/heim/dashboard/app.py` (the three list routes + `/investigations/rows` partial)
- Modify: `src/heim/dashboard/templates/investigations.html`, `incidents.html`, `findings.html`, `partials/_inv_rows.html`
- Modify: `src/heim/incidents/store.py` (add `offset` support to `investigations()`, `all_rows()`, and the findings/runs listing the findings page uses — inspect their current signatures first)
- Modify: `src/heim/dashboard/static/heim.css` (`.loadmore` row)
- Test: `tests/test_pagination.py` (new)

**Interfaces:**
- Consumes: `IncidentStore.investigations(limit, status)`, `all_rows(limit)`, the findings-page grouping helper in `app.py`.
- Produces: the same store methods with `offset: int = 0` keyword; each list route accepts `?offset=N` (multiples of 50) and template context gains `next_offset: int | None` (None = exhausted).

- [ ] **Step 1: Write failing store tests for offset**

```python
# tests/test_pagination.py
import pytest
from heim.incidents.store import IncidentStore

@pytest.fixture()
def store(tmp_path):
    s = IncidentStore(tmp_path / "p.sqlite3")
    yield s
    s.close()

def test_investigations_offset(store):
    for i in range(7):
        store.create_investigation(fingerprint=f"f{i}", host="h", trigger="manual",
                                   status="complete", started_at=f"2026-09-1{i}T00:00:00")
    first = store.investigations(limit=5)
    rest = store.investigations(limit=5, offset=5)
    assert len(first) == 5 and len(rest) == 2
    assert first[0]["id"] != rest[0]["id"]
    assert {r["id"] for r in first}.isdisjoint({r["id"] for r in rest})

def test_incidents_offset(store):
    store.upsert([{"fingerprint": f"fp{i}", "host": "h", "metric": "m", "severity": "warning",
                   "status": "open", "firstSeen": f"2026-09-0{i+1}", "lastSeen": f"2026-09-0{i+1}",
                   "resolvedAt": "", "timesSeen": 1, "missedRuns": 0, "description": "d",
                   "investigated": False} for i in range(6)])
    assert len(store.all_rows(limit=4)) == 4
    assert len(store.all_rows(limit=4, offset=4)) == 2
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/test_pagination.py -q`
Expected: FAIL with `TypeError: ... unexpected keyword argument 'offset'`

- [ ] **Step 3: Add `offset` to the store readers**

In `src/heim/incidents/store.py`, add `offset: int = 0` to `investigations()` and `all_rows()` (and to the findings/runs list method the findings page paginates over — match its existing name), appending `LIMIT ? OFFSET ?` with both values bound. Example shape:

```python
def all_rows(self, limit: int = 200, offset: int = 0) -> list[dict]:
    cur = self._db.execute(
        "SELECT * FROM incidents ORDER BY lastSeen DESC LIMIT ? OFFSET ?",
        (limit, offset))
    return [self._to_dict(r) for r in cur.fetchall()]
```

- [ ] **Step 4: Run store tests to verify pass, commit**

Run: `.venv/bin/pytest tests/test_pagination.py -q` → PASS

```bash
git add src/heim/incidents/store.py tests/test_pagination.py
git commit -m "store: offset support on list readers for pagination"
```

- [ ] **Step 5: Write failing route tests**

Append to `tests/test_pagination.py` (copy the app/client fixture pattern from `tests/test_dashboard.py` — config from settings.example + DUMMY_ENV):

```python
def test_investigations_page_paginates(client_with_60_investigations):
    c = client_with_60_investigations
    html = c.get("/investigations").text
    assert html.count('class="inv-row"') <= 50 or "LOAD 50 MORE" in html
    assert 'href="/investigations?offset=50' in html.replace("&amp;", "&")
    page2 = c.get("/investigations?offset=50").text
    assert "LOAD 50 MORE" not in page2          # exhausted
    # filters survive pagination
    filtered = c.get("/investigations?host=h&offset=0").text
    assert "offset=50" not in filtered or "host=h" in filtered
```

Build the `client_with_60_investigations` fixture by inserting 60 rows like Step 1. Add equivalent assertions for `/incidents` and `/findings` (findings: paginate by runs/groups — assert the button appears with >50 findings across runs and disappears on the last page).

- [ ] **Step 6: Run to verify failure** → FAIL (no LOAD 50 MORE anywhere)

- [ ] **Step 7: Implement routes + templates**

In each list route: parse `offset = max(0, int(request.query_params.get("offset", 0)))`, fetch `limit=50, offset=offset`, fetch one extra row (limit=51) OR do a cheap count to decide `next_offset = offset + 50` when more exist, else `None`. Pass `next_offset` and the current filter params into the template. Template addition (same pattern in all three, filters preserved via a query-string helper or explicit params):

```html
{%- if next_offset %}
<p class="loadmore">
  <a class="btn" href="?{{ qs_with(offset=next_offset) }}"
     hx-get="?{{ qs_with(offset=next_offset) }}" hx-select=".rows-and-more"
     hx-target="closest .rows-and-more" hx-swap="outerHTML">LOAD 50 MORE</a>
</p>
{%- endif %}
```

Wrap each table's `<tbody>`+button in a `.rows-and-more` container so the htmx swap appends rows and replaces the button in one go (plain link still works: it renders the full page at the new offset — spec §8 allows either full-page or append semantics for the no-JS path; keep plain = full page). Add a small `qs_with` Jinja helper (existing filter-module style) that merges current query params with overrides. CSS: `.loadmore { text-align: center; margin: 8px 0; }`.

- [ ] **Step 8: Run tests, full suite, commit**

Run: `.venv/bin/pytest tests/test_pagination.py -q` → PASS, then `.venv/bin/pytest -q` → all green.

```bash
git add -A src/heim/dashboard tests/test_pagination.py
git commit -m "dashboard: LOAD 50 MORE pagination on investigations, incidents, findings"
```

---

### Task 2: Recommendations backend (table + collection logic)

**Files:**
- Modify: `src/heim/incidents/store.py` (new table + methods)
- Create: `src/heim/dashboard/recommendations.py` (pure collection logic)
- Test: `tests/test_recommendations.py` (new)

**Interfaces:**
- Consumes: `store.open_rows()`, `store.recent_findings()`, `store.investigations()`, `reports.render.extract_sections`.
- Produces:
  - `store` methods: `set_recommendation_state(key: str, state: str) -> None` (state ∈ {"done","dismissed"}; INSERT OR REPLACE), `recommendation_states() -> dict[str, dict]` (key → {state, created_at}).
  - `recommendations.collect(open_incidents, findings, investigations) -> list[dict]` — each dict: `{"key": str, "host": str, "text": str, "source": str, "source_href": str, "at": str}`; `recommendations.rec_key(kind: str, source_id, text: str) -> str` (sha1 hex of `kind:id:normalized-text`, normalize = lowercase, collapsed whitespace).

- [ ] **Step 1: Write failing tests**

```python
# tests/test_recommendations.py
from heim.dashboard.recommendations import collect, rec_key

def test_rec_key_stable_and_normalized():
    a = rec_key("finding", 3, "Set a  memory LIMIT")
    b = rec_key("finding", 3, "set a memory limit")
    assert a == b and len(a) == 40
    assert rec_key("finding", 4, "set a memory limit") != a

def test_collect_unions_open_incident_findings_and_remediations():
    incidents = [{"fingerprint": "u|mem|", "host": "u", "status": "open"}]
    findings = [
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "Cap it",
         "run_at": "2026-09-18T07:00:00"},
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "",
         "run_at": "2026-09-18T22:00:00"},           # empty rec -> ignored
        {"fingerprint": "x|gone|", "host": "x", "metric": "X", "recommendation": "Old",
         "run_at": "2026-09-17T07:00:00"},           # incident not open -> ignored
    ]
    invs = [{"id": 7, "host": "u", "status": "complete", "finished_at": "2026-09-18T08:00:00",
             "report_md": "## Summary\ns\n## Root cause\nrc\n## Recommended remediation\n1. Restart it\n2. Add an alert\n"}]
    rows = collect(incidents, findings, invs)
    texts = [r["text"] for r in rows]
    assert "Cap it" in texts and "Restart it" in texts and "Add an alert" in texts
    assert "Old" not in texts
    inv_row = next(r for r in rows if r["text"] == "Restart it")
    assert inv_row["source"] == "investigation #7" and inv_row["source_href"] == "/investigations/7"
    fin_row = next(r for r in rows if r["text"] == "Cap it")
    assert fin_row["source"].startswith("finding") and "Mem" in fin_row["source"]

def test_store_state_roundtrip(tmp_path):
    from heim.incidents.store import IncidentStore
    s = IncidentStore(tmp_path / "r.sqlite3")
    s.set_recommendation_state("k1", "done")
    s.set_recommendation_state("k1", "dismissed")   # idempotent replace
    states = s.recommendation_states()
    assert states["k1"]["state"] == "dismissed" and states["k1"]["created_at"]
    s.close()
```

- [ ] **Step 2: Run to verify failure** → FAIL (module/methods missing)

- [ ] **Step 3: Implement**

`store.py`: add to `_SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS recommendation_states (
    key        TEXT PRIMARY KEY,
    state      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

plus the two methods (validate `state in ("done", "dismissed")`, raise ValueError otherwise). `recommendations.py`:

```python
"""Collect actionable recommendations from open incidents and investigations (spec §9)."""
from __future__ import annotations
import hashlib, re
from heim.reports.render import extract_sections

def rec_key(kind: str, source_id, text: str) -> str:
    norm = re.sub(r"\s+", " ", str(text).strip().lower())
    return hashlib.sha1(f"{kind}:{source_id}:{norm}".encode()).hexdigest()

def collect(open_incidents: list[dict], findings: list[dict], investigations: list[dict]) -> list[dict]:
    open_fps = {i["fingerprint"] for i in open_incidents}
    rows: list[dict] = []
    latest: dict[tuple, dict] = {}
    for f in findings:                      # newest finding per (fingerprint) with a rec
        if f.get("fingerprint") in open_fps and str(f.get("recommendation") or "").strip():
            k = f["fingerprint"]
            if k not in latest or str(f.get("run_at", "")) > str(latest[k].get("run_at", "")):
                latest[k] = f
    for f in latest.values():
        rows.append({"key": rec_key("finding", f["fingerprint"], f["recommendation"]),
                     "host": f.get("host", ""), "text": str(f["recommendation"]).strip(),
                     "source": f"finding · {f.get('metric', '')}", "source_href": "/findings",
                     "at": str(f.get("run_at", ""))})
    for inv in investigations:
        if inv.get("status") not in ("complete", "resolved"):
            continue
        for item in extract_sections(inv.get("report_md") or "").get("remediation", []):
            rows.append({"key": rec_key("investigation", inv["id"], item),
                         "host": inv.get("host", ""), "text": item,
                         "source": f"investigation #{inv['id']}",
                         "source_href": f"/investigations/{inv['id']}",
                         "at": str(inv.get("finished_at") or "")})
    rows.sort(key=lambda r: r["at"], reverse=True)
    return rows
```

- [ ] **Step 4: Run tests to verify pass, full suite, commit**

```bash
.venv/bin/pytest tests/test_recommendations.py -q && .venv/bin/pytest -q
git add src/heim/incidents/store.py src/heim/dashboard/recommendations.py tests/test_recommendations.py
git commit -m "recommendations backend: state table + collection logic"
```

---

### Task 3: Recommendations page + actions + nav

**Files:**
- Modify: `src/heim/dashboard/app.py` (GET /recommendations, POST /actions/recommendation, nav entry)
- Create: `src/heim/dashboard/templates/recommendations.html`
- Modify: `src/heim/dashboard/static/heim.css` (row styles if needed)
- Test: extend `tests/test_recommendations.py`

**Interfaces:**
- Consumes: Task 2's `collect`, `rec_key`, store state methods; the existing `hostbadge` macro, `.btn`/`.acts` patterns, auth middleware, `_fields()` form parsing, flash/303 conventions from the actions slice.
- Produces: routes `GET /recommendations` and `POST /actions/recommendation` (form: `key`, `state` ∈ done|dismissed; 303 back / htmx fragment). Nav gains `Recommendations` between Findings and Metrics.

- [ ] **Step 1: Write failing route tests**

```python
def test_recommendations_page_lists_and_acts(seeded_client):
    c = seeded_client   # fixture: open incident w/ rec finding + complete investigation w/ remediation
    html = c.get("/recommendations").text
    assert "Cap it" in html and "investigation #" in html and "DONE" in html and "DISMISS" in html
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    r = c.post("/actions/recommendation", data={"key": key, "state": "done", "back": "/recommendations"},
               follow_redirects=False)
    assert r.status_code == 303
    html2 = c.get("/recommendations").text
    assert "handled (1)" in html2

def test_recommendation_bad_state_400(seeded_client):
    assert seeded_client.post("/actions/recommendation",
                              data={"key": "x" * 40, "state": "nope"}).status_code == 400

def test_nav_has_recommendations(seeded_client):
    assert 'href="/recommendations"' in seeded_client.get("/").text

def test_recommendations_empty_state(empty_client):
    assert "Nothing to act on." in empty_client.get("/recommendations").text
```

- [ ] **Step 2: Run to verify failure** → FAIL (404 on route)

- [ ] **Step 3: Implement route, action, template**

Route: gather `open_rows()`, `recent_findings(limit=500)`, `investigations(limit=100)`; `rows = collect(...)`; split by `store.recommendation_states()` into active vs handled; render. Action route mirrors the existing `/actions/*` handlers exactly (auth, `_fields`, validation → 400/404, 303/htmx fragment with a flash line "Marked done." / "Dismissed."). Template per spec §9 — active list rows:

```html
<tr>
  <td>{{ m.hostbadge(r.host) }}</td>
  <td class="rectext">{{ r.text }}</td>
  <td class="mono dim2"><a class="qlink" href="{{ r.source_href }}">{{ r.source }}</a></td>
  <td class="mono dim2">{{ r.at|rel }}</td>
  <td class="c-acts"><div class="acts">
    {{ m.act('/actions/recommendation', 'DONE', {'key': r.key, 'state': 'done'}) }}
    {{ m.act('/actions/recommendation', 'DISMISS', {'key': r.key, 'state': 'dismissed'}) }}
  </div></td>
</tr>
```

then the folded `<details><summary>handled ({{ handled|length }})</summary>…</details>` section with state pills. Nav entry between Findings and Metrics (nav list lives where the Metrics task put it — find it in app.py/base.html).

- [ ] **Step 4: Run tests, full suite, commit**

```bash
.venv/bin/pytest tests/test_recommendations.py -q && .venv/bin/pytest -q
git add -A src/heim/dashboard tests/test_recommendations.py
git commit -m "dashboard: recommendations page with done/dismiss actions"
```

---

### Task 4: Light mode

**Files:**
- Modify: `src/heim/dashboard/static/heim.css` (the `[data-theme="light"]` block from spec §10, verbatim tokens)
- Modify: `src/heim/dashboard/templates/base.html` (html data-theme, inline no-flash script, topbar toggle form)
- Modify: `src/heim/dashboard/app.py` (`?theme=` handler → cookie + 303; template context `theme`)
- Test: `tests/test_light_mode.py` (new)

**Interfaces:**
- Consumes: the token variables in `:root` (every component already reads vars).
- Produces: cookie `heim_theme` ∈ {auto, light, dark}; `<html data-theme="...">`.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_light_mode.py
def test_theme_toggle_sets_cookie_and_redirects(client):
    r = client.get("/?theme=light", follow_redirects=False)
    assert r.status_code == 303 and "heim_theme=light" in r.headers.get("set-cookie", "")
    html = client.get("/", cookies={"heim_theme": "light"}).text
    assert '<html lang="en" data-theme="light"' in html

def test_theme_auto_is_default_and_bad_values_ignored(client):
    html = client.get("/").text
    assert 'data-theme="auto"' in html or "prefers-color-scheme" in html
    r = client.get("/?theme=neon", follow_redirects=False)
    assert "heim_theme=neon" not in r.headers.get("set-cookie", "")

def test_css_has_light_tokens_and_no_stray_dark_hexes(client):
    css = client.get("/static/heim.css").text
    assert '[data-theme="light"]' in css
    assert "#B05E1A" in css       # validated light ember
    # identity palettes are mode-invariant — must NOT be redefined in the light block
    light = css[css.index('[data-theme="light"]'):]
    assert "--tool-ssh" not in light and "--ok:" not in light
```

- [ ] **Step 2: Run to verify failure** → FAIL

- [ ] **Step 3: Implement**

CSS: append the spec §10 block verbatim (tokens exactly as specced — they are validator-approved). Also add the auto media-query mirror:

```css
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]):not([data-theme="light"]) { /* same overrides as [data-theme="light"] */ }
}
```

(Duplicate the variable set or use the `[data-theme="light"], @media…` grouping — keep bytes tight; raising the CSS budget test is allowed per Global Constraints.)

base.html: `<html lang="en" data-theme="{{ theme }}">`; when theme == "auto", omit the attribute or set `auto` and let the media query act. Topbar toggle (next to the clock):

```html
<form class="themetoggle" method="get">
  <button class="btn" name="theme" value="{{ next_theme }}"
          title="theme: {{ theme }} — click for {{ next_theme }}">{{ theme_icon }}</button>
</form>
```

app.py: in the shared `page()` helper (or a small middleware), read `request.query_params.get("theme")` — if in {auto, light, dark}: set cookie (`max_age=31536000, samesite="lax"`), 303 to the same path without the param. Compute `theme` from cookie (default auto), `next_theme` cycling auto→light→dark→auto, `theme_icon` ☾/☀/◐. No inline JS needed if `data-theme` is server-rendered from the cookie (the "no-flash" script is only for auto-mode OS detection — the media-query mirror covers that without JS; skip the script).

Then sweep: `grep -n '#1B1917\|#131110\|#E9E2D4' src/heim/dashboard/templates src/heim/dashboard/static/heim.css` — any hex outside the `:root`/theme blocks is a bug; convert to vars.

- [ ] **Step 4: Run tests, full suite, visual check, commit**

Run: `.venv/bin/pytest tests/test_light_mode.py -q && .venv/bin/pytest -q` → green. Boot the app in-process, GET `/` with the light cookie, and confirm the emitted html carries the theme and the CSS serves the block (no browser needed).

```bash
git add -A src/heim/dashboard tests/test_light_mode.py
git commit -m "dashboard: light mode — warm paper tokens, cookie toggle, auto via media query"
```

---

### Task 5: Model choice at trigger time

**Files:**
- Modify: `src/heim/config.py` (Settings.investigator_models: list[str] = []), `config/settings.example.yaml` + `config/settings.yaml` (commented key, keep identical)
- Modify: `src/heim/pipelines/investigate.py` (InvestigationRequest.model_override; agent-cfg copy — REUSE the override mechanism the replay slice added, do not duplicate), `src/heim/pipelines/queue.py` (payload carries `model`), `src/heim/daemon.py` only if the worker builds requests there
- Modify: `src/heim/dashboard/app.py` (`/actions/investigate` accepts optional `model`, validated against settings.investigator_models), `templates/partials/_host_acts.html`, `_incident_acts.html` (the select), `partials/_macros.html` if the act macro needs an extra-fields slot
- Modify: `src/heim/cli.py` (`heim investigate --model X`)
- Test: `tests/test_model_choice.py` (new)

**Interfaces:**
- Consumes: the replay slice's model-override path in run_agent/run_investigation (read it first; reuse its exact mechanism).
- Produces: job payload key `"model"`; `InvestigationRequest.model_override: str = ""`; investigations.model records the model that ran.

**Spec:** `docs/design/dashboard-ui.md` §5.1.

- [ ] **Step 1: Failing tests**

```python
# tests/test_model_choice.py
def test_request_model_override_reaches_client(stubbed_investigation_env):
    # run a stubbed investigation with model_override="claude-opus-4-6";
    # assert the stubbed anthropic client received that model AND the stored
    # investigation row's model column says "claude-opus-4-6".
    ...  # build on test_tracking.py's stub pattern — the stub records kwargs["model"]

def test_dashboard_investigate_accepts_allowed_model(actions_client):
    r = actions_client.post("/actions/investigate",
        data={"host": "ubuntu-server", "model": "claude-opus-4-6", "back": "/hosts"},
        follow_redirects=False)
    assert r.status_code == 303
    job = store_of(actions_client).jobs()[0]
    assert '"model": "claude-opus-4-6"' in job["payload_json"]

def test_dashboard_rejects_unlisted_model(actions_client):
    assert actions_client.post("/actions/investigate",
        data={"host": "ubuntu-server", "model": "gpt-99"}).status_code == 400

def test_select_rendered_only_when_configured(actions_client, plain_client):
    assert '<select name="model"' in actions_client.get("/hosts").text      # models configured
    assert '<select name="model"' not in plain_client.get("/hosts").text    # empty list
```

(Replace the `...` with the concrete stub wiring copied from how test_tracking.py fakes run_agent/the anthropic client — the test must assert the model kwarg end-to-end, not a mock of our own code.)

- [ ] **Step 2: Run to verify failure** → FAIL

- [ ] **Step 3: Implement**

Settings + yamls: `investigator_models: []` with comment "exact model ids offered in the dashboard's investigate dropdown; empty = default only". Request plumbing: `InvestigationRequest.model_override: str = ""`; where run_investigation resolves the agent cfg, apply the override exactly the way the replay pipeline overrides the model (import/shared helper — no duplication). Persist the ACTUAL model on the investigation row. queue.enqueue_investigation gains `model=""` → payload; request_from_payload restores it. Dashboard action: validate `model` ∈ settings.investigator_models (else 400); template select (first option `default (<cfg model>)`, value=""):

```html
{%- if models %}
<select class="mselect mono" name="model">
  <option value="">default ({{ default_model }})</option>
  {%- for mid in models %}<option value="{{ mid }}">{{ mid }}</option>{% endfor %}
</select>
{%- endif %}
```

Approval texts: append ` · model: <id>` when overridden (Telegram ask + pending screen header already show inv.model — verify it shows the override). CLI: `--model` choice-validated the same way.

- [ ] **Step 4: Run tests, full suite, commit**

```bash
.venv/bin/pytest tests/test_model_choice.py -q && .venv/bin/pytest -q
git add -A && git commit -m "investigations: per-trigger model choice (dashboard select, CLI --model)"
```
