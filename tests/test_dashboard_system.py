"""The console system (redesign 2026-11-01, `design.md`): the Hallmark stamp,
the token blocks, the lamps, the grouped rail with its footer, the favicon,
and the rule that no template carries an emoji or a symbol glyph as a status."""
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard.app import NAV, create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _seed

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src/heim/dashboard/static"
TEMPLATES = ROOT / "src/heim/dashboard/templates"

LIGHT = '[data-theme="light"] {'
MIRROR = ':root:not([data-theme="dark"]) {'

#: the glyphs the redesign retired (the operator's ruling: words and lamps).
#: ▲ stays allowed: it is a change marker in data, not a status.
RETIRED = "💡 🔒 👍 ☀ ☾ ◐ ● ○ ◌ ◷ ✓ ✗ ✕ ⚠ ✳ ◆ ‖ ⛔".split()


def _css() -> str:
    return (STATIC / "heim.css").read_text()


def _decls(css: str, selector: str) -> dict[str, str]:
    start = css.index(selector) + len(selector)
    body = re.sub(r"/\*.*?\*/", "", css[start:css.index("}", start)], flags=re.S)
    return {m.group(1): m.group(2).strip()
            for m in re.finditer(r"(--[\w-]+)\s*:\s*([^;]+);", body)}


def _iso(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    _seed(db)
    with TestClient(create_app(cfg)) as c:
        yield c


def _client_with(tmp_path, monkeypatch, seed) -> TestClient:
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    seed(store)
    store.close()
    return TestClient(create_app(cfg))


# ------------------------------------------------------------------ tokens

def test_css_starts_with_the_hallmark_stamp():
    first = next(line for line in _css().splitlines() if line.strip())
    assert first.startswith("/* Hallmark ·") and "theme: custom" in first


def test_light_ground_is_the_console_grey():
    css = _css()
    assert _decls(css, LIGHT)["--bg"] == "#E6E2DA"
    assert _decls(css, ":root {")["--bg"] == "#1C1916"


def test_lamp_tokens_are_mode_invariant():
    css = _css()
    root, light, mirror = (_decls(css, s) for s in (":root {", LIGHT, MIRROR))
    for token in ("--signal", "--crit", "--warn", "--ok"):
        assert token in root, token
        assert token not in light and token not in mirror, token


def test_overflow_clip_on_html_and_body():
    assert re.search(r"html,\s*body\s*\{[^}]*overflow-x:\s*clip", _css())


def test_three_font_weights_only():
    css = re.sub(r"/\*.*?\*/", "", _css(), flags=re.S)
    keyword = {"normal": "400", "bold": "700", "bolder": "700", "lighter": "300"}
    weights = {keyword.get(w, w) for w in re.findall(r"font-weight:\s*([\w-]+)", css)}
    for value in re.findall(r"\bfont:\s*([^;}]+)", css):
        head = value.split()[0]
        if head.isdigit() or head in keyword:
            weights.add(keyword.get(head, head))
    assert weights and weights <= {"400", "600", "800"}, weights


# --------------------------------------------------------------- templates

def test_no_emoji_or_status_glyphs_in_templates():
    found = [(p.relative_to(TEMPLATES).as_posix(), g)
             for p in TEMPLATES.rglob("*.html") for g in RETIRED
             if g in p.read_text()]
    assert not found, found


def test_dot_spans_are_empty_lamps(client):
    html = client.get("/incidents").text
    dots = re.findall(r'<span class="dot" aria-hidden="true">(.*?)</span>', html, re.S)
    assert dots, "the incidents page renders pills"
    assert all(d == "" for d in dots), sorted(set(dots))


def test_favicon_is_the_compact_mark():
    svg = (STATIC / "logo.svg").read_text()
    assert "#E8541E" in svg and "#E88C3A" not in svg


# ------------------------------------------------------------------- shell

def test_rail_is_grouped_with_lamps_and_counts(client):
    html = client.get("/").text
    rail = html[html.index('<nav class="rail"'):]
    rail = rail[:rail.index("</nav>")]
    for group in ("Workspace", "Infrastructure", "Insights"):
        assert re.search(rf'class="label[^"]*">{group}<', rail), group
    items = re.findall(r"<li>(.*?)</li>", rail, re.S)
    assert len(items) == len(NAV)
    assert all('class="lamp' in item for item in items)
    current = [i for i in items if 'aria-current="page"' in i]
    assert len(current) == 1 and 'href="/"' in current[0]
    for href in ("/agents", "/investigations", "/incidents", "/hosts"):
        item = next(i for i in items if f'href="{href}"' in i)
        assert 'class="n"' in item, href
    # the brand: the logo mark with its lamp dot, named once for AT
    assert 'class="spark"' in rail and 'class="dot"' in rail
    assert 'aria-label="HEIM"' in rail and "H 01" in rail


def test_rail_counts_come_from_the_store(client):
    html = client.get("/incidents").text          # any page: page() supplies them

    def count(href: str) -> str:
        item = re.search(rf'<a href="{href}"[^>]*>.*?</a>', html, re.S).group(0)
        return re.search(r'<span class="n">(\d+)</span>', item).group(1)

    assert count("/agents") == "7"
    assert count("/investigations") == "1"       # the seed: one running, none pending
    assert count("/incidents") == "2"            # the seed's two open incidents
    assert count("/hosts") == str(len(client.app.state.config.hosts))


def test_rail_footer_shows_connection_and_appearance(client):
    html = client.get("/").text
    foot = html[html.index('class="rail-foot"'):]
    assert any(w in foot for w in ("Connected", "Daemon quiet", "No heartbeat yet"))
    assert "Appearance" in foot and 'class="daemon' in foot


def test_daemon_line_reads_the_newest_poll_heartbeat(tmp_path, monkeypatch):
    def fresh(store):
        store.record_agent_run("thresholds", _iso(2), _iso(2), True)
        store.record_agent_run("alert_poller", _iso(40), _iso(40), True)

    with _client_with(tmp_path / "a", monkeypatch, fresh) as c:
        html = c.get("/").text
        assert "Connected" in html and "Synced 2m ago" in html

    def quiet(store):
        store.record_agent_run("uptime", _iso(90), _iso(90), False, "boom")

    with _client_with(tmp_path / "b", monkeypatch, quiet) as c:
        html = c.get("/").text
        assert "Daemon quiet" in html and "Last sync 1h ago" in html

    with _client_with(tmp_path / "c", monkeypatch, lambda s: None) as c:
        assert "No heartbeat yet" in c.get("/").text


def test_seg_macro_marks_the_engaged_segment(client):
    env = client.app.state.templates.env
    out = env.from_string(
        '{% import "partials/_macros.html" as m %}{{ m.seg(items, "Window") }}'
    ).render(items=[{"href": "?window=live", "label": "Live", "on": True},
                    {"href": "?window=24h", "label": "24 h", "n": 3, "on": False}])
    assert 'class="seg" role="group" aria-label="Window"' in out
    live = re.search(r'<a[^>]*href="\?window=live"[^>]*>.*?</a>', out).group(0)
    assert 'aria-current="true"' in live and 'class="lamp sm orange"' in live
    day = re.search(r'<a[^>]*href="\?window=24h"[^>]*>.*?</a>', out).group(0)
    assert "aria-current" not in day and '<span class="n">3</span>' in day
