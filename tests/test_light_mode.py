"""Light mode (spec §10): the `heim_theme` cookie, the no-JS toggle form, and
the "morning ash" token override set — including the deliberate exception that
keeps the terminal surfaces dark."""
import re
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """An empty store is enough here: the theme lives in the base shell, so
    every page carries it whether or not there is anything to list."""
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot,
                    ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    IncidentStore(db).close()
    with TestClient(create_app(cfg)) as c:
        yield c


# ------------------------------------------------------------- the no-JS path

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


def test_redirect_drops_only_the_theme_param_and_cookie_is_durable(client):
    r = client.get("/incidents?status=open&theme=dark", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/incidents?status=open"
    cookie = r.headers["set-cookie"]
    assert "heim_theme=dark" in cookie
    assert "Max-Age=31536000" in cookie and "SameSite=lax" in cookie


def test_toggle_form_cycles_auto_light_dark_and_works_without_js(client):
    def toggle(theme: str | None) -> tuple[str, str]:
        cookies = {"heim_theme": theme} if theme else {}
        html = client.get("/", cookies=cookies).text
        form = re.search(r'<form class="themetoggle" method="get">.*?</form>',
                         html, re.S).group(0)
        # a plain GET form with a single submit button: no hx-* attribute, so
        # the switch is a normal page load with JS off
        assert "hx-" not in form
        return re.search(r'value="(\w+)"', form).group(1), form

    assert toggle(None)[0] == "light"          # auto → light
    assert toggle("light")[0] == "dark"        # light → dark
    assert toggle("dark")[0] == "auto"         # dark → auto
    # the icon is the lockup's own vocabulary (§10): ☀ light · ☾ dark · ◐ auto
    assert ">☀<" in toggle("light")[1]
    assert ">☾<" in toggle("dark")[1]
    assert ">◐<" in toggle(None)[1]


def test_bad_theme_value_still_renders_the_page_with_the_cookie_theme(client):
    html = client.get("/?theme=neon", cookies={"heim_theme": "light"}).text
    assert 'data-theme="light"' in html


# -------------------------------------------------- tokens, not hardcoded hex

def test_components_read_theme_tokens_only(client):
    """Outside :root and the theme blocks, no component may name a color: the
    dark surfaces would survive the override set and leak into light mode."""
    css = (ROOT / "src/heim/dashboard/static/heim.css").read_text()
    blocks = re.findall(r"(?:^:root|\[data-theme=\"light\"\]\s*\{|"
                        r":root:not\(\[data-theme=\"dark\"\]\))[^}]*\}",
                        css, re.M)
    rest = css
    for block in blocks:
        rest = rest.replace(block, "")
    assert not re.search(r"#[0-9A-Fa-f]{3,8}\b", rest), \
        re.findall(r".*#[0-9A-Fa-f]{3,8}.*", rest)


def test_terminal_surfaces_stay_dark_in_light_mode(client):
    """§10's one deliberate exception: a terminal has no light mode. The dark
    charcoal is pinned through the --term-* slots so the components themselves
    still read tokens only."""
    css = (ROOT / "src/heim/dashboard/static/heim.css").read_text()
    light = css[css.index('[data-theme="light"] {'):]
    light = light[:light.index("}")]
    assert "--term-bg: #1B1917" in light and "--term-ink: #E9E2D4" in light
    # the burn/prompt ember keeps its original value inside the dark islands
    assert "--term-ember: #E88C3A" in light
    for rule in (".cmd", ".rfull", ".wrap", ".prose code, .prose pre"):
        body = css[css.index(rule + " ") if rule.endswith("pre") else css.index(rule + " {"):]
        body = body[:body.index("}")]
        assert "var(--term-bg)" in body, rule


def test_light_mode_applies_to_a_rendered_page_end_to_end(client):
    """The emitted HTML under the light cookie must carry the theme and no
    stray dark surface hex of its own."""
    html = client.get("/incidents", cookies={"heim_theme": "light"}).text
    assert 'data-theme="light"' in html
    # the rail wordmark is inline SVG on currentColor, so it themes itself
    assert 'fill="currentColor"' in html and "#E9E2D4" not in html
    assert "#131110" not in html and "#1B1917" not in html
