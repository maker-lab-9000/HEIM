"""Light mode (spec §10): the `heim_theme` cookie, the no-JS toggle form, and
the "morning ash" token override set — including the deliberate exception that
keeps the terminal surfaces dark."""
import html as html_mod
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
    # a preference, not a session — but no script has any reason to read it
    assert "HttpOnly" in cookie


def test_toggle_form_cycles_auto_light_dark_and_works_without_js(client):
    def toggle(theme: str | None, path: str = "/") -> tuple[str, str]:
        cookies = {"heim_theme": theme} if theme else {}
        html = client.get(path, cookies=cookies).text
        link = re.search(r'<a class="btn themetoggle".*?</a>', html, re.S).group(0)
        # a plain GET link: no hx-* attribute, so the switch is a normal page
        # load with JS off
        assert "hx-" not in link
        return re.search(r'theme=(\w+)', link).group(1), link

    assert toggle(None)[0] == "light"          # auto → light
    assert toggle("light")[0] == "dark"        # light → dark
    assert toggle("dark")[0] == "auto"         # dark → auto
    # the icon is the lockup's own vocabulary (§10): ☀ light · ☾ dark · ◐ auto
    assert ">☀<" in toggle("light")[1]
    assert ">☾<" in toggle("dark")[1]
    assert ">◐<" in toggle(None)[1]
    # the glyph is not an accessible name and `title` is not reliably
    # announced, so the button says what it does out loud
    assert 'aria-label="theme: light — switch to dark"' in toggle("light")[1]
    assert 'aria-label="theme: auto — switch to light"' in toggle(None)[1]


def test_toggle_preserves_filters_and_paging(client):
    """Switching the theme must not throw the operator's filters and offset
    away: the toggle target is this URL with `theme` merged in, so the 303
    (which drops only `theme`) lands back on the same filtered page."""
    html = client.get("/incidents?status=open&offset=50").text
    raw = re.search(r'<a class="btn themetoggle" href="([^"]+)"', html).group(1)
    # the separators are escaped in the attribute, exactly like the paging links
    assert "&amp;" in raw
    href = html_mod.unescape(raw)
    assert href.startswith("/incidents?")
    params = sorted(href.split("?", 1)[1].split("&"))
    assert params == ["offset=50", "status=open", "theme=light"]
    # and the round trip really does come back to the filtered page
    r = client.get(href, follow_redirects=False)
    assert r.status_code == 303
    assert sorted(r.headers["location"].removeprefix("/incidents?").split("&")) \
        == ["offset=50", "status=open"]


def test_bad_theme_value_still_renders_the_page_with_the_cookie_theme(client):
    html = client.get("/?theme=neon", cookies={"heim_theme": "light"}).text
    assert 'data-theme="light"' in html


# -------------------------------------------------- tokens, not hardcoded hex

LIGHT_SELECTOR = '[data-theme="light"] {'
MIRROR_SELECTOR = ':root:not([data-theme="dark"]) {'


def _css() -> str:
    return (ROOT / "src/heim/dashboard/static/heim.css").read_text()


def _declarations(css: str, selector: str) -> dict[str, str]:
    """The `--token: value` pairs of one rule, comments stripped."""
    start = css.index(selector) + len(selector)
    body = re.sub(r"/\*.*?\*/", "", css[start:css.index("}", start)], flags=re.S)
    return dict(
        (m.group(1), m.group(2).strip())
        for m in re.finditer(r"(--[\w-]+)\s*:\s*([^;]+);", body)
    )


def test_light_block_and_auto_mirror_declare_the_same_tokens():
    """The media mirror duplicates the override set because a media query
    cannot join a selector list — and it OUTWEIGHS the light block:
    `:root:not([data-theme="dark"])` is (0,2,0) since :not()'s argument
    counts, versus (0,1,0). So on the one combination where both match (an
    explicit light cookie on an OS that also prefers light) the mirror wins
    silently, and any drift between them would surface only there. Compare
    them instead of trusting that they were copied right."""
    css = _css()
    light = _declarations(css, LIGHT_SELECTOR)
    mirror = _declarations(css, MIRROR_SELECTOR)
    assert light, "the light override set went missing"
    drift = sorted(
        f"{token}: light={light.get(token, '<absent>')!r} "
        f"mirror={mirror.get(token, '<absent>')!r}"
        for token in set(light) | set(mirror)
        if light.get(token) != mirror.get(token)
    )
    assert not drift, (
        "[data-theme=\"light\"] and the prefers-color-scheme mirror must stay "
        "token-identical; they drifted:\n  " + "\n  ".join(drift))


def test_components_read_theme_tokens_only(client):
    """Outside :root and the theme blocks, no component may name a color: the
    dark surfaces would survive the override set and leak into light mode."""
    # comments first: the theme blocks are annotated with the literals they
    # pin, and prose about a color is not a declaration
    css = re.sub(r"/\*.*?\*/", "", _css(), flags=re.S)
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
    css = _css()
    light = _declarations(css, LIGHT_SELECTOR)
    # deliberately §10's literal panel charcoal, a shade below dark mode's own
    # var(--raised) #232019 for the same component (documented at the block)
    assert light["--term-bg"] == "#1B1917" and light["--term-ink"] == "#E9E2D4"
    # the burn/prompt ember keeps its original value inside the dark islands
    assert light["--term-ember"] == "#E88C3A"
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
