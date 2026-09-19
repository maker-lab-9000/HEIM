# Investigation detail header → real table

## What changed

`src/heim/dashboard/templates/investigation.html`
- The `<dl class="imeta">` grid of `.kv` label/value pairs is replaced by
  `<table class="tbl dense imeta">` — the same dense-table classes every other
  table in the app uses. One `<thead>` row of `<th scope="col">` labels
  (trigger · agent · tokens · cost · duration · started · fingerprint) and one
  `<tbody>` row of values. `.tbl th` already carries the mono-caps eyebrow
  treatment (0.6875rem mono, `.08em` tracking, uppercase, `--ink-2`), so the
  labels look exactly as they did with no new CSS.
- Values keep their filters: trigger in `.eyebrow`; agent as
  `<agent> · <model>`; tokens `N in → N out`; cost via `|money` (dash when
  unpriced); duration with "… so far" while running; started via `m.when()`
  (the `<time datetime=… title=…>` macro, the table convention); fingerprint
  now via the existing `|fp` middle-truncate filter with the full value on
  `title=`, matching the list/overview/incidents cells.
- The host name + status pill stay above the table in `h2.ihost`; the
  APPROVE/DECLINE/RE-RUN `_inv_acts.html` include stays below it.
- The `re-run of #N` / `replay of #N` lineage line was a `.kv` pair inside the
  `<dl>` (it was never a column). It now renders as a `<p class="headline">`
  between the table and the actions — same place in the reading order, and
  `.headline` is an existing rule, so again no new CSS. The anchor markup
  (`href="/investigations/N">replay of #N</a>`) is byte-identical to before,
  which is what `test_replay.py` asserts on.

`src/heim/dashboard/static/heim.css`
- The `.imeta` grid rules were replaced in place by table rules. `.imeta` is
  still the investigation-meta class, now:
  `table-layout: fixed`, `td { overflow-wrap: anywhere }`, and percentage
  widths (tokens/cost/duration 11% each, agent/fingerprint 19% each; trigger
  and started take the remaining ~10% each). Fixed layout + `overflow-wrap`
  is the same technique `.mtbl` already uses, and it is what stops a long
  model name or fingerprint from widening the table past a laptop viewport —
  they wrap inside their column instead.

## CSS byte accounting

- Old `.imeta` block (grid + `.kv`/`dt`/`dd` rules + its comment): 337 B
- New `.imeta` block (4 rules + a 2-line comment): 330 B
- File: 20,971 B → **20,964 B** (−7 B). Cap left at 20,992 B, untouched —
  no new budget was needed because the grid rules the table replaced paid
  for the new ones.

## Tests ported

- `tests/test_dashboard.py::test_header_meta_pairs_are_atomic_cells` →
  `test_header_meta_is_a_table_with_one_row_of_values`. The old test proved
  "a value can never slide under the neighbouring column" via the `.kv`
  wrapper invariant; that intent is now proved structurally: the seven `<th>`
  labels in order, exactly one `<tr>` in the body with one `<td>` per column,
  and each value checked positionally (so a value cannot land in the wrong
  column). It also asserts the CSS rules that keep long values in their
  column, replacing the old `".imeta .kv" / "auto-fit"` CSS assertion. This is
  also the required new test: it covers all seven headers, the single value
  row, the unpriced-cost em dash and the running investigation's "so far"
  duration, plus `m.when()`'s `<time datetime=…>` and the truncated
  fingerprint with its full-value `title`.
- `tests/test_observability.py::test_unpriced_investigation_shows_a_dash_not_zero`
  and `::test_currency_other_than_usd_uses_the_code` both sliced the header
  with `html.index('<dl class="imeta">') … '</dl>'`. Added a module-local
  `_meta_table(html)` helper that slices `class="tbl dense imeta"` … `</table>`
  and pointed both at it. Their assertions (no `$0.00`, DASH present,
  `EUR 0.45` and no `$`) are unchanged.
- Nothing was deleted: `test_running_row_shows_elapsed_not_a_dash`,
  `test_investigation_detail_transcript` (agent/tokens strings),
  `test_dashboard_actions`'s `re-run of #N` and `test_replay`'s lineage
  assertions all still pass unmodified against the new markup.

## Verification

Rendered in-process with TestClient (no server, no curl), eyeballing the
emitted `.card.head` HTML for:
(a) pending_approval, no tokens/cost — `0 in → 0 out`, `—` cost, `—` duration;
(b) complete + priced — `128k in → 4.2k out`, `$0.45`, `5m 00s`, truncated
    fingerprint with the full value on `title`;
(c) a replay — trigger `replay`, `claude-haiku-4-6`, and the
    `lineage · replay of #1` line below the table.
All three rendered one header row and one value row with the columns aligned.
The scratch file used for this was deleted; it is not part of the commit.

Command: `.venv/bin/pytest -q`
Output: `724 passed, 12 warnings in 21.19s`

## Judgment calls

- **Fingerprint is now truncated on the detail page too.** It used to print in
  full. In a fixed-width column the full string wrapped to three lines, so it
  now goes through `|fp` (the "existing filter" the brief names) with the
  complete value on `title=` — identical to every other fingerprint cell in
  the app. Nothing is lost: hover, view-source and copy all still give the
  whole string, and the page works without JS.
- **Lineage is a line, not a column.** It only exists on re-runs/replays, so a
  column would be empty on almost every page and the brief lists seven columns
  that do not include it.
- **Reused `.imeta` rather than adding a class.** The name still means "the
  investigation header meta", so repurposing its rules kept the diff local and
  paid for the new rules out of the old ones.
- **No `margin-top` on the table**: `.card > h2` already supplies 10px below
  the title, which is what the old `.imeta { margin: 10px 0 0 }` doubled.
