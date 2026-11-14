# SENTINEL console — design system

Durable visual decisions for the hub web console (`collector/`). Product truth
lives in [PRODUCT.md](PRODUCT.md). The console is an **Operate** surface.

## The one idea

A quiet operations ledger. The event feed is the page; scope, status and
forensics arrange themselves around it. It refuses the cockpit: no hero metric
tiles, no gauges, no sparklines, no neon.

## Colour

Restrained, physically motivated: a night on-call operator in a dark room.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--ground` | `#101112` | `#f3f1ec` | page, feed |
| `--surface` | `#151719` | `#fbfaf7` | bars, rail, panes |
| `--raised` | `#1b1e21` | `#ffffff` | hover, dialogs |
| `--sunken` | `#0b0c0d` | `#e9e6e0` | inputs, wells |
| `--line` | `#25292d` | `#dcd8d1` | hairlines |
| `--line-strong` | `#363c43` | `#c3beb5` | dialog edges |
| `--ink` | `#e8e6e3` | `#17191b` | text |
| `--ink-muted` | `#a6a39f` | `#54585c` | secondary text |
| `--ink-faint` | `#8a8f94` | `#777c81` | timestamps, hints |
| `--accent` | `#8fb0d9` | `#3f6f9f` | focus, selection, lineage ids |
| `--crit` / `--high` / `--ok` | `#e2685f` / `#d9a441` / `#7fbf9f` | `#a8342b` / `#8a5a10` / `#2f6b4f` | severity only |

Severity is the only place colour carries meaning; it never fills a row. The
accent marks selection and focus, never decoration. Text contrast is ≥4.5:1
for body and placeholders.

## Type

One family, system stack, no webfont dependency (self-hosted/offline).

- `--font-ui`: `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, …`
- `--font-mono`: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, …`

Fixed scale, ratio ~1.15: 11 / 12 / 13 / 14 / 16 / 20 px. Mono is reserved for
data: timestamps, pids, lineage ids, rule ids, commands, hosts. Labels and UI
copy are sans. Tabular numerals everywhere numbers align.

## Space and form

4 / 8 / 12 / 16 rhythm. Surfaces are squared (4–6 px radii), separated by 1 px
hairlines rather than shadows or cards-inside-cards. Headings carry weight;
there are no eyebrow/kicker labels above them.

## The feed (primary surface)

40 px rows in a five-column grid, normal mode:

```
76px time · 74px severity · 168px process · 1fr event summary · 116px host
```

Investigation mode swaps the host column for `rule · pid · lineage`, keeps the
summary last. Rows state severity as a word plus a small square swatch — never
a coloured bar. Selected rows take an accent wash and a 1 px inset ring. Hover
is a background shift only. A `kill` tag appears inside the summary when
enforcement acted.

## Components and states

Every control ships default / hover / focus-visible / active-or-selected /
disabled: icon buttons, text buttons, selects, chips, palette rows, inspector
actions. Focus is a 2 px accent outline with 2 px offset. Empty states teach
(a heading, what will appear, and the command to run) instead of saying
"nothing here".

## Motion

State only, 140 ms, `cubic-bezier(0.2, 0, 0, 1)`. No page-load choreography,
no decorative easing. `prefers-reduced-motion` collapses all durations.

## Modes

- **Normal** (default): feed + scope rail. Graph and inspector closed.
- **Investigation**: adds rule/pid/lineage columns, the lineage graph pane and a
  click-through inspector. `I`, the header button, or the palette toggle it.

## Responsive

Structural, not fluid type: graph pane hides <980 px, rail becomes an overlay
<760 px, columns drop (host, then process) instead of shrinking type. Coarse
pointers get 40 px targets.

## Bans observed

No gradient text, no glass/blur decoration, no coloured left borders on rows,
no sparklines or hero metric tiles, no eyebrow labels, no emoji icons, no
monospace as a costume.
