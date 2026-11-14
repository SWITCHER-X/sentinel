# Surface: hub console

- Target: collector/index.html (+ collector/login.html)
- Mode: Operate
- Audience: self-hosting admins on call at night, dark room, one monitor
- Job: triage a live feed, open one event for forensics, act on a lineage
- Constraints: vanilla JS module contract, no build step, no new dependencies,
  no external fonts; all existing controls must remain reachable

## Direction contract

THESIS: A quiet operations ledger, not a cockpit. The event feed is the page;
scope, status and forensics arrange around it. Refuses hero metrics, gauges,
sparklines, neon and card grids.

OWN-WORLD: warm graphite ground (#101112), paper-white text (#e8e6e3), hairline
rules (#25292d), one steel-blue accent (#8fb0d9) for focus/selection/lineage,
squared 4–6px surfaces, system sans throughout with mono reserved for data.

STORY: The operator scans severity and process, spots the one event that
matters, opens it to see rule, pid, lineage and host, then blocks or exports.

FIRST VIEWPORT: 46px app bar (wordmark, host/range scope, live status, mode,
view toggle) over a 268px scope rail and a full-height feed of 40px rows —
time, severity word, process, event summary, host — with a 32px status footer.

FORM: code-led; ledger/triage composition, position 1 of 3 ordered structures.
seed: none (unavailable) — the direction round was substituted by two product
questions (primary task, use scene) because this host has no browser to serve
the decision page.

FINISH: unreviewed and undocumented is unfinished; this build ends with the
finish review, the verdict, DESIGN.md, and every shipping raster carrying its
provenance.
