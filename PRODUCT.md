# SENTINEL — Lineage EDR

Self-hosted, single-node Linux endpoint detection and response built on eBPF
process lineage. Ships two processes: a hub (collector + web console) and an
agent that reports executions, connections, file access and blocked lineages.

## Users

System administrators, security engineers and developers who run their own
infrastructure. They install it themselves, keep it on their own network, and
are the only operators. Not a managed SOC with shifts and handoffs.

## Jobs

1. **Triage (primary).** Scan a live feed and spot what matters in seconds:
   what ran, how bad it is, and whether enforcement acted.
2. **Investigate.** Open one event and understand the chain: rule, lineage,
   parent, pid, host, argv, MITRE technique.
3. **Respond.** Switch learn/enforce, block a lineage, export evidence, audit.

## Scene

Night on-call. Dark room, long sessions, one monitor, low ambient light. The
console is glanced at, not read start to finish. Dark is the default theme and
must stay low-glare; light theme exists for daytime handoff.

## Tone

Precise, calm, evidence-first. It states facts and shows its work. No hype, no
gamification, no alarms that shout. Severity is information, not decoration.

## Anti-references

- Neon-on-black "hacker movie" terminals, glowing edges, scanlines, matrix
  rain, decorative cyber motifs.
- Cockpit dashboards where gauges and sparklines outrank the event list.
- Marketing gradients, glass panels, hero metric tiles.
- Anything that makes an operator hesitate about what is interactive.

## Principles

- Signal first: severity and process legible in under a second.
- Progressive disclosure: a calm default that expands into forensic detail.
- Every claim traceable to evidence (rule id, lineage, pid, argv, host).
- Keyboard-first, pointer-friendly, no hidden gestures.
- Self-hosted by default: no external font/CDN dependency, works offline.

## Platform

web

## Constraints

Single-page vanilla JS with no build step and no new dependencies; the hub API
and the existing dashboard module contract stay unchanged. Functionality may
not be removed, only revealed differently.
