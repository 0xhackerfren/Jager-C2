# Jager-C2 Engagement Profile Arsenal

Cobalt Strike-style malleable C2 profiles as YAML templates. Each build mutates a template
deterministically from `engagement_id + build_nonce`, producing globally unique wire signatures
that match between teamserver listener and compiled implant.

## Layout

```
profiles/
  arsenal/          # Base templates (AI/human authored)
  schema.yaml       # Field reference for agents
  generated/        # Per-build outputs (gitignored in engagements)
```

## Agent workflow

1. Read `engagement.config.json` → `jager.profile.template` (or pick from arsenal)
2. Optionally author/customize YAML under `engagements/<lab>/c2/profile.yaml`
3. Build via MCP `c2_build_implant(profile_template=...)` — never reuse artifacts across engagements
4. Store `profile_fingerprint` in evidence and session log

## Determinism

Same `(engagement_id, template, build_nonce)` always yields the same URIs, transforms, pipes,
mutexes, and compile flags. Different `build_nonce` per implant build = unique signature.
