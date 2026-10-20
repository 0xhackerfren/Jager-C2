#!/usr/bin/env python3
"""
Jager-C2 Engagement Profile Engine

Deterministic malleable C2 profile generation from YAML arsenal templates.
Every build gets a globally unique wire signature keyed on:
    SHA256(engagement_id : template : build_nonce)

Delegates shared IOC derivation to ``jager_shared.profile_core`` so both
JagerExec and Jager-C2 stay in lock-step on pipe/service/mutex/key generation.

Outputs:
  - overlay JSON  -> build_implant.py --profile-json (paths + malleable_wire + evasion)
  - malleable JSON -> teamserver listener (full CS-style profile)

Usage:
  python3 profile_engine.py --template default --engagement-id dante-2026 \\
      --build-nonce $(openssl rand -hex 8) \\
      --overlay-out /tmp/overlay.json --malleable-out /tmp/malleable.json
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

_repo = Path(__file__).resolve().parents[2]
if str(_repo) not in sys.path:
    sys.path.insert(0, str(_repo))

from jager_shared.profile_core import (
    compute_fingerprint,
    derive_ioc_artifacts,
    load_engagement_config,
    load_yaml,
    mutate_user_agent,
    resolve_engagement_id,
    rng_for,
    rng_sub,
    utc_iso_now,
)


VALID_INJECT_METHODS = frozenset({"classic", "threadless", "hollow", "apc"})
VALID_DOMAIN_FRONT_CDNS = (
    "cloudfront.net",
    "azureedge.net",
    "fastly.net",
    "akamaized.net",
)
VALID_SLEEP_TECHNIQUES = frozenset(
    {"none", "basic", "timer", "zilean", "hwbp", "threadpool", "ekko", "foliage"}
)
VALID_AMSI_BYPASS = frozenset({"hwbp", "pageguard", "patch"})


def validate_profile(profile: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for profile schema and CDN fronting checks."""
    errors: list[str] = []
    warnings: list[str] = []

    for key in ("name", "user_agent", "http_get", "http_post"):
        if key not in profile:
            errors.append(f"missing required field: {key}")

    errors.extend(validate_evasion_section(profile.get("evasion")))

    im = (profile.get("evasion") or {}).get("inject_method")
    if im and str(im).lower() not in VALID_INJECT_METHODS:
        errors.append(f"evasion.inject_method invalid: {im!r}")

    if df := profile.get("domain_front"):
        cdn = str(df.get("cdn") or df.get("cdn_host") or "")
        if cdn and not any(cdn.endswith(suffix) for suffix in VALID_DOMAIN_FRONT_CDNS):
            warnings.append(f"Domain fronting CDN '{cdn}' not recognized")

    spawn = profile.get("spawn_to")
    if spawn is not None and not isinstance(spawn, dict):
        errors.append("spawn_to must be an object with x86/x64 paths")

    return errors, warnings


def validate_evasion_section(evasion: dict[str, Any] | None) -> list[str]:
    """Return validation errors for profile evasion block."""
    if not evasion:
        return []
    errors: list[str] = []
    if im := evasion.get("inject_method"):
        if str(im).lower() not in VALID_INJECT_METHODS:
            errors.append(f"evasion.inject_method invalid: {im!r}")
    if st := evasion.get("sleep_technique"):
        st_norm = "zilean" if str(st).lower() == "timer" else str(st).lower()
        if st_norm not in VALID_SLEEP_TECHNIQUES:
            errors.append(f"evasion.sleep_technique invalid: {st!r}")
    if ab := evasion.get("amsi_bypass_method"):
        if str(ab).lower() not in VALID_AMSI_BYPASS:
            errors.append(f"evasion.amsi_bypass_method invalid: {ab!r}")
    return errors


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


_DEFAULT_IMPLANT_PATHS = frozenset([
    "/api/v1/checkin", "/api/v1/register", "/api/v1/result",
    "/api/v1/tunnel", "/api/v1/stage",
])


def _mutate_uri(uri: str, rng: "random.Random", mutation: dict[str, Any]) -> str:
    import hashlib, random
    if not uri:
        return uri
    suffixes = [s for s in (mutation.get("uri_suffixes") or [""]) if s]
    if not suffixes:
        suffixes = ["/v2", "/v3"]
    tokens = mutation.get("path_tokens") or ["x"]
    suffix = rng.choice(suffixes)
    if not uri.endswith("/") and not suffix.startswith("/"):
        uri = uri + suffix
    else:
        uri = uri.rstrip("/") + suffix
    if rng.random() < 0.45:
        token = rng.choice(tokens)
        seg = hashlib.sha256(str(rng.random()).encode()).hexdigest()[: rng.randint(6, 10)]
        uri = f"{uri.rstrip('/')}/{token}/{seg}"
    if uri in _DEFAULT_IMPLANT_PATHS:
        seg = hashlib.sha256(str(rng.random()).encode()).hexdigest()[:7]
        uri = f"{uri}/{rng.choice(tokens)}/{seg}"
    return uri


def _pick_wrap(rng: "random.Random", mutation: dict[str, Any]) -> tuple[str, str]:
    prep = rng.choice(mutation.get("prepend_pool") or [""])
    app = rng.choice(mutation.get("append_pool") or [""])
    return prep, app


def _mask_key(rng: "random.Random", mutation: dict[str, Any]) -> int:
    lo, hi = mutation.get("mask_key_range") or [1, 254]
    return rng.randint(int(lo), int(hi))


def mutate_profile(
    base: dict[str, Any],
    engagement_id: str,
    build_nonce: str,
) -> dict[str, Any]:
    """Return full malleable profile dict after deterministic mutation."""
    template = base.get("name", "default")
    rng = rng_for(engagement_id, template, build_nonce)
    p = deepcopy(base)
    mutation = p.pop("mutation", {}) or {}

    p["user_agent"] = mutate_user_agent(p.get("user_agent", ""), rng, mutation)

    for block_key in ("http_get", "http_post", "http_stager"):
        block = p.get(block_key)
        if not isinstance(block, dict):
            continue
        uris = block.get("uri") or []
        block["uri"] = [_mutate_uri(u, rng_sub(rng, f"{block_key}-{i}"), mutation) for i, u in enumerate(uris)]

        if block_key == "http_post":
            prep, app = _pick_wrap(rng, mutation)
            body = block.setdefault("body", {})
            if prep and not body.get("prepend"):
                body["prepend"] = prep
            if app and not body.get("append"):
                body["append"] = app
            if body.get("mask"):
                body["mask_key"] = _mask_key(rng, mutation)
            sout = block.setdefault("server_output", {})
            sp, sa = _pick_wrap(rng_sub(rng, "srv"), mutation)
            if sp and not sout.get("prepend"):
                sout["prepend"] = sp
            if sa and not sout.get("append"):
                sout["append"] = sa
            if sout.get("mask") or body.get("mask"):
                sout["mask"] = True
                sout["mask_key"] = body.get("mask_key", _mask_key(rng, mutation))

        headers = block.get("headers")
        if isinstance(headers, dict) and headers and rng.random() < 0.4:
            key = rng.choice(list(headers.keys()))
            val = headers[key]
            if isinstance(val, str) and ";" in val:
                headers[key] = val
            elif isinstance(val, str):
                headers[key] = f"{val};q={rng.randint(8, 10)}/10"

    fp_data = {
        "engagement_id": engagement_id,
        "template": template,
        "build_nonce": build_nonce,
        "user_agent": p.get("user_agent"),
        "http_get": p.get("http_get", {}).get("uri"),
        "http_post": p.get("http_post", {}).get("uri"),
    }
    p["profile_fingerprint"] = compute_fingerprint(fp_data)
    p["engagement_id"] = engagement_id
    p["build_nonce"] = build_nonce
    p["generated_at"] = utc_iso_now()
    p["name"] = f"{template}-{p['profile_fingerprint']}"
    return p


def _first_uri(block: dict[str, Any] | None, fallback: str) -> str:
    if not block:
        return fallback
    uris = block.get("uri") or []
    return uris[0] if uris else fallback


def _nth_uri(block: dict[str, Any] | None, n: int, fallback: str) -> str:
    if not block:
        return fallback
    uris = block.get("uri") or []
    if n < len(uris):
        return uris[n]
    return fallback


def to_overlay(profile: dict[str, Any]) -> dict[str, Any]:
    """Build JSON overlay for build_implant.py."""
    http_get = profile.get("http_get") or {}
    http_post = profile.get("http_post") or {}
    http_stager = profile.get("http_stager") or {}
    post_body = http_post.get("body") or {}
    post_out = http_post.get("server_output") or {}
    get_headers = http_get.get("headers") or {}
    post_headers = http_post.get("headers") or {}

    mask_key = post_body.get("mask_key") or post_out.get("mask_key") or 0

    http_headers = {
        "Accept": get_headers.get("Accept") or post_headers.get("Accept") or "application/json, */*",
        "Accept-Language": get_headers.get("Accept-Language") or "en-US,en;q=0.9",
    }
    for k, v in post_headers.items():
        if k.lower() not in ("host", "content-type"):
            http_headers[k] = v

    malleable_wire = {
        "out_base64": bool(post_body.get("base64")),
        "in_base64": bool(post_out.get("base64")),
        "out_prepend": post_body.get("prepend") or "",
        "out_append": post_body.get("append") or "",
        "in_prepend": post_out.get("prepend") or "",
        "in_append": post_out.get("append") or "",
        "mask_key": mask_key,
    }

    evasion = profile.get("evasion") or {}
    ioc = derive_ioc_artifacts(profile.get("engagement_id", ""), profile.get("build_nonce", ""))
    ioc.pop("aes_key", None)
    ioc.pop("aes_iv", None)

    overlay = {
        "user_agent": profile.get("user_agent", ""),
        "checkin_path": _first_uri(http_get, "/api/v1/checkin"),
        "register_path": _first_uri(http_post, "/api/v1/register"),
        "result_path": _nth_uri(http_post, 1, "/api/v1/result"),
        "stage1_path": _first_uri(http_stager, "/api/v1/stage"),
        "tunnel_path": _nth_uri(http_post, 2, "/api/v1/tunnel"),
        "profile_name": profile.get("name", "unknown"),
        "profile_fingerprint": profile.get("profile_fingerprint", ""),
        "engagement_id": profile.get("engagement_id", ""),
        "build_nonce": profile.get("build_nonce", ""),
        "sleep_time": profile.get("sleep_time", 60),
        "jitter": profile.get("jitter", 20),
        "malleable_wire": malleable_wire,
        "http_headers": http_headers,
        "evasion": evasion,
        "ioc": ioc,
        "spawn_to": profile.get("spawn_to") or {},
        "process_inject": profile.get("process_inject") or {},
    }

    if pin := profile.get("cert_pin_hash") or profile.get("cert_pin"):
        overlay["cert_pin_hash"] = pin
    if df := profile.get("domain_front"):
        overlay["domain_front"] = df

    return overlay


def to_malleable_json(profile: dict[str, Any]) -> dict[str, Any]:
    """Strip engine-only keys; emit teamserver-compatible profile."""
    out = deepcopy(profile)
    for k in ("mutation", "engagement_id", "build_nonce", "generated_at", "profile_fingerprint"):
        out.pop(k, None)
    return out


def list_arsenal(arsenal_dir: Path) -> list[str]:
    return sorted(p.stem for p in arsenal_dir.glob("*.yaml"))


def resolve_template(workspace: Path, override: str | None) -> str:
    if override:
        return override
    cfg = load_engagement_config(workspace)
    jager = cfg.get("jager") or {}
    prof = jager.get("profile") or {}
    return prof.get("template") or prof.get("arsenal") or "default"


def _safe_template_name(name: str) -> str:
    """Sanitize template name to prevent path traversal."""
    safe = re.sub(r'[/\\]', '', name)
    safe = safe.replace('..', '')
    if not re.match(r'^[a-zA-Z0-9_-]+$', safe):
        raise ValueError(f"Invalid template name: {name}")
    return safe


def generate_profile(
    *,
    workspace: Path,
    template: str,
    engagement_id: str,
    build_nonce: str,
    custom_yaml: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if custom_yaml and custom_yaml.exists():
        base = load_yaml(custom_yaml)
    else:
        safe_template = _safe_template_name(template)
        arsenal_path = workspace / "profiles" / "arsenal" / f"{safe_template}.yaml"
        if not arsenal_path.exists():
            raise FileNotFoundError(f"Arsenal template not found: {arsenal_path}")
        base = load_yaml(arsenal_path)

    mutated = mutate_profile(base, engagement_id, build_nonce)
    val_errors, val_warnings = validate_profile(mutated)
    if val_errors:
        raise ValueError(f"Profile validation failed: {val_errors}")
    for w in val_warnings:
        print(f"[!] profile warning: {w}", file=sys.stderr)
    overlay = to_overlay(mutated)
    malleable = to_malleable_json(mutated)
    return overlay, malleable


def main() -> int:
    parser = argparse.ArgumentParser(description="Jager-C2 engagement profile engine")
    parser.add_argument("--workspace", default=str(_repo_root()))
    parser.add_argument("--template", default=None, help="Arsenal template name (default.yaml -> default)")
    parser.add_argument("--engagement-id", default=None)
    parser.add_argument("--build-nonce", default=None)
    parser.add_argument("--custom-yaml", default=None, help="Engagement-specific profile YAML path")
    parser.add_argument("--overlay-out", required=True)
    parser.add_argument("--malleable-out", required=True)
    parser.add_argument("--list-arsenal", action="store_true")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    arsenal_dir = workspace / "profiles" / "arsenal"

    if args.list_arsenal:
        print(json.dumps({"arsenal": list_arsenal(arsenal_dir)}, indent=2))
        return 0

    engagement_id = resolve_engagement_id(workspace, args.engagement_id)
    template = resolve_template(workspace, args.template)
    build_nonce = args.build_nonce or secrets.token_hex(8)
    custom = Path(args.custom_yaml) if args.custom_yaml else None

    overlay, malleable = generate_profile(
        workspace=workspace,
        template=template,
        engagement_id=engagement_id,
        build_nonce=build_nonce,
        custom_yaml=custom,
    )

    overlay_path = Path(args.overlay_out)
    malleable_path = Path(args.malleable_out)
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    malleable_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_text(json.dumps(overlay, indent=2), encoding="utf-8")
    malleable_path.write_text(json.dumps(malleable, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "success": True,
                "engagement_id": engagement_id,
                "template": template,
                "build_nonce": build_nonce,
                "profile_fingerprint": overlay.get("profile_fingerprint"),
                "profile_name": overlay.get("profile_name"),
                "overlay_out": str(overlay_path),
                "malleable_out": str(malleable_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
