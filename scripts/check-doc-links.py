#!/usr/bin/env python3
"""Check local inline Markdown document links; no external network access."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def check(root):
    errors = []
    paths = sorted(root.glob('*.md')) + sorted((root / 'docs').rglob('*.md'))
    for source in paths:
        text = re.sub(r'```[^\n]*\n.*?```', '', source.read_text(encoding='utf-8'), flags=re.S)
        for match in re.finditer(r'\[[^\]\n]*\]\(\s*(?:<([^>]+)>|([^\s)]+))\s*\)', text):
            target = match.group(1) or match.group(2)
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = source.parent / unquote(parsed.path)
            if not destination.exists():
                errors.append(f'{source.relative_to(root)}: missing {target}')
    return errors


if __name__ == '__main__':
    errors = check(Path(__file__).resolve().parents[1])
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        sys.exit(1)
    print('Local Markdown links OK')
