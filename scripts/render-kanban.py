#!/usr/bin/env python3
"""Render REST issue JSON to a deterministic, injection-safe Markdown board."""
import argparse
import html
import json
from pathlib import Path
import re

COLUMNS = ('Backlog', 'Ready', 'In Progress', 'In Review', 'Done')
STATUSES = dict(zip(('status/backlog', 'status/ready', 'status/in-progress',
                     'status/in-review'), COLUMNS))
MARKER = '<!-- jager-kanban-dashboard -->'


def names(item):
    return {label['name'] if isinstance(label, dict) else label
            for label in item.get('labels', [])}


def classify(item):
    if item.get('state') == 'closed':
        return 'Done', []
    statuses = sorted(label for label in names(item) if label.startswith('status/'))
    if len(statuses) > 1:
        return 'Backlog', ['conflicting status labels']
    if statuses and statuses[0] not in STATUSES:
        return 'Backlog', ['unknown status label']
    return STATUSES.get(statuses[0], 'Backlog') if statuses else 'Backlog', []


def escape(value):
    value = ' '.join(str(value).split())
    # Entities keep labels inert in table cells and avoid notification mentions.
    return ''.join(f'&#{ord(char)};' if char in '|[]()@`*_' else html.escape(char)
                   for char in value)


def render(issues, repository, dashboard_number):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('repository must be owner/name')
    if not isinstance(issues, list):
        raise ValueError('expected an issue list')
    groups = {column: [] for column in COLUMNS}
    warnings, seen, owners = [], set(), {}
    def priority(item):
        labels = names(item)
        return next((i for i in (1, 2, 3) if f'priority/p{i}' in labels), 4)
    for item in issues:
        number = item.get('number')
        if type(number) is not int or number <= 0:
            raise ValueError('issue number must be a positive integer')
    for item in sorted(issues, key=lambda item: (priority(item), item['number'])):
        number = item['number']
        if number == dashboard_number or 'pull_request' in item or number in seen:
            continue
        seen.add(number)
        column, problems = classify(item)
        warnings.extend(f'#{number}: {problem}' for problem in problems)
        title = escape(item.get('title', 'Untitled'))
        url = f'https://github.com/{repository}/issues/{number}'
        labels = names(item)
        suffix = ' **blocked**' if 'blocked' in labels else ''
        groups[column].append(f'[#'+str(number)+f' {title}]({url}){suffix}')
        if column == 'In Progress':
            assignees = item.get('assignees') or []
            if not assignees:
                warnings.append(f'#{number}: In Progress has no owner')
            for assignee in assignees:
                owners.setdefault(assignee['login'], []).append(number)
    for owner, numbers in sorted(owners.items()):
        if len(numbers) > 1:
            warnings.append(f'WIP limit: {escape(owner)} owns '+
                            ', '.join(f'#{n}' for n in numbers))
    lines = [MARKER, '# Jager-C2 development Kanban', '',
             'Issue labels are the source of truth. Move work by replacing its status label.',
             'Docs → failing tests → implementation → review → merge.', '',
             '| '+' | '.join(COLUMNS)+' |', '| '+' | '.join('---' for _ in COLUMNS)+' |']
    rows = max((len(items) for items in groups.values()), default=0)
    for row in range(rows):
        lines.append('| '+' | '.join(groups[column][row] if row < len(groups[column])
                                    else '—' for column in COLUMNS)+' |')
    if not seen:
        lines.extend(['', 'No work items.'])
    lines.extend(['', '## Workflow checks', ''])
    lines.extend('- '+warning for warning in warnings)
    if not warnings:
        lines.append('No status conflicts or owner WIP violations in this snapshot.')
    lines.extend(['', '**Closed items require review:** Done reflects issue closure; confirm merged',
                  'delivery and acceptance evidence in the issue before treating it as shipped.', '',
                  f'[Development process](https://github.com/{repository}/blob/main/docs/DEVELOPMENT.md)',
                  '· [Release gates](https://github.com/'+repository+'/blob/main/docs/RELEASE_READINESS.md)', '',
                  'Automation refreshes on issue opening, labeling, closing/reopening and manual dispatch.',
                  'Title, description or assignee-only edits require a manual refresh.'])
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--dashboard', type=int, required=True)
    args = parser.parse_args()
    args.output.write_text(render(json.loads(args.input.read_text()),
                                 args.repository, args.dashboard), encoding='utf-8')


if __name__ == '__main__':
    main()
