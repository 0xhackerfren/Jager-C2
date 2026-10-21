"""Behavioral contracts for the issue board and local documentation checks."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


board = load('kanban', 'render-kanban.py')
links = load('doclinks', 'check-doc-links.py')


def issue(number, labels=(), state='open', title=None, **extra):
    return dict(number=number, title=title or f'Work {number}',
                labels=[{'name': label} for label in labels], state=state,
                assignees=[], **extra)


class BoardTests(unittest.TestCase):
    def render(self, issues):
        return board.render(issues, '0xhackerfren/Jager-C2', 12)

    def test_all_columns_and_unlabeled_backlog(self):
        result = self.render([issue(1)])
        self.assertIn('| Backlog | Ready | In Progress | In Review | Done |', result)
        self.assertIn('[#1 Work 1]', result)

    def test_state_classification(self):
        for label, column in [('status/backlog', 'Backlog'), ('status/ready', 'Ready'),
                              ('status/in-progress', 'In Progress'),
                              ('status/in-review', 'In Review')]:
            self.assertEqual(board.classify(issue(1, [label]))[0], column)

    def test_closed_issue_is_done(self):
        self.assertEqual(board.classify(issue(1, ['status/ready'], 'closed'))[0], 'Done')

    def test_conflicting_status_is_visible(self):
        result = self.render([issue(1, ['status/ready', 'status/in-progress'])])
        self.assertIn('conflicting status labels', result)

    def test_priority_and_number_order(self):
        result = self.render([issue(4), issue(3, ['priority/p1']), issue(2, ['priority/p1'])])
        self.assertLess(result.index('[#2 '), result.index('[#3 '))
        self.assertLess(result.index('[#3 '), result.index('[#4 '))

    def test_exclude_dashboard_and_pull_requests(self):
        result = self.render([issue(12), issue(13, pull_request={}), issue(14)])
        self.assertNotIn('[#12 ', result)
        self.assertNotIn('[#13 ', result)
        self.assertIn('[#14 ', result)

    def test_duplicate_inputs_are_deduplicated(self):
        self.assertEqual(self.render([issue(1), issue(1)]).count('[#1 '), 1)

    def test_title_cannot_inject_markup_or_mentions(self):
        result = self.render([issue(1, title='<img>|[x](https://evil)\n@everyone')])
        self.assertNotIn('<img>', result)
        self.assertNotIn('@everyone', result)
        self.assertNotIn('](https://evil)', result)

    def test_wip_violation_is_reported(self):
        items = [issue(i, ['status/in-progress']) for i in (1, 2)]
        for item in items:
            item['assignees'] = [{'login': 'maintainer'}]
        self.assertIn('WIP limit', self.render(items))

    def test_unassigned_work_is_reported(self):
        self.assertIn('no owner', self.render([issue(1, ['status/in-progress'])]))

    def test_blocked_label_visible(self):
        self.assertIn('blocked', self.render([issue(1, ['blocked'])]))

    def test_invalid_repository_rejected(self):
        with self.assertRaises(ValueError):
            board.render([], 'https://evil', 12)

    def test_invalid_issue_number_rejected(self):
        with self.assertRaises(ValueError):
            self.render([issue('bad')])

    def test_unknown_status_reported(self):
        self.assertIn('unknown status', self.render([issue(1, ['status/imaginary'])]))

    def test_empty_board(self):
        self.assertIn('No work items', self.render([]))


class DocumentationTests(unittest.TestCase):
    def test_existing_relative_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('[guide](docs/guide.md#usage)')
            (root / 'docs').mkdir()
            (root / 'docs/guide.md').write_text('# Guide')
            self.assertEqual(links.check(root), [])

    def test_missing_link_reported_with_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('[broken](missing.md)')
            self.assertIn('README.md', '\n'.join(links.check(root)))

    def test_external_anchor_and_code_examples_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text(
                '[web](https://example.com) [jump](#heading)\n```md\n[x](fake.md)\n```')
            self.assertEqual(links.check(root), [])

    def test_markdown_target_with_parentheses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('[guide](<guide(v2).md>)')
            (root / 'guide(v2).md').write_text('# Guide')
            self.assertEqual(links.check(root), [])


if __name__ == '__main__':
    unittest.main()
