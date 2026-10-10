#!/usr/bin/env python3
"""Refuse partial, inconsistent or falsely green LLVM report inputs."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-source-coverage.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SOURCE = '/workspace/src/example.rs'
LCOV = f'SF:{SOURCE}\nDA:1,1\nDA:2,2\nBRDA:1,0,0,1\nBRDA:1,0,1,1\nLF:2\nLH:2\nBRF:2\nBRH:2\nend_of_record\n'
TEXT = f'{SOURCE}:\n 1| 1|source\n 2| 2|source\n'
RAW = {'type': 'llvm.coverage.json.export', 'data': [{'files': [{
    'filename': SOURCE, 'branches': [[1, 1, 1, 2, 1, 1]],
    'summary': {'lines': {'count': 2, 'covered': 2}, 'branches': {'count': 2, 'covered': 2}}
}]}]}

class GateTests(unittest.TestCase):
    def check(self, lcov=LCOV, raw=None, text=TEXT):
        with contextlib.redirect_stdout(io.StringIO()):
            gate.check(lcov, RAW if raw is None else raw, '/workspace', text)

    def test_complete_source_report(self):
        self.check()

    def test_single_file_upstream_report_without_heading(self):
        self.check(text=TEXT.split('\n', 1)[1])
        raw = copy.deepcopy(RAW)
        other = copy.deepcopy(raw['data'][0]['files'][0])
        other['filename'] = '/workspace/src/other.rs'
        raw['data'][0]['files'].append(other)
        with self.assertRaises(ValueError):
            self.check(lcov=LCOV + LCOV.replace(SOURCE, other['filename']), raw=raw,
                       text=TEXT.split('\n', 1)[1])

    def test_malformed_or_missing_records(self):
        for data in ['', LCOV.replace('DA:2,2\n', ''), LCOV.replace('end_of_record\n', ''),
                     LCOV + LCOV, LCOV.replace('DA:1,1', 'DA:1,-1'),
                     LCOV.replace('DA:2,2', 'DA:1,1'),
                     LCOV.replace('BRDA:1,0,1,1\n', ''),
                     LCOV.replace('BRDA:1,0,1,1', 'BRDA:2,0,1,1'),
                     LCOV.replace('LH:2', 'LH:1'), LCOV + 'unexpected\n']:
            with self.subTest(data=data), self.assertRaises((ValueError, KeyError)):
                self.check(lcov=data)

    def test_uncovered_and_forged_counters(self):
        with self.assertRaises(ValueError):
            self.check(lcov=LCOV.replace('DA:2,2', 'DA:2,0'), text=TEXT.replace('2| 2|', '2| 0|'))
        with self.assertRaises(ValueError):
            self.check(lcov=LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0'))
        with self.assertRaises(ValueError):
            self.check(text=TEXT.replace('2| 2|', '2| 0|'))

    def test_missing_or_duplicate_raw_inventory(self):
        for raw in [{'type': 'llvm.coverage.json.export', 'data': []},
                    {'type': 'llvm.coverage.json.export', 'data': [{'files': []}]}]:
            with self.assertRaises(ValueError): self.check(raw=raw)
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'].append(copy.deepcopy(raw['data'][0]['files'][0]))
        with self.assertRaises(ValueError): self.check(raw=raw)

    def test_missing_or_duplicate_annotated_inventory(self):
        for text in ['', TEXT + TEXT, TEXT.replace(' 2| 2|source\n', '')]:
            with self.assertRaises(ValueError): self.check(text=text)

if __name__ == '__main__':
    unittest.main()
