"""Simulated CLI tests: not evidence of a live Android Wi-Fi audit."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'termux' / 'mitm-eligibility.sh'


def ap(name='Office', bssid='02:11:22:33:44:55', freshness='os_cached', age=30):
    return {'sighting': {'name': name, 'network_id': bssid}, 'freshness': freshness,
            'age_secs': age, 'os_timestamp_us': 42, 'capabilities': '[WPA2-PSK-CCMP]'}


def capture(rows=None, evaluated=0, source='termux-wifi-scaninfo', status='os_cached', rejected=0, findings=None):
    rows = rows if rows is not None else [ap()]
    return {'source': source, 'acquisition': 'android_cached_scan_results_not_active_scan',
            'observed': len(rows), 'status': status, 'rejected': rejected, 'observations': rows,
            'mitm_assessment': {'source': source, 'status': ('inconclusive' if evaluated == 0
                              else 'unconfirmed_indicators' if findings else 'no_specific_indicators_observed'),
                              'evaluated_access_points': evaluated, 'rejected_records': rejected,
                              'mitm_confirmed': False, 'findings': findings or []}}


class TestRefactor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hse-mitm-refactor-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'bin').mkdir()
        (self.root/'state').mkdir()
        mock = self.root/'bin'/'huntsman'
        mock.write_text('#!/bin/sh\ncat "$MOCK_RADAR_FILE"\nexit "${MOCK_RC:-0}"\n')
        mock.chmod(0o755)

    def run_case(self, data, rc=0):
        raw = self.root/'input.json'
        raw.write_text(json.dumps(data) if not isinstance(data, str) else data)
        env = {**os.environ, 'PATH': f'{self.root}/bin:' + os.environ['PATH'],
               'MOCK_RADAR_FILE': str(raw), 'MOCK_RC': str(rc),
               'HUNTSMAN_HOME': str(self.root/'state'), 'TMPDIR': str(self.root)}
        result = subprocess.run(['bash', str(SCRIPT)], capture_output=True, text=True, env=env, timeout=15)
        output = None
        if '{' in result.stdout:
            output = json.loads(result.stdout[result.stdout.find('{'):])
        for sensitive in ('Office', '02:11:22:33:44:55'):
            self.assertNotIn(sensitive, result.stdout)
            self.assertNotIn(sensitive, result.stderr)
        reports = sorted((self.root/'state').glob('mitm-eligibility.*.json'))
        if output is not None:
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(reports[0].read_text()), output)
            for sensitive in ('Office', '02:11:22:33:44:55'):
                self.assertNotIn(sensitive, reports[0].read_text())
        return result, output

    def test_visible_fresh(self):
        r, d = self.run_case(capture(evaluated=1))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['eligibility']['predicted_unique_eligible'], 1)
        self.assertTrue(d['eligibility']['agrees'])

    def test_stale_two(self):
        r, d = self.run_case(capture([ap(freshness='stale', age=600), ap(freshness='stale', age=800)], status='stale_only'), 69)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['stale'], 2)
        self.assertEqual(d['conclusion'], 'INCONCLUSIVE_ZERO_EVALUATED')

    def test_unknown_two(self):
        r, d = self.run_case(capture([ap(freshness='unknown', age=None), ap(freshness='unknown', age=None)], status='freshness_unknown'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['freshness_unknown'], 2)

    def test_hidden_and_missing(self):
        r, d = self.run_case(capture([ap(name='(hidden)'), ap(name='(no SSID)'), ap(name='')]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['hidden_ssid'], 2)
        self.assertEqual(d['exclusions']['missing_ssid'], 1)

    def test_unicode_byte_limit(self):
        r, d = self.run_case(capture([ap(name='é'*17)]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['oversized_ssid'], 1)

    def test_duplicate(self):
        r, d = self.run_case(capture([ap(), ap()], evaluated=1))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['eligibility']['duplicate_rows'], 1)

    def test_mac_case_folding(self):
        r, d = self.run_case(capture([ap(bssid='02:AA:BB:CC:DD:EE'), ap(bssid='02:aa:bb:cc:dd:ee')], evaluated=1))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['eligibility']['duplicate_rows'], 1)

    def test_invalid_group_bssid(self):
        r, d = self.run_case(capture([ap(bssid='03:11:22:33:44:55')]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['invalid_bssid'], 1)

    def test_invalid_redacted_bssid(self):
        r, d = self.run_case(capture([ap(bssid='02:00:00:00:00:00')]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['exclusions']['invalid_bssid'], 1)

    def test_mismatch_exits_nonzero(self):
        r, d = self.run_case(capture(evaluated=0))
        self.assertEqual(r.returncode, 24, r.stderr)
        self.assertEqual(d['conclusion'], 'COUNT_MISMATCH')

    def test_no_records(self):
        r, d = self.run_case(capture([], status='inconclusive'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['conclusion'], 'INCONCLUSIVE_ZERO_EVALUATED')

    def test_raw_rejected_only(self):
        r, d = self.run_case(capture([], rejected=2, status='inconclusive'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['raw_records_rejected_by_rust'], 2)

    def test_unconfirmed_findings(self):
        findings=[{'code':'unverified_ssid_security_variation','severity':'review', 'ssid':'Office', 'bssid':'02:11:22:33:44:55'}]
        r, d=self.run_case(capture(evaluated=1,findings=findings))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d['conclusion'], 'UNCONFIRMED_INDICATORS')
        self.assertEqual(d['mitm']['unconfirmed_finding_count'], 1)

    def test_inconsistent_rc(self):
        r, d=self.run_case(capture(evaluated=1), rc=69)
        self.assertEqual(r.returncode, 25, r.stderr)
        self.assertTrue(d['eligibility']['agrees'])

    def test_invalid_json(self):
        r,d=self.run_case('{not JSON')
        self.assertEqual(r.returncode, 22)
        self.assertIsNone(d)

    def test_refuse_replay(self):
        r,d=self.run_case(capture(source='unverified_json_file'))
        self.assertEqual(r.returncode, 22)
        self.assertIsNone(d)

    def test_reject_wrong_observed(self):
        obj=capture()
        obj['observed']=6
        r,d=self.run_case(obj)
        self.assertEqual(r.returncode, 22)

    def test_reject_wrong_rejected(self):
        obj=capture()
        obj['mitm_assessment']['rejected_records']=2
        r,d=self.run_case(obj)
        self.assertEqual(r.returncode, 22)

    def test_empty_stdout(self):
        r,d=self.run_case('')
        self.assertEqual(r.returncode, 21)


if __name__=='__main__':
    unittest.main(verbosity=2)
