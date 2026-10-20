"""Deterministic offline validation of Huntsman AnalysisView JSON projection."""
import json
from pathlib import Path
import unittest
from copy import deepcopy
from hse_analysis_to_graph import convert, MAX_NODES, MAX_EDGES

F=Path(__file__).with_name('fixture_analysis.json')
BASE=json.loads(F.read_text(encoding='utf-8'))

class AdapterTests(unittest.TestCase):
    def test_valid_projection_preserves_uid_relationship(self):
        out=convert(BASE)
        self.assertEqual(len(out['nodes']),2)
        self.assertEqual(len(out['edges']),1)
        self.assertIn(out['edges'][0]['source'],[n['id'] for n in out['nodes']])
        self.assertIn(out['edges'][0]['target'],[n['id'] for n in out['nodes']])
    def test_unknown_dates_are_null(self):
        out=convert(BASE)
        self.assertTrue(all(n['year'] is None for n in out['nodes']))
        self.assertIsNone(out['edges'][0]['year'])
    def test_native_confidence_does_not_verify(self):
        d=deepcopy(BASE)
        d['relations'][0]['confidence']=1.0
        d['relations'][0]['evidence'][0]['verification']={'SomeMethod':'claimed'}
        self.assertEqual(convert(d)['edges'][0]['status'],'hypothetical')
    def test_real_observation_year(self):
        d=deepcopy(BASE);d['entities'][0]['observed_at_unix']=1704067200
        d['relations'][0]['evidence'][0]['provenance']['recorded_at_unix']=1704067200
        out=convert(d)
        self.assertEqual(out['nodes'][0]['year'],2024)
        self.assertEqual(out['edges'][0]['year'],2024)
    def test_refuse_missing_keys(self):
        with self.assertRaisesRegex(ValueError,'Expected entities'):
            convert({'entities':[]})
    def test_refuse_truncated(self):
        d=deepcopy(BASE);d['truncated']=True
        with self.assertRaisesRegex(ValueError,'truncated'):
            convert(d)
    def test_refuse_orphan_edge(self):
        d=deepcopy(BASE);d['relations'][0]['to_uid']='missing'
        with self.assertRaisesRegex(ValueError,'unknown entity'):
            convert(d)
    def test_refuse_duplicate_uid(self):
        d=deepcopy(BASE);d['entities'].append(deepcopy(d['entities'][0]))
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            convert(d)
    def test_refuse_excess_nodes(self):
        d=deepcopy(BASE);d['entities']=[dict(BASE['entities'][0],uid=f'u{i}') for i in range(MAX_NODES+1)];d['relations']=[]
        with self.assertRaisesRegex(ValueError,'viewer bounds'):
            convert(d)
    def test_refuse_excess_edges(self):
        d=deepcopy(BASE);d['relations']=[deepcopy(BASE['relations'][0]) for _ in range(MAX_EDGES+1)]
        with self.assertRaisesRegex(ValueError,'viewer bounds'):
            convert(d)
    def test_no_invented_document_reference(self):
        out=convert(BASE)
        self.assertIn('not document citations',out['edges'][0]['reference'])
    def test_escape_untrusted_label_later_by_viewer(self):
        d=deepcopy(BASE);d['entities'][0]['value']='<script>alert(1)</script>'
        out=convert(d)
        self.assertEqual(out['nodes'][0]['label'],'<script>alert(1)</script>')
        # Viewer renders labels with SVG textContent and does not interpret markup.

if __name__=='__main__':
    unittest.main(verbosity=2)