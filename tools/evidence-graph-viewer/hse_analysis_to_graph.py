#!/usr/bin/env python3
"""Offline, evidence-conservative Huntsman /api/analyze -> graph-demo JSON adapter.

No network access or invented verification. Tested against the publicly documented
AnalysisView, Entity and EntityRelation serialisation structures from huntsman-recon.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

MAX_INPUT = 8_000_000
MAX_NODES, MAX_EDGES = 250, 700


def bounded(value, limit=1500):
    return str(value if value is not None else "")[:limit]


def year_from_unix(value):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    try:
        year = datetime.fromtimestamp(value, tz=timezone.utc).year
    except (OverflowError, OSError, ValueError):
        return None
    return year if 1900 <= year <= 2200 else None


def safe_id(raw):
    return "ent_" + hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def convert(data):
    if not isinstance(data, dict):
        raise ValueError('Expected JSON object returned by Huntsman /api/analyze')
    if data.get('truncated') is True:
        raise ValueError('Upstream analysis is truncated: refusing a graph missing entities or links')
    entities, relations = data.get('entities'), data.get('relations')
    if not isinstance(entities, list) or not isinstance(relations, list):
        raise ValueError('Expected entities[] and relations[] from /api/analyze')
    if len(entities) > MAX_NODES or len(relations) > MAX_EDGES:
        raise ValueError(f'Graph exceeds viewer bounds ({MAX_NODES} nodes, {MAX_EDGES} relations); no silent truncation')
    nodes, edges, ids = [], [], {}
    for e in entities:
        if not isinstance(e, dict):
            raise ValueError('Entity must be an object')
        uid = e.get('uid')
        kind = e.get('kind')
        value = e.get('value')
        if not all(isinstance(x, str) for x in (uid,kind,value)) or not uid or not value:
            raise ValueError('Entity requires nonempty uid, kind and value strings')
        if uid in ids:
            raise ValueError(f'Duplicate native entity uid: {uid[:70]}')
        nid = safe_id(uid)
        if nid in ids.values():
            raise ValueError('Entity identifier hash collision')
        ids[uid] = nid
        node_type = 'person' if kind=='person' else 'organisation' if kind=='organisation' else 'asset'
        date = year_from_unix(e.get('observed_at_unix'))
        confidence = e.get('confidence')
        summary = (f'Huntsman {kind} entity. Native confidence: {confidence if isinstance(confidence,(int,float)) else "unknown"}. '
                   f'Operator input and automated scoring are not independent verification. Original UID: {uid}')
        nodes.append({'id':nid,'label':bounded(value,160),'type':node_type,
                      'year':date,'summary':bounded(summary)})
    for i, r in enumerate(relations):
        if not isinstance(r,dict):
            raise ValueError('Relation must be an object')
        src, dest = r.get('from_uid'),r.get('to_uid')
        if src not in ids or dest not in ids:
            raise ValueError('Relation references unknown entity uid; refusing to drop it')
        ev=r.get('evidence', [])
        if not isinstance(ev,list):
            raise ValueError('Relation evidence must be a list')
        names=[]; dates=[]; summaries=[]
        for proof in ev:
            if not isinstance(proof,dict):
                raise ValueError('Invalid relation evidence record')
            prov=proof.get('provenance',{})
            if not isinstance(prov,dict):
                raise ValueError('Invalid evidence provenance')
            source=prov.get('source')
            if isinstance(source,str) and source and source not in names:
                names.append(source)
            timestamp=year_from_unix(prov.get('recorded_at_unix'))
            if timestamp is not None:
                dates.append(timestamp)
            if isinstance(proof.get('summary'),str):
                summaries.append(proof['summary'])
        label=r.get('label') or r.get('kind') or 'unspecified_relationship'
        note='Unverified relationship projection from Huntsman analysis. Native confidence is NOT a source-verification verdict.'
        if summaries: note+=' Evidence summaries: '+ ' | '.join(summaries[:3])
        edges.append({
            'id':f'relation_{i+1}', 'source':ids[src],'target':ids[dest],
            'relation':bounded(label,160), 'status':'hypothetical',
            'year':min(dates) if dates else None,
            'source_name':bounded(', '.join(names) if names else 'No relation-level source in analysis'),
            'reference':bounded(f'Native relation index {i+1}; sources are provenance labels, not document citations'),
            'note':bounded(note)})
    return {'nodes':nodes,'edges':edges, 'metadata':{
        'generated_by':'hse_analysis_to_graph.py',
        'origin':'huntsman-recon /api/analyze (offline analytical projection)',
        'not_source_verified':True,
        'upstream_termination': bounded(data.get('termination','not provided'),160),
        'date_semantics':'null means unknown; no invented observation date',
        'relation_status_semantics':'all projected links hypothetical pending independent verification',
    }}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path,help='Saved JSON body from Huntsman GET /api/analyze')
    p.add_argument('-o','--output',type=Path,required=True,help='Graph viewer import JSON')
    args=p.parse_args()
    try:
        if args.input.stat().st_size > MAX_INPUT:
            raise ValueError(f'Input exceeds {MAX_INPUT} bytes')
        obj=json.loads(args.input.read_text(encoding='utf-8'))
        result=convert(obj)
        encoded=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
        if len(encoded.encode('utf-8'))>250_000:
            raise ValueError('Converted result exceeds graph viewer import limit; refusing truncation')
        args.output.write_text(encoded,encoding='utf-8')
        print(f'Converted {len(result["nodes"])} entities and {len(result["edges"])} links; verification labels remain hypothetical.',file=sys.stderr)
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        print(f'REFUSED: {exc}',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(main())