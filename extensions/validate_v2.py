#!/usr/bin/env python3
"""Endpoint and plaintext-capture validation; unknown measurements remain null.

Provide receiver logs for every destination with an OPEN UDP service. Closed
port scenarios intentionally have no receive event and are not delivery tests.
"""
import argparse,json,hashlib,statistics
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from pcapio import packets
from traffic_v2 import parse_payload

def load_logs(paths):
    result=[]
    for path in paths:
        with open(path,encoding='utf-8') as f:
            for i,line in enumerate(f,1):
                r=json.loads(line)
                if r.get('schema')!='net074.log.v2': raise ValueError(f'{path}:{i}: schema mismatch')
                result.append(r)
    return result

def key(r): return (r['acquisition_id'],r['seq'])

def check_capture(paths,expected):
    if not paths: return None
    seen=Counter();mismatch=0;truncated=0;fragmented=0
    for path in paths:
        for p in packets(path):
            truncated+=int(p['truncated']);fragmented+=int(p['fragment'])
            if p['proto']!=17 or p.get('dport')!=50074: continue
            ident=parse_payload(p.get('udp_payload',b''))
            if not ident: continue
            k=key(ident);seen[k]+=1;truth=expected.get(k)
            if truth and (hashlib.sha256(p['udp_payload']).hexdigest()!=truth.get('sha256') or p['dst']!=truth['dst'] or ident['code']!=truth['code']): mismatch+=1
    return dict(unique=len(seen),missing=len(set(expected)-set(seen)),unexpected=len(set(seen)-set(expected)),duplicates=sum(n-1 for n in seen.values()),mismatch=mismatch,truncated=truncated,fragmented=fragmented)

def validate(sent_path,received_paths=(),pre=(),post=()):
    sent_rows=load_logs([sent_path]);starts=[r for r in sent_rows if r['kind']=='sender_start']
    if len(starts)!=1: raise ValueError('Exactly one acquisition per sender log is required')
    aid=starts[0]['acquisition_id'];success=[r for r in sent_rows if r['kind']=='send' and r['success']]
    expected={key(r):r for r in success}
    if len(expected)!=len(success): raise ValueError('Duplicate sender identities')
    rec=[r for r in load_logs(received_paths) if r['kind']=='receive' and r.get('acquisition_id')==aid] if received_paths else []
    seen=Counter(key(r) for r in rec);received=set(seen)&set(expected)
    mismatch=sum(r.get('sha256')!=expected[key(r)].get('sha256') or r.get('code')!=expected[key(r)]['code'] for r in rec if key(r) in expected)
    replies=[r for r in sent_rows if r['kind']=='reply' and r['valid']]
    reply_ids={key(r) for r in replies}&set(expected)
    times=[r['monotonic_ns'] for r in sent_rows if r['kind'] in ('sender_start','sender_stop')]
    elapsed=(max(times)-min(times))/1e9 if len(times)>=2 else None
    precheck=check_capture(pre,expected);postcheck=check_capture(post,expected)
    receiver_complete=bool(received_paths)
    for path in received_paths:
        kinds=[r['kind'] for r in load_logs([path])]
        receiver_complete=receiver_complete and 'receiver_start' in kinds and 'receiver_stop' in kinds
    sender_complete=any(r['kind']=='sender_stop' for r in sent_rows)
    linked=bool(receiver_complete and sender_complete and precheck is not None and postcheck is not None)
    quality=linked and all(v==0 for c in (precheck,postcheck) for k,v in c.items() if k not in ('unique',)) and mismatch==0 and not (set(expected)-received) and not (set(seen)-set(expected)) and all(n==1 for n in seen.values())
    return dict(acquisition_id=aid,sent_success=len(expected),send_errors=sum(r['kind']=='send' and not r['success'] for r in sent_rows),
                receiver_unique=len(received) if received_paths else None,receiver_missing=len(set(expected)-received) if received_paths else None,
                receiver_loss_pct=100*len(set(expected)-received)/len(expected) if expected and received_paths else None,
                receiver_duplicates=sum(n-1 for n in seen.values()) if received_paths else None,receiver_unexpected=len(set(seen)-set(expected)) if received_paths else None,
                receiver_payload_mismatches=mismatch if received_paths else None,replies_unique=len(reply_ids),
                duplicate_replies=len(replies)-len(reply_ids),rtt_median_ms=statistics.median(r['rtt_ms'] for r in replies) if replies else None,
                echo_goodput_bps=8*sum(expected[k]['bytes'] for k in reply_ids)/elapsed if elapsed else None,
                goodput_window='sender_start to sender_stop including grace',pre_encryption=precheck,post_decryption=postcheck,
                receiver_log_complete=receiver_complete,sender_log_complete=sender_complete,independent_packet_evidence_complete=linked,all_packets_accounted_for=bool(quality),
                note='This report does not infer ESP plaintext or gateway CPU. Use all open-service receiver logs; no losses are inferred from absent logs.')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sent',required=True);p.add_argument('--received',nargs='+',default=[]);p.add_argument('--pre',nargs='+',default=[]);p.add_argument('--post',nargs='+',default=[]);p.add_argument('--out',required=True);a=p.parse_args()
    r=validate(a.sent,a.received,a.pre,a.post)
    with open(a.out,'x',encoding='utf-8') as f: json.dump(r,f,ensure_ascii=False,indent=2)
    print(json.dumps(r,ensure_ascii=False,indent=2))
