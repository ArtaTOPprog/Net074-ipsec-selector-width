#!/usr/bin/env python3
"""Compare independently recomputed archived results with committed reference tables."""
import argparse,csv,json,math
from pathlib import Path

FILES=('runs.csv','statistics.csv','icmp_evidence.csv','plain_packet_validation.csv','sha256.csv','audit.json')

def compare(a,b,path=''):
    if isinstance(a,dict) and isinstance(b,dict):
        if a.keys()!=b.keys():raise ValueError(f'{path}: different fields')
        for k in a:compare(a[k],b[k],path+'/'+str(k))
    elif isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b):raise ValueError(f'{path}: different row count')
        for i,(x,y) in enumerate(zip(a,b)):compare(x,y,path+'/'+str(i))
    elif a!=b:
        try:equal=math.isclose(float(a),float(b),rel_tol=1e-10,abs_tol=1e-8)
        except (TypeError,ValueError):equal=False
        if not equal:raise ValueError(f'{path}: actual={a!r}, expected={b!r}')

def load(path):
    if path.suffix=='.json':return json.loads(path.read_text(encoding='utf-8'))
    with path.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--actual',required=True,type=Path);p.add_argument('--expected',required=True,type=Path);a=p.parse_args()
    for name in FILES:compare(load(a.actual/name),load(a.expected/name),name)
    print(f'OK: {len(FILES)} result files match the reference')
