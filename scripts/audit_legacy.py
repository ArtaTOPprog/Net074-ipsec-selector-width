#!/usr/bin/env python3
"""Reproduce aggregate results and audit evidence without claiming delivery or ESP packet truth."""
import argparse,csv,json,random,re,hashlib,statistics,math
from pathlib import Path
from collections import Counter,defaultdict
from pcapio import packets,CaptureError

DESTS={'P':('192.168.20.10',200,.40),'N1':('192.168.20.20',400,.15),
       'N2':('192.168.20.30',600,.15),'E1':('203.0.113.10',800,.15),'E2':('198.51.100.10',1000,.15)}
BYIP={v[0]:k for k,v in DESTS.items()}
TAG=re.compile(rb'^NET25-038\|(S[123]-\d\d)\|(\d+)\|(P|N1|N2|E1|E2)\|')
T15=2.1447866879169273

def classify_length(length,mapping):
    candidates=mapping.get(length,[])
    return candidates[0] if len(candidates)==1 else None

def write_csv(path,rows):
    if not rows: return
    with path.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def summary(v):
    if len(v)!=15: raise ValueError('This protocol requires exactly 15 independent runs per selector')
    m=statistics.mean(v);sd=statistics.stdev(v);h=T15*sd/math.sqrt(len(v))
    return dict(n=len(v),mean=m,sd=sd,ci95_low=m-h,ci95_high=m+h)

def audit(root,out):
    root=Path(root);out=Path(out);out.mkdir(parents=True,exist_ok=True)
    gt={};gtduplicates=0
    gt_path = root/'gt.csv' if (root/'gt.csv').exists() else root/'data/gt.csv'
    with gt_path.open(encoding='utf-8-sig',newline='') as f:
        for r in csv.DictReader(f):
            if r['selector'] not in ('S1','S2','S3'): continue
            key=(r['selector'],int(r['run']),r['code'])
            if key in gt: gtduplicates+=1
            gt[key]=int(r['sent'])
    if gtduplicates: raise ValueError('Duplicate ground truth keys; select a unique acquisition first')
    calibration=json.loads((root/'calib.json').read_text(encoding='utf-8'))
    lengths={int(k):([v] if isinstance(v,str) else v) for k,v in calibration.items()}
    rows=[];evidence=[];plain_rows=[];hashes=[];spis=Counter();all_tuples=defaultdict(set)
    files=sorted((root/'pcap').glob('S[123]-[0-9][0-9]_esr1.pcap'))
    expected={(s,r) for s in ('S1','S2','S3') for r in range(1,16)}
    keys=set()
    for path in files:
        selector=path.name[:2];run=int(path.name[3:5]);key=(selector,run)
        if key in keys: raise ValueError('Duplicate acquisition')
        keys.add(key);tag=f'{selector}-{run:02d}'
        rng=random.Random(f'{selector}-{run}')
        planned=rng.choices(list(DESTS),weights=[d[2] for d in DESTS.values()],k=1000)
        planned_counts=Counter(planned)
        tun=Counter();plain=Counter();seen_ids=Counter();seen_esp=Counter();ports=set()
        unknown=fragmented=truncated=metadata=ext_icmp=cisco_icmp=invalid_tag=payload_mismatch=0
        vt=vp=0;times=[];tunseq=defaultdict(list);leak_tuples=set();capture_ids=[]
        for p in packets(path):
            truncated+=int(p['truncated']);fragmented+=int(p['fragment'])
            if p['proto']==50 and p['src']=='10.0.1.2' and p['dst']=='10.0.2.2':
                if p['fragment'] or p['truncated'] or 'spi' not in p:
                    unknown+=1;continue
                code=classify_length(p['ip_len'],lengths)
                seen_esp[(p['spi'],p['esp_seq'])]+=1;tunseq[p['spi']].append(p['esp_seq'])
                spis[f'{selector}:{p["spi"]:08x}']+=1
                if code is None: unknown+=1;continue
                tun[code]+=1;vt+=p['ip_len'];times.append(p['timestamp'])
            elif p['proto']==17 and p['src']=='192.168.10.100' and p.get('dport')==50074 and p['dst'] in BYIP:
                code=BYIP[p['dst']];plain[code]+=1;vp+=p['ip_len'];times.append(p['timestamp']);ports.add(p['sport'])
                m=TAG.match(p.get('udp_payload',b''));status='invalid'
                if m:
                    observed_tag=m[1].decode();seq=int(m[2]);observed_code=m[3].decode()
                    seen_ids[(observed_tag,seq)]+=1
                    status='ok' if observed_tag==tag and 0<=seq<1000 and planned[seq]==code==observed_code else 'mismatch'
                    head=f'NET25-038|{tag}|{seq}|{code}|'.encode()
                    want=(head+b'x'*DESTS[code][1])[:DESTS[code][1]]
                    if p['udp_payload']!=want: payload_mismatch+=1;status='mismatch'
                else: invalid_tag+=1;seq=-1;observed_tag='';observed_code=''
                plain_rows.append(dict(run_tag=tag,frame=p['frame'],seq=seq,code=code,status=status,src=p['src'],dst=p['dst'],sport=p['sport'],dport=p['dport'],ip_len=p['ip_len']))
            if p['proto']==1 and p.get('icmp_type')==3 and p.get('icmp_code')==3:
                q=p.get('quoted')
                if not q or q['src']!='192.168.10.100' or q['proto']!=17 or q.get('dport')!=50074 or q['dst'] not in BYIP: continue
                code=BYIP[q['dst']]
                if p['src']=='10.0.2.2':
                    cisco_icmp+=1
                    if code=='P':
                        metadata+=1
                        leak_tuples.add((q['src'],q['dst'],17,q['sport'],q['dport']))
                        all_tuples[selector].add((q['src'],q['dst'],17,q['sport'],q['dport']))
                if p['src'] in ('203.0.113.10','198.51.100.10'): ext_icmp+=1
                qm=TAG.match(q.get('udp_payload',b''));quote_status='header_only';quote_seq=''
                if qm:
                    quote_seq=int(qm[2]);quote_status='ok' if qm[1].decode()==tag and 0<=quote_seq<1000 and planned[quote_seq]==code==qm[3].decode() else 'mismatch'
                evidence.append(dict(run_tag=tag,pcap=path.name,frame=p['frame'],timestamp=p['timestamp'],outer_src=p['src'],outer_dst=p['dst'],ip_len=p['ip_len'],icmp_type=3,icmp_code=3,inner_src=q['src'],inner_dst=q['dst'],inner_proto=17,inner_sport=q['sport'],inner_dport=q['dport'],inner_ip_id=q['ip_id'],inner_ip_len=q['ip_len'],quote_bytes=len(p['payload'])-8,quote_payload_bytes=len(q.get('udp_payload',b'')),quote_seq=quote_seq,quote_validation=quote_status,protected_class=int(code=='P'),scope='Cisco local Loopback' if p['src']=='10.0.2.2' else 'provider Loopback'))
        n=sum(tun.values());total=n+sum(plain.values());excess=n-tun['P']
        mismatches=sum(tun[c]+plain[c]!=gt.get((selector,run,c),-1) for c in DESTS)
        seed_mismatches=sum(planned_counts[c]!=gt.get((selector,run,c),-1) for c in DESTS)
        expected_plain={i for i,c in enumerate(planned) if c not in {'S1':{'P'},'S2':{'P','N1','N2'},'S3':set(DESTS)}[selector]}
        observed_plain={seq for (rt,seq) in seen_ids if rt==tag}
        if not n or not tun['P']: raise ValueError(f'{tag}: insufficient class evidence to calculate ratios')
        row=dict(selector=selector,run=run,run_tag=tag,pcap=path.name,sent=sum(gt.get((selector,run,c),0) for c in DESTS),captured_at_WAN=total,
                 **{'tun_'+c:tun[c] for c in DESTS},**{'plain_'+c:plain[c] for c in DESTS},
                 esp_unknown=unknown,aggregate_class_mismatches=mismatches,seed_class_mismatches=seed_mismatches,
                 plain_expected=len(expected_plain),plain_unique_ids=len(observed_plain),plain_missing_ids=len(expected_plain-observed_plain),plain_unexpected_ids=len(observed_plain-expected_plain),
                 plain_duplicate_ids=sum(v-1 for v in seen_ids.values()),plain_invalid_tags=invalid_tag,plain_payload_mismatch=payload_mismatch,
                 esp_duplicate_spi_seq=sum(v-1 for v in seen_esp.values()),esp_spi_count=len(tunseq),
                 esp_internal_sequence_gaps=sum(max(v)-min(v)+1-len(set(v)) for v in tunseq.values()),
                 truncated_ipv4=truncated,fragmented_ipv4=fragmented,Y1=100*n/total,Y2=100*excess/n,Y3=100*excess/tun['P'],
                 observed_plain_P=plain['P'],V_ESP=vt,V_plain=vp,V_WAN=vt+vp,excess_ESP_bytes_pct=100*(vt-300*tun['P'])/vt,
                 Cisco_ICMP=cisco_icmp,P_metadata_ICMP=metadata,external_ICMP=ext_icmp,unique_P_5tuples=len(leak_tuples),
                 first_to_last_outgoing_seconds=max(times)-min(times) if times else None)
        rows.append(row);hashes.append(dict(path='pcap/'+path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size))
    if keys!=expected: raise ValueError(f'Unexpected acquisitions: missing={expected-keys}, extra={keys-expected}')
    stats=[]
    for selector in ('S1','S2','S3'):
        selected=[r for r in rows if r['selector']==selector]
        for metric in ('Y1','Y2','Y3','V_ESP','V_plain','V_WAN','excess_ESP_bytes_pct'):
            stats.append(dict(selector=selector,metric=metric,**summary([r[metric] for r in selected])))
    totals={s:{k:sum(r[k] for r in rows if r['selector']==s) for k in ('sent','captured_at_WAN','plain_expected','plain_unique_ids','P_metadata_ICMP','Cisco_ICMP','external_ICMP')} for s in ('S1','S2','S3')}
    for s in totals: totals[s]['unique_P_5tuples_across_runs']=len(all_tuples[s])
    report=dict(scope='Retrospective WAN audit, not endpoint delivery measurement',runs=len(rows),class_comparisons=5*len(rows),
                aggregate_mismatches=sum(r['aggregate_class_mismatches'] for r in rows),seed_mismatches=sum(r['seed_class_mismatches'] for r in rows),
                totals=totals,statistics=stats,limitations=['No pre-encryption or post-decryption capture','No receiver log','ESP class attribution conditional on disjoint calibrated lengths','No CPU or service goodput data','No full independent audit baseline'])
    for name,data in [('runs.csv',rows),('statistics.csv',stats),('icmp_evidence.csv',evidence),('plain_packet_validation.csv',plain_rows),('sha256.csv',hashes)]: write_csv(out/name,data)
    (out/'audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    print(json.dumps(audit(a.root,a.out),ensure_ascii=False,indent=2))
