#!/usr/bin/env python3
"""Versioned UDP plan, sender and receiver with packet identities and JSONL evidence.

The same plan must be reused across S1/S2/S3 in a block. Acquisition IDs are
unique. No claim about VPN encapsulation is made by this endpoint program.
"""
import argparse,hashlib,json,random,socket,time,uuid
from pathlib import Path
from datetime import datetime,timezone

TARGETS={'P':('192.168.20.10',.40,200),'N1':('192.168.20.20',.15,400),
         'N2':('192.168.20.30',.15,600),'E1':('203.0.113.10',.15,800),'E2':('198.51.100.10',.15,1000)}
MAGIC=b'NET074v2|'

def parse_payload(b):
    if not b.startswith(MAGIC): return None
    parts=b.split(b'|',4)
    if len(parts)!=5: return None
    try:
        aid=parts[1].decode();uuid.UUID(hex=aid);seq=int(parts[2]);code=parts[3].decode()
    except (ValueError,UnicodeError): return None
    if seq<0 or code not in TARGETS: return None
    return dict(acquisition_id=aid,seq=seq,code=code)

def payload(aid,seq,code,size):
    h=f'NET074v2|{aid}|{seq}|{code}|'.encode()
    if size<len(h): raise ValueError('Payload size smaller than identity header')
    return h+b'x'*(size-len(h))

def make_plan(seed,count,profile,overrides=None):
    if count<=0 or profile not in ('disjoint','equal','overlap'): raise ValueError('Invalid plan')
    rng=random.Random(str(seed));codes=rng.choices(list(TARGETS),weights=[x[1] for x in TARGETS.values()],k=count)
    rows=[]
    for seq,c in enumerate(codes):
        size=TARGETS[c][2] if profile=='disjoint' else 512 if profile=='equal' else rng.choice((256,384,512,768))
        rows.append(dict(seq=seq,code=c,dst=(overrides or {}).get(c,TARGETS[c][0]),port=50074,size=size,required=(c=='P')))
    return dict(schema='net074.plan.v2',seed=str(seed),profile=profile,count=count,packets=rows)

def emit(f,kind,**kwargs):
    row=dict(schema='net074.log.v2',kind=kind,wall_ns=time.time_ns(),monotonic_ns=time.perf_counter_ns(),**kwargs)
    f.write(json.dumps(row,ensure_ascii=False)+'\n');f.flush()

def receive(bind,port,out,duration):
    if duration<=0: raise ValueError('duration must be positive')
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((bind,port));s.settimeout(.2)
    with open(out,'x',encoding='utf-8') as f:
        emit(f,'receiver_start',bind=bind,port=port)
        deadline=time.perf_counter()+duration
        while time.perf_counter()<deadline:
            try: b,peer=s.recvfrom(65535)
            except socket.timeout: continue
            identity=parse_payload(b)
            emit(f,'receive',peer_ip=peer[0],peer_port=peer[1],size=len(b),sha256=hashlib.sha256(b).hexdigest(),**(identity or dict(unidentified=True)))
            if identity:
                try:
                    n=s.sendto(b,peer);emit(f,'echo_send',bytes=n,**identity)
                except OSError as e: emit(f,'echo_error',error=str(e),**identity)
        emit(f,'receiver_stop')
    s.close()

def send(plan_path,bind,port,rate,out,grace,aid=None):
    if rate<=0 or grace<0: raise ValueError('rate must be positive; grace nonnegative')
    plan_bytes=Path(plan_path).read_bytes();plan=json.loads(plan_bytes)
    if plan.get('schema')!='net074.plan.v2' or plan['count']<=0 or plan['count']!=len(plan['packets']): raise ValueError('Invalid plan schema or count')
    if [r['seq'] for r in plan['packets']]!=list(range(plan['count'])): raise ValueError('Nonunique or unordered plan sequence')
    aid=uuid.UUID(aid).hex if aid else uuid.uuid4().hex
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((bind,port));s.setblocking(False)
    with open(out,'x',encoding='utf-8') as f:
        emit(f,'sender_start',acquisition_id=aid,source_ip=bind,source_port=s.getsockname()[1],rate=rate,
             plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),profile=plan['profile'],plan_count=plan['count'])
        start=time.perf_counter();i=0;sent_times={};final=None
        while i<len(plan['packets']) or final is None or time.perf_counter()<final:
            now=time.perf_counter()
            if i<len(plan['packets']) and now>=start+i/rate:
                r=plan['packets'][i];b=payload(aid,r['seq'],r['code'],r['size']);identity=dict(acquisition_id=aid,seq=r['seq'],code=r['code'])
                t=time.perf_counter_ns()
                try:
                    n=s.sendto(b,(r['dst'],r['port']));sent_times[r['seq']]=t
                    emit(f,'send',success=(n==len(b)),bytes=n,dst=r['dst'],dport=r['port'],sha256=hashlib.sha256(b).hexdigest(),schedule_lag_ms=max(0,(now-start-i/rate)*1000),**identity)
                except OSError as e: emit(f,'send',success=False,bytes=0,dst=r['dst'],dport=r['port'],error=str(e),**identity)
                i+=1
                if i==len(plan['packets']): final=time.perf_counter()+grace
            try:
                b,peer=s.recvfrom(65535);identity=parse_payload(b);t=time.perf_counter_ns()
                if identity:
                    seq=identity['seq'];valid=identity['acquisition_id']==aid and seq in sent_times and seq<len(plan['packets'])
                    r=plan['packets'][seq] if valid else None
                    valid=bool(valid and peer==(r['dst'],r['port']) and identity['code']==r['code'] and b==payload(aid,seq,r['code'],r['size']))
                    emit(f,'reply',valid=valid,peer_ip=peer[0],peer_port=peer[1],size=len(b),rtt_ms=(t-sent_times[seq])/1e6 if valid else None,**identity)
                else: emit(f,'reply_unidentified',peer_ip=peer[0],peer_port=peer[1],size=len(b))
            except BlockingIOError: pass
            except OSError as e: emit(f,'receive_error',error=str(e))
            if i<len(plan['packets']): time.sleep(min(.001,max(0,start+i/rate-time.perf_counter())))
            else: time.sleep(.001)
        emit(f,'sender_stop',acquisition_id=aid)
    s.close()

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('plan');a.add_argument('--seed',required=True);a.add_argument('--count',type=int,default=1000);a.add_argument('--profile',choices=('disjoint','equal','overlap'),default='equal');a.add_argument('--targets',help='JSON mapping of class to actual lab endpoint IP');a.add_argument('--out',required=True)
    a=sub.add_parser('serve');a.add_argument('--bind',required=True);a.add_argument('--port',type=int,default=50074);a.add_argument('--duration',type=float,default=120);a.add_argument('--out',required=True)
    a=sub.add_parser('send');a.add_argument('--plan',required=True);a.add_argument('--bind',required=True);a.add_argument('--source-port',type=int,default=40074);a.add_argument('--rate',type=float,default=200);a.add_argument('--grace',type=float,default=3);a.add_argument('--acquisition-id');a.add_argument('--out',required=True)
    a=p.parse_args()
    if a.command=='plan':
        targets=json.loads(Path(a.targets).read_text()) if a.targets else None
        with open(a.out,'x',encoding='utf-8') as f: json.dump(make_plan(a.seed,a.count,a.profile,targets),f,ensure_ascii=False,indent=2)
    elif a.command=='serve': receive(a.bind,a.port,a.out,a.duration)
    else: send(a.plan,a.bind,a.source_port,a.rate,a.out,a.grace,a.acquisition_id)

if __name__=='__main__': main()
