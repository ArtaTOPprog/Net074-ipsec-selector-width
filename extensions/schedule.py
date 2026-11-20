#!/usr/bin/env python3
"""15 complete blocks, position-balanced S1/S2/S3, a shared plan seed per block."""
import argparse,csv,itertools,random
def schedule(seed):
    rng=random.Random(str(seed))
    orders=list(itertools.permutations(('S1','S2','S3')))*2+[('S1','S2','S3'),('S2','S3','S1'),('S3','S1','S2')]
    rng.shuffle(orders)
    return [dict(block=b,position=p,selector=s,plan_seed=f'{seed}-block-{b:02d}',require_SA_pre_post=True) for b,order in enumerate(orders,1) for p,s in enumerate(order,1)]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seed',default='NET074-v2');p.add_argument('--out',required=True);a=p.parse_args();rs=schedule(a.seed)
    with open(a.out,'x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rs[0]));w.writeheader();w.writerows(rs)
