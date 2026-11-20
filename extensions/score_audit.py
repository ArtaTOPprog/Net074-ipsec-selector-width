#!/usr/bin/env python3
"""Score independent binary event labels; missing predictions are unknown.

Truth CSV: event_id,truth (0 or 1). Prediction CSV: event_id,prediction
(0, 1 or unknown). Event universe must be fixed BEFORE inspecting methods.
"""
import argparse,csv,json
def read_unique(path,column):
    with open(path,encoding='utf-8-sig',newline='') as f:
        rows=list(csv.DictReader(f))
    result={r['event_id']:r[column] for r in rows}
    if len(result)!=len(rows): raise ValueError('Duplicate event IDs')
    return result
def score(truth,pred):
    if set(pred)-set(truth): raise ValueError('Predictions contain events outside the fixed truth universe')
    if set(truth.values())-{'0','1'} or set(pred.values())-{'0','1','unknown'}: raise ValueError('Invalid labels')
    c={k:0 for k in ('TP','FP','FN','TN','unknown_positive','unknown_negative')}
    for eid,t in truth.items():
        p=pred.get(eid,'unknown')
        if p=='unknown': c['unknown_positive' if t=='1' else 'unknown_negative']+=1
        else: c[{('1','1'):'TP',('0','1'):'FP',('1','0'):'FN',('0','0'):'TN'}[(t,p)]]+=1
    def ratio(a,b): return a/b if b else None
    return dict(**c,precision=ratio(c['TP'],c['TP']+c['FP']),recall_on_decided=ratio(c['TP'],c['TP']+c['FN']),
                recall_lower_bound=ratio(c['TP'],c['TP']+c['FN']+c['unknown_positive']),
                FPR_on_decided=ratio(c['FP'],c['FP']+c['TN']),coverage=ratio(len(truth)-c['unknown_positive']-c['unknown_negative'],len(truth)))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--truth',required=True);p.add_argument('--prediction',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    r=score(read_unique(a.truth,'truth'),read_unique(a.prediction,'prediction'))
    with open(a.out,'x',encoding='utf-8') as f: json.dump(r,f,indent=2)
