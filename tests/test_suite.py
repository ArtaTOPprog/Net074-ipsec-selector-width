"""Offline parser, uncertainty, schedule and packet-validation regression tests."""
import json,socket,struct,tempfile,unittest,threading,time
from pathlib import Path
from collections import Counter
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "extensions"))
from pcapio import packets,CaptureError
from traffic_v2 import make_plan,payload,parse_payload,send,receive
from audit_legacy import classify_length
from score_audit import score
from schedule import schedule
from validate_v2 import validate

def udp_packet(body,dst='192.168.20.10'):
    udp=struct.pack('!HHHH',40074,50074,len(body)+8,0)+body
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(udp)+20,1,0,64,17,0,socket.inet_aton('192.168.10.100'),socket.inet_aton(dst))+udp
    return b'\0'*12+b'\x08\0'+ip
def pcap_file(path,frames):
    b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for frame in frames: b+=struct.pack('<IIII',1,0,len(frame),len(frame))+frame
    path.write_bytes(b)

class Tests(unittest.TestCase):
    def test_identity_and_ambiguous_length(self):
        b=payload('a'*32,4,'P',200);self.assertEqual(len(b),200)
        self.assertEqual(parse_payload(b)['seq'],4)
        self.assertIsNone(classify_length(300,{300:['P','N1']}))
        self.assertIsNone(classify_length(301,{300:['P']}))
        self.assertEqual(classify_length(300,{300:['P']}),'P')
    def test_plan_independent_of_selector_and_overlap(self):
        a=make_plan('42',1000,'equal');b=make_plan('42',1000,'equal')
        self.assertEqual(a,b);self.assertEqual({r['size'] for r in a['packets']},{512})
        self.assertEqual(len({r['code'] for r in a['packets']}),5)
    def test_schedule_positions_and_blocks(self):
        rows=schedule('test');self.assertEqual(len(rows),45)
        self.assertEqual(set(Counter((r['selector'],r['position']) for r in rows).values()),{5})
        for block in range(1,16): self.assertEqual({r['selector'] for r in rows if r['block']==block},{'S1','S2','S3'})
    def test_pcap_short_record(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'t.pcap';pcap_file(p,[udp_packet(b'test')]);self.assertEqual(len(list(packets(p))),1)
            p.write_bytes(p.read_bytes()[:-1])
            with self.assertRaises(CaptureError): list(packets(p))
    def test_vlan_offset(self):
        frame=udp_packet(b'test');tagged=frame[:12]+b'\x81\x00\0\1\x08\0'+frame[14:]
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'v.pcap';pcap_file(p,[tagged]);self.assertEqual(list(packets(p))[0]['dport'],50074)
    def test_unknown_is_not_negative(self):
        r=score({'a':'1','b':'0','c':'1'},{'a':'1','b':'0'})
        self.assertEqual(r['recall_lower_bound'],.5);self.assertEqual(r['recall_on_decided'],1)
        self.assertEqual(r['unknown_positive'],1)
    def test_no_receiver_data_no_loss_claim(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'sent.jsonl'
            rows=[dict(schema='net074.log.v2',kind='sender_start',acquisition_id='a'*32,monotonic_ns=0),dict(schema='net074.log.v2',kind='send',acquisition_id='a'*32,seq=0,code='P',success=True,bytes=200,dst='192.168.20.10',sha256='x',monotonic_ns=1),dict(schema='net074.log.v2',kind='sender_stop',monotonic_ns=1000000000)]
            p.write_text('\n'.join(json.dumps(r) for r in rows),encoding='utf-8')
            r=validate(p);self.assertIsNone(r['receiver_loss_pct']);self.assertFalse(r['all_packets_accounted_for'])
    def test_duplicate_truth_rejected(self):
        with self.assertRaises(ValueError): score({'a':'1'},{'b':'1'})
    def test_udp_loopback_delivery(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td);plan=make_plan('integration',20,'equal',{c:'127.0.0.1' for c in ('P','N1','N2','E1','E2')})
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
            for r in plan['packets']:r['port']=port
            (td/'plan.json').write_text(json.dumps(plan),encoding='utf-8')
            errors=[]
            def server():
                try:receive('127.0.0.1',port,td/'rx.jsonl',1.2)
                except Exception as e:errors.append(e)
            th=threading.Thread(target=server);th.start()
            deadline=time.perf_counter()+3
            while not (td/'rx.jsonl').exists() and time.perf_counter()<deadline:time.sleep(.01)
            send(td/'plan.json','127.0.0.1',0,100,td/'tx.jsonl',.3)
            th.join(3);self.assertFalse(th.is_alive());self.assertEqual(errors,[])
            result=validate(td/'tx.jsonl',[td/'rx.jsonl'])
            self.assertEqual(result['sent_success'],20);self.assertEqual(result['receiver_unique'],20)
            self.assertEqual(result['replies_unique'],20);self.assertEqual(result['receiver_loss_pct'],0)
            self.assertFalse(result['independent_packet_evidence_complete'])

if __name__=='__main__': unittest.main(verbosity=2)
