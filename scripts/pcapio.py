"""Strict classic-PCAP IPv4 reader. No length-based attribution is performed here."""
import struct
import socket

class CaptureError(ValueError):
    pass

def ipv4(data, quoted=False):
    if len(data)<20 or data[0]>>4 != 4:
        return None
    ihl=(data[0]&15)*4
    total=struct.unpack_from('!H',data,2)[0]
    if ihl<20 or total<ihl or len(data)<ihl:
        raise CaptureError('Invalid IPv4 header')
    flags=struct.unpack_from('!H',data,6)[0]
    d={'src':socket.inet_ntoa(data[12:16]),'dst':socket.inet_ntoa(data[16:20]),
       'proto':data[9],'ip_len':total,'ip_id':struct.unpack_from('!H',data,4)[0],
       'fragment':bool(flags&0x3fff),'fragment_offset':flags&0x1fff,
       'truncated':len(data)<total,'payload':data[ihl:min(len(data),total)]}
    b=d['payload']
    if d['fragment_offset']==0:
        if d['proto']==17 and len(b)>=8:
            d.update(zip(('sport','dport','udp_len','udp_checksum'),struct.unpack_from('!HHHH',b)))
            d['udp_payload']=b[8:]
        if d['proto']==50 and len(b)>=8:
            d['spi'],d['esp_seq']=struct.unpack_from('!II',b)
        if d['proto']==1 and len(b)>=8:
            d['icmp_type'],d['icmp_code']=b[:2]
            if b[0] in (3,4,5,11,12):
                d['quoted']=ipv4(b[8:],quoted=True)
    return d

def ip_offset(linktype,b):
    if linktype==1:
        if len(b)<14: raise CaptureError('Short Ethernet header')
        off=14; et=struct.unpack_from('!H',b,12)[0]
        while et in (0x8100,0x88a8,0x9100):
            if len(b)<off+4: raise CaptureError('Short VLAN header')
            et=struct.unpack_from('!H',b,off+2)[0]; off+=4
        return off if et==0x0800 else None
    if linktype==113:
        if len(b)<16: raise CaptureError('Short SLL header')
        return 16 if b[14:16]==b'\x08\x00' else None
    if linktype==276:
        if len(b)<20: raise CaptureError('Short SLL2 header')
        return 20 if b[:2]==b'\x08\x00' else None
    if linktype in (101,228): return 0
    if linktype==0:
        if len(b)<4: raise CaptureError('Short loopback header')
        return 4 if b[:4] in (b'\x02\0\0\0',b'\0\0\0\x02') else None
    raise CaptureError(f'Unsupported linktype {linktype}; convert with editcap')

def packets(path):
    with open(path,'rb') as f:
        h=f.read(24)
        if len(h)!=24: raise CaptureError('Short PCAP global header')
        formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),
                 b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
        if h[:4] not in formats: raise CaptureError('Classic PCAP required; convert pcapng with editcap -F pcap')
        endian,scale=formats[h[:4]]
        version=struct.unpack_from(endian+'HH',h,4)
        if version!=(2,4): raise CaptureError(f'Unsupported PCAP version {version}')
        linktype=struct.unpack_from(endian+'I',h,20)[0]&0xffff
        number=0
        while True:
            rh=f.read(16)
            if not rh: break
            if len(rh)!=16: raise CaptureError('Truncated PCAP record header')
            sec,frac,caplen,wirelen=struct.unpack(endian+'IIII',rh)
            if caplen>64*1024*1024 or caplen>wirelen: raise CaptureError('Invalid capture length')
            b=f.read(caplen); number+=1
            if len(b)!=caplen: raise CaptureError('Truncated PCAP record data')
            off=ip_offset(linktype,b)
            if off is None: continue
            d=ipv4(b[off:])
            if d:
                d.update(frame=number,timestamp=sec+frac/scale,caplen=caplen,wirelen=wirelen)
                yield d
