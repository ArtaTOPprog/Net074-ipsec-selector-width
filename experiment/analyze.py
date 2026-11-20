#!/usr/bin/env python3
"""
NET25-038 / NET-074 — разбор захватов с WAN ESR №1.

1) Калибровка (один раз, захват при S3, gen.py --calibrate):
     python3 analyze.py calibrate pcap/CAL_esr1.pcap
   -> calib.json: длина ESP-пакета (IP total length) -> код назначения

3) Запасной путь без pcap (старые прошивки):
     python3 analyze.py counters --selector S2 --run 7 --esp-out 702

2) Разбор прогона:
     python3 analyze.py run pcap/S2-07_esr1.pcap --selector S2 --run 7
   -> добавляет строку в data/results.csv

Классификация пакетов на WAN ESR №1:
  туннель  = IP proto 50 (ESP), src=10.0.1.2, dst=10.0.2.2 -> код по длине (calib.json)
  открыто  = UDP dport 50074, src из 192.168.10.0/24      -> код по адресу назначения
  остальное (IKE, ARP, ICMP, служебное) игнорируется.
"""
import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import Counter

import struct
from types import SimpleNamespace

ESR1_WAN = "10.0.1.2"
ESR2_WAN = "10.0.2.2"
LAN_A = ipaddress.ip_network("192.168.10.0/24")
DPORT = 50074
DESTS = {  # код: (адрес, в плане?)
    "P": ("192.168.20.10", 1),
    "N1": ("192.168.20.20", 0),
    "N2": ("192.168.20.30", 0),
    "E1": ("203.0.113.10", 0),
    "E2": ("198.51.100.10", 0),
}
ORDER = ["P", "N1", "N2", "E1", "E2"]          # по возрастанию размера пакета
BY_IP = {ip: code for code, (ip, _) in DESTS.items()}


def _ip_offset(linktype, data):
    """Смещение IPv4-заголовка в кадре для частых типов канала."""
    if linktype == 1:                      # Ethernet (+ VLAN-теги)
        off, et = 14, struct.unpack("!H", data[12:14])[0]
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        return off if et == 0x0800 else None
    if linktype == 113:                    # Linux cooked (SLL)
        return 16 if struct.unpack("!H", data[14:16])[0] == 0x0800 else None
    if linktype == 276:                    # Linux cooked v2 (SLL2)
        return 20 if struct.unpack("!H", data[0:2])[0] == 0x0800 else None
    if linktype in (101, 228, 12, 14):     # raw IP
        return 0
    return None


def packets(path):
    """Читает классический pcap без внешних библиотек; отдаёт IPv4-пакеты.
    pcapng сначала перевести: editcap -F pcap in.pcapng out.pcap"""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            sys.exit(f"{path}: пустой или битый файл")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            sys.exit(f"{path}: это pcapng. Переведите: editcap -F pcap {path} out.pcap")
        else:
            sys.exit(f"{path}: неизвестный формат файла")
        linktype = struct.unpack(e + "I", gh[20:24])[0] & 0xFFFF
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            incl = struct.unpack(e + "IIII", rh)[2]
            data = f.read(incl)
            off = _ip_offset(linktype, data)
            if off is None or len(data) < off + 20 or data[off] >> 4 != 4:
                continue
            ihl = (data[off] & 0x0F) * 4
            tot, proto = struct.unpack("!H", data[off + 2:off + 4])[0], data[off + 9]
            ip = SimpleNamespace(
                len=tot, proto=proto,
                src=".".join(map(str, data[off + 12:off + 16])),
                dst=".".join(map(str, data[off + 16:off + 20])), dport=None)
            if proto == 17 and len(data) >= off + ihl + 4:
                ip.dport = struct.unpack("!H", data[off + ihl + 2:off + ihl + 4])[0]
            yield ip


def calibrate(path, out):
    lens = Counter()
    for ip in packets(path):
        if ip.proto == 50 and ip.src == ESR1_WAN and ip.dst == ESR2_WAN:
            lens[ip.len] += 1
    # отбрасываем редкие длины (служебные/ошибочные), оставляем 5 самых частых
    common = sorted(l for l, _ in lens.most_common(5))
    if len(common) != 5:
        sys.exit(f"Ожидалось 5 разных длин ESP, найдено {len(common)}: {dict(lens)}. "
                 "Калибровку нужно снимать при селекторе S3 (всё в туннель).")
    calib = {str(l): code for l, code in zip(common, ORDER)}
    with open(out, "w") as f:
        json.dump(calib, f, indent=2, ensure_ascii=False)
    print("Калибровка (длина ESP -> назначение):")
    for l, code in calib.items():
        print(f"  {l:>5} байт -> {code} ({DESTS[code][0]}), пакетов: {lens[int(l)]}")
    print(f"Сохранено в {out}")


def analyze(path, selector, run, calib_path, gt_path, out):
    with open(calib_path) as f:
        calib = {int(k): v for k, v in json.load(f).items()}
    tun, plain = Counter(), Counter()
    esp_unknown = 0
    for ip in packets(path):
        if ip.proto == 50 and ip.src == ESR1_WAN and ip.dst == ESR2_WAN:
            code = calib.get(ip.len)
            if code:
                tun[code] += 1
            else:
                esp_unknown += 1
        elif ip.proto == 17 and ip.dport == DPORT and \
                ipaddress.ip_address(ip.src) in LAN_A and ip.dst in BY_IP:
            plain[BY_IP[ip.dst]] += 1

    sent = Counter()
    if gt_path and os.path.exists(gt_path):
        with open(gt_path) as f:
            for row in csv.DictReader(f):
                if row["selector"] == selector and int(row["run"]) == run:
                    sent[row["code"]] = int(row["sent"])  # последняя запись прогона

    t_all = sum(tun.values())
    p_all = sum(plain.values())
    out_all = t_all + p_all
    t_plan = sum(tun[c] for c in ORDER if DESTS[c][1])
    t_extra = t_all - t_plan
    plan_all = sum(tun[c] + plain[c] for c in ORDER if DESTS[c][1])

    def pct(a, b):
        return round(100.0 * a / b, 3) if b else ""

    row = {
        "selector": selector, "run": run, "pcap": os.path.basename(path),
        **{f"tun_{c}": tun[c] for c in ORDER},
        **{f"plain_{c}": plain[c] for c in ORDER},
        "esp_unknown": esp_unknown,
        "sent_total": sum(sent.values()) if sent else "",
        "captured_total": out_all,
        "Y1_tunneled_pct": pct(t_all, out_all),                 # доля туннелируемого
        "Y2_excess_of_tunnel_pct": pct(t_extra, t_all),         # лишнее среди туннеля
        "Y2_excess_vs_plan_pct": pct(t_extra, t_plan),          # лишнее относительно плана
        "plan_leak_pct": pct(plan_all - t_plan, plan_all),      # план, ушедший в открытую
        "wan_count_deficit_pct": pct(sum(sent.values()) - out_all, sum(sent.values())) if sent else "",
    }
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    new = not os.path.exists(out)
    with open(out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"[{selector}-{run:02d}] туннель={t_all} открыто={p_all} "
          f"Y1={row['Y1_tunneled_pct']}% Y2(от туннеля)={row['Y2_excess_of_tunnel_pct']}% "
          f"Y2(от плана)={row['Y2_excess_vs_plan_pct']}% утечка плана={row['plan_leak_pct']}% "
          f"недосчёт_WAN={row['wan_count_deficit_pct']}% неопознанных ESP={esp_unknown}")


def counters(selector, run, esp_out, gt_path, out):
    """Запасной путь для прошивок без monitor ... file: вместо pcap берётся
    прирост счётчика исходящих пакетов SA (show security ipsec vpn status VPN1)
    за прогон. Разбивки по назначениям нет, поэтому принимается, что
    запланированный трафик P туннелирован полностью (проверяется при S1)."""
    raise ValueError("По одному счётчику SA нельзя установить класс P, Y2/Y3 или доставку; используйте PCAP.")
    sent = Counter()
    with open(gt_path) as f:
        for row in csv.DictReader(f):
            if row["selector"] == selector and int(row["run"]) == run:
                sent[row["code"]] = int(row["sent"])
    if not sent:
        sys.exit(f"В {gt_path} нет записи для {selector} прогон {run}")
    total = sum(sent.values())
    t_plan = min(sent["P"], esp_out)
    t_extra = esp_out - t_plan

    def pct(a, b):
        return round(100.0 * a / b, 3) if b else ""

    row = {"selector": selector, "run": run, "pcap": "counters",
           **{f"tun_{c}": "" for c in ORDER}, **{f"plain_{c}": "" for c in ORDER},
           "esp_unknown": "", "sent_total": total, "captured_total": esp_out,
           "Y1_tunneled_pct": pct(esp_out, total),
           "Y2_excess_of_tunnel_pct": pct(t_extra, esp_out),
           "Y2_excess_vs_plan_pct": pct(t_extra, t_plan),
           "plan_leak_pct": pct(sent["P"] - t_plan, sent["P"]),
           "wan_count_deficit_pct": ""}
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    new = not os.path.exists(out)
    with open(out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"[{selector}-{run:02d}] по счётчикам: ESP={esp_out} из {total}, "
          f"Y1={row['Y1_tunneled_pct']}% Y2(от туннеля)={row['Y2_excess_of_tunnel_pct']}%")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("calibrate")
    c.add_argument("pcap")
    c.add_argument("--out", default="calib.json")
    r = sub.add_parser("run")
    r.add_argument("pcap")
    r.add_argument("--selector", required=True)
    r.add_argument("--run", type=int, required=True)
    r.add_argument("--calib", default="calib.json")
    r.add_argument("--gt", default="data/gt.csv")
    r.add_argument("--out", default="data/results.csv")
    k = sub.add_parser("counters", help="запасной путь: по счётчику SA")
    k.add_argument("--selector", required=True)
    k.add_argument("--run", type=int, required=True)
    k.add_argument("--esp-out", type=int, required=True,
                   help="прирост Output packets SA за прогон")
    k.add_argument("--gt", default="data/gt.csv")
    k.add_argument("--out", default="data/results.csv")
    a = ap.parse_args()
    print("Исторический анализ: ESP-классы условны по длине; ICMP здесь не анализируется. Для статьи используйте scripts/audit_legacy.py.", file=sys.stderr)
    if a.cmd == "calibrate":
        calibrate(a.pcap, a.out)
    elif a.cmd == "counters":
        counters(a.selector, a.run, a.esp_out, a.gt, a.out)
    else:
        analyze(a.pcap, a.selector, a.run, a.calib, a.gt, a.out)


if __name__ == "__main__":
    main()
