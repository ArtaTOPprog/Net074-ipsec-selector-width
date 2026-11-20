#!/usr/bin/env python3
"""
NET25-038 / NET-074 — генератор синтетического трафика.

Отправляет N UDP-пакетов на 5 назначений (P, N1, N2, E1, E2) в случайном
порядке с заданными весами. У каждого назначения свой размер нагрузки,
поэтому по длине ESP-пакета потом можно понять, к кому он шёл.

Root не нужен. Пишет «истину» (сколько чего отправлено) в gt.csv.

Примеры:
  python3 gen.py --selector S1 --run 1
  python3 gen.py --selector S3 --run 1 --count 1000 --rate 200
  python3 gen.py --calibrate          # по 20 пакетов на каждое назначение, по очереди
"""
import argparse
import csv
import os
import random
import socket
import time
from datetime import datetime

# код, адрес, в плане?, вес, размер UDP-нагрузки
DESTS = [
    ("P",  "192.168.20.10", 1, 0.40, 200),
    ("N1", "192.168.20.20", 0, 0.15, 400),
    ("N2", "192.168.20.30", 0, 0.15, 600),
    ("E1", "203.0.113.10",  0, 0.15, 800),
    ("E2", "198.51.100.10", 0, 0.15, 1000),
]
DPORT = 50074          # порт назначения тестового трафика (фильтр при анализе)
MAGIC = b"NET25-038"   # метка в нагрузке, видна в открытом трафике


def payload(size, run, seq, code):
    head = MAGIC + f"|{run}|{seq}|{code}|".encode()
    return (head + b"x" * size)[:size]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selector", default="S1", help="S1 | S2 | S3 (только для журнала)")
    ap.add_argument("--run", type=int, default=1, help="номер повтора 1..15")
    ap.add_argument("--count", type=int, default=1000, help="пакетов за прогон")
    ap.add_argument("--rate", type=float, default=200.0, help="пакетов в секунду")
    ap.add_argument("--out", default="data/gt.csv", help="файл истины")
    ap.add_argument("--calibrate", action="store_true",
                    help="калибровка: по 20 пакетов на каждое назначение по очереди")
    a = ap.parse_args()

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gap = 1.0 / a.rate

    if a.calibrate:
        seq_codes = [d for d in DESTS for _ in range(20)]
        run_tag = "CAL"
    else:
        # зерно = селектор + номер повтора: прогон воспроизводим
        rnd = random.Random(f"{a.selector}-{a.run}")
        seq_codes = rnd.choices(DESTS, weights=[d[3] for d in DESTS], k=a.count)
        run_tag = f"{a.selector}-{a.run:02d}"

    sent = {d[0]: 0 for d in DESTS}
    t0 = time.time()
    nxt = time.perf_counter()
    for seq, (code, ip, _plan, _w, size) in enumerate(seq_codes):
        sock.sendto(payload(size, run_tag, seq, code), (ip, DPORT))
        sent[code] += 1
        nxt += gap
        delay = nxt - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
    dur = time.time() - t0

    new = not os.path.exists(a.out)
    with open(a.out, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp", "run_tag", "selector", "run", "code", "dst",
                        "in_plan", "size", "sent"])
        ts = datetime.now().isoformat(timespec="seconds")
        for code, ip, plan, _w, size in DESTS:
            w.writerow([ts, run_tag, "CAL" if a.calibrate else a.selector,
                        0 if a.calibrate else a.run, code, ip, plan, size, sent[code]])

    total = sum(sent.values())
    print(f"[{run_tag}] отправлено {total} пакетов за {dur:.1f} с: "
          + ", ".join(f"{k}={v}" for k, v in sent.items()))


if __name__ == "__main__":
    main()
