#!/usr/bin/env python3
"""
NET25-038 / NET-074 — итоговая таблица и график.

  python3 stats.py                 # читает data/results.csv
  -> data/summary.csv, data/summary.md (таблица для статьи), data/fig_selector.png

Для каждой ширины селектора: среднее, СКО, 95 % доверительный интервал
по t-распределению Стьюдента (n=15 -> df=14, t=2.145).
"""
import argparse
import csv
import math
import os
from collections import defaultdict

try:
    from scipy import stats as st
except ImportError:
    st = None

METRICS = [
    ("Y1_tunneled_pct", "Доля туннелируемого, %"),
    ("Y2_excess_of_tunnel_pct", "Избыточно туннелируемое (от туннеля), %"),
    ("Y2_excess_vs_plan_pct", "Избыточно туннелируемое (от плана), %"),
    ("plan_leak_pct", "Утечка плана в открытую, %"),
    ("wan_count_deficit_pct", "Недосчёт на WAN по агрегатам, %"),
]
SEL_NAME = {"S1": "точный узел /32", "S2": "подсеть /24", "S3": "широкий префикс 192.0.0.0/2"}


def t_crit(n):
    if n < 2:
        return float("nan")
    if st:
        return st.t.ppf(0.975, n - 1)
    table = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 10: 2.262, 15: 2.1447866879169273, 20: 2.093}
    if n not in table:
        raise ValueError("Для этого n установите scipy; подмена t-критерия значением 1.96 недопустима")
    return table[n]


def summarize(vals):
    n = len(vals)
    m = sum(vals) / n
    sd = math.sqrt(sum((v - m) ** 2 for v in vals) / (n - 1)) if n > 1 else 0.0
    h = t_crit(n) * sd / math.sqrt(n) if n > 1 else float("nan")
    return n, m, sd, m - h, m + h


def main():
    print("Исторические агрегаты: нулевой недосчёт на WAN не доказывает доставку приложению. S3 = 192.0.0.0/2.")
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", default="data/results.csv")
    ap.add_argument("--outdir", default="data")
    a = ap.parse_args()

    data = defaultdict(lambda: defaultdict(list))
    with open(a.inp) as f:
        for row in csv.DictReader(f):
            for key, _ in METRICS:
                if row.get(key, "") != "":
                    data[row["selector"]][key].append(float(row[key]))

    sels = sorted(data)
    rows = []
    for s in sels:
        for key, title in METRICS:
            v = data[s][key]
            if not v:
                continue
            n, m, sd, lo, hi = summarize(v)
            rows.append([s, SEL_NAME.get(s, s), title, n, round(m, 2), round(sd, 2),
                         round(lo, 2), round(hi, 2)])

    os.makedirs(a.outdir, exist_ok=True)
    with open(os.path.join(a.outdir, "summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["selector", "selector_name", "metric", "n", "mean", "sd", "ci95_low", "ci95_high"])
        w.writerows(rows)

    # Markdown-таблица для статьи: строка = селектор, столбцы = главные метрики
    lines = ["| Селектор | n | Доля туннелируемого, % (95 % ДИ) | Избыточно, % от туннеля (95 % ДИ) "
             "| Избыточно, % от плана (95 % ДИ) | Утечка плана, % |",
             "| --- | --- | --- | --- | --- | --- |"]
    for s in sels:
        def cell(key):
            v = data[s][key]
            if not v:
                return "—"
            n, m, sd, lo, hi = summarize(v)
            return f"{m:.1f} [{lo:.1f}; {hi:.1f}]"
        n = len(data[s]["Y1_tunneled_pct"])
        leak = data[s]["plan_leak_pct"]
        leak_s = f"{sum(leak) / len(leak):.1f}" if leak else "—"
        lines.append(f"| {SEL_NAME.get(s, s)} | {n} | {cell('Y1_tunneled_pct')} | "
                     f"{cell('Y2_excess_of_tunnel_pct')} | {cell('Y2_excess_vs_plan_pct')} | "
                     f"{leak_s} |")
    md = "\n".join(lines)
    with open(os.path.join(a.outdir, "summary.md"), "w") as f:
        f.write(md + "\n")
    print(md)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4))
        x = range(len(sels))
        for i, (key, title) in enumerate(METRICS[:2]):
            ms, errs = [], []
            for s in sels:
                n, m, sd, lo, hi = summarize(data[s][key])
                ms.append(m)
                errs.append(0 if math.isnan(hi) else hi - m)
            ax.bar([xi + i * 0.38 - 0.19 for xi in x], ms, 0.36, yerr=errs, capsize=4, label=title)
        ax.set_xticks(list(x))
        ax.set_xticklabels([SEL_NAME.get(s, s) for s in sels])
        ax.set_ylabel("%")
        ax.set_ylim(0, 105)
        ax.set_title("Ширина селектора и доля трафика в туннеле (среднее, 95 % ДИ)")
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(os.path.join(a.outdir, "fig_selector.png"), dpi=200)
        print(f"График: {os.path.join(a.outdir, 'fig_selector.png')}")
    except ImportError:
        print("matplotlib не установлен — график пропущен")


if __name__ == "__main__":
    main()
