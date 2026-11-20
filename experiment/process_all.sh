#!/usr/bin/env bash
# Same analyze.py -> stats.py pipeline as on the screenshot. Inputs stay read-only.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON=${PYTHON:-python3}
if (( $# > 2 )); then echo 'Usage: ./process_all.sh [source_dir] [new_output_dir]' >&2; exit 2; fi
SOURCE=${1:-"$ROOT/data/legacy"}
OUTPUT=${2:-"$ROOT/results/local/historical"}
if [[ -e "$OUTPUT" ]]; then echo "Выходная папка уже есть: $OUTPUT. Выберите новое имя." >&2; exit 2; fi
GT="$SOURCE/data/gt.csv"
if [[ ! -f "$GT" ]]; then GT="$SOURCE/gt.csv"; fi
[[ -f "$SOURCE/calib.json" && -f "$GT" ]] || { echo 'Нужны calib.json и gt.csv' >&2; exit 2; }
for SEL in S1 S2 S3; do
  for RUN in {1..15}; do
    printf -v R '%02d' "$RUN"
    [[ -s "$SOURCE/pcap/${SEL}-${R}_esr1.pcap" ]] || { echo "Нет $SEL-$R" >&2; exit 2; }
  done
done
mkdir -p -- "$OUTPUT"
for SEL in S1 S2 S3; do
  for RUN in {1..15}; do
    printf -v R '%02d' "$RUN"
    "$PYTHON" "$SCRIPT_DIR/analyze.py" run "$SOURCE/pcap/${SEL}-${R}_esr1.pcap" --selector "$SEL" --run "$RUN" --calib "$SOURCE/calib.json" --gt "$GT" --out "$OUTPUT/results.csv"
  done
done
echo 'Разобрано прогонов: 45 (15 для каждого селектора)'
"$PYTHON" "$SCRIPT_DIR/stats.py" --inp "$OUTPUT/results.csv" --outdir "$OUTPUT"
echo 'Это историческая агрегатная обработка. Исправленный разбор ICMP и пакетных ID: scripts/audit_legacy.py.'
