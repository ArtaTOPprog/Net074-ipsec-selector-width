#!/usr/bin/env bash
# ESR branch of the original screenshot workflow; no SSH password or selector changes.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# -ne 3 || "$1" != esr || ! "$2" =~ ^S[123]$ || ! "$3" =~ ^[0-9]{1,2}$ ]]; then
  echo 'Использование: ./run.sh esr S1|S2|S3 номер(1..15)' >&2; exit 2
fi
SEL=$2
RUN=$((10#$3))
if (( RUN < 1 || RUN > 15 )); then echo 'Номер прогона: 1..15' >&2; exit 2; fi
RATE=${RATE:-200}
if [[ ! "$RATE" =~ ^[0-9]+([.][0-9]+)?$ || "$RATE" =~ ^0+([.]0+)?$ ]]; then echo 'RATE должен быть положительным' >&2; exit 2; fi
PYTHON=${PYTHON:-python3}
WORK_DIR=${WORK_DIR:-"$SCRIPT_DIR/../results/local/acquisition"}
TFTP_DIR=${TFTP_DIR:-/srv/tftp}
mkdir -p -- "$WORK_DIR"
cd -- "$WORK_DIR"
mkdir -p pcap data
printf -v R '%02d' "$RUN"
F="${SEL}-${R}_esr1.pcap"
if [[ -e "pcap/$F" || -e "$TFTP_DIR/$F" ]]; then
  echo "Файл $F уже существует. Для новой серии выберите новый WORK_DIR и свободное имя в TFTP." >&2; exit 2
fi
# Do not append another acquisition with the same selector/run to an existing log.
"$PYTHON" - "$SEL" "$RUN" <<'PY'
import csv,sys
from pathlib import Path
p=Path('data/gt.csv')
if p.exists():
    with p.open(encoding='utf-8-sig',newline='') as f:
        if any(r['selector']==sys.argv[1] and int(r['run'])==int(sys.argv[2]) for r in csv.DictReader(f)):
            raise SystemExit('Такой прогон уже есть в gt.csv; выберите новый WORK_DIR')
PY
echo "Прогон $SEL-$R (площадка A: esr)"
echo 'Разогрев туннеля...'
if ping -c3 -W1 192.168.20.10 >/dev/null 2>&1; then echo 'P отвечает'; else echo 'P не отвечает: проверьте стенд'; fi
echo 'ШАГ 1. В окне ESR введите:'
echo "  monitor gigabitethernet 1/0/1 packets 3000 file flash:data/$F"
read -rp 'ШАГ 2. Захват идёт? Нажмите Enter для отправки трафика... '
"$PYTHON" "$SCRIPT_DIR/gen.py" --selector "$SEL" --run "$RUN" --rate "$RATE" --out data/gt.csv
echo 'ШАГ 3. На ESR: Ctrl+C, затем:'
echo "  copy flash:data/$F tftp://192.168.10.100:/$F"
read -rp 'Нажмите Enter после копирования... '
if [[ ! -s "$TFTP_DIR/$F" ]]; then echo "Нет файла $TFTP_DIR/$F; заберите его вручную" >&2; exit 1; fi
# Copy only this acquisition; never move all files from a shared TFTP directory.
"$PYTHON" - "$TFTP_DIR/$F" "pcap/$F" <<'PY'
from pathlib import Path
import shutil,sys
with Path(sys.argv[1]).open('rb') as src,Path(sys.argv[2]).open('xb') as dst:
    shutil.copyfileobj(src,dst)
print(f'ГОТОВО: {Path(sys.argv[2]).resolve()}')
PY
echo 'Скрипт не меняет селектор и не подтверждает состояние SA: это проверяется на шлюзах отдельно.'
