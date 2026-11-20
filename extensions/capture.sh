#!/usr/bin/env bash
# Run on a Linux observation host. Preserve stderr: it contains tcpdump drop counters.
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "Usage: $0 interface absolute_output.pcap duration_seconds" >&2; exit 2; fi
iface=$1
outfile=$2
duration=$3
[[ "$outfile" = /* && ! -e "$outfile" && ! -e "$outfile.stderr" ]] || { echo 'Output must be a new absolute path' >&2; exit 2; }
[[ "$duration" =~ ^[1-9][0-9]*$ ]] || { echo 'Duration must be a positive integer' >&2; exit 2; }
# timeout may return 124 after the planned stop; the capture is valid only after its quality check.
status=0
sudo timeout --signal=INT "$duration" tcpdump -i "$iface" -s 0 -U -w "$outfile" 'ip' 2>"$outfile.stderr" || status=$?
[[ "$status" -eq 0 || "$status" -eq 124 ]] || exit "$status"
test -s "$outfile"
cat "$outfile.stderr"
