#!/bin/bash

set -e

DEFAULT_DIR="/srv/evmtest"
DEFAULT_RUNNER_COUNTS=100

DIR=${1:-$DEFAULT_DIR}
RUNNER_COUNTS=${2:-DEFAULT_RUNNER_COUNTS}

function convert_log() {
    local line=$1
    local test_id=$(echo "$line" | cut -d ';' -f 2)
    local reason=$(echo "$line" | cut -d ';' -f 3 | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));")
    echo "$test_id: $reason"
}

# 1. check how many subdir in the DIR
LAUNCHED_COUNTS=$(ls -l $DIR | grep "^d" | wc -l)
echo "Actual workers launched: $LAUNCHED_COUNTS"

# list un-launched workers
echo -n "Workers not launched: "
for i in $(seq 0 $((RUNNER_COUNTS - 1))); do
  if [[ ! -d "$DIR/$i" ]]; then
    echo -n "$i "
  fi
done
echo

# 2. check how many workers output reports

# ensure there's no stale report files
for SUBDIR in "$DIR"/*/; do
  COUNT=$(find "$SUBDIR" -path "*/report/nightly.*.csv" -type f -not -size 0 | wc -l)
  if [ "$COUNT" -gt 1 ]; then
    echo "Check failed in $SUBDIR: Found stale report files."
    exit 1
  fi
done

FINISH_FOUNDS=$(find "$DIR" -path "*/report/finish.txt" -type f -not -size 0 | wc -l)
echo "Actual workers finished: $FINISH_FOUNDS"
CSV_FOUNDS=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 | wc -l)
echo "Actual workers output reports: $CSV_FOUNDS"
if [ "$FINISH_FOUNDS" -ne "$CSV_FOUNDS" ]; then
  echo "ERROR: Not all finished workers output reports."
fi

echo -n "Workers quit without reports: "
find "$DIR" -mindepth 1 -maxdepth 1 -type d | while read dir; do
  if ! find "$dir" -path "*/report/nightly.*.csv" -type f -not -size 0 | grep -q '.'; then
    echo -n "${dir#$DIR/} "
  fi
done
echo

# 3. statistics
SUCCESS_COUNTS=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 -print0 | xargs -0 grep -hc '^Success;' | awk '{s+=$1} END {print s}')
echo "Success: $SUCCESS_COUNTS"
PANIC_COUNTS=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 -print0 | xargs -0 grep -hc '^Panic;' | awk '{s+=$1} END {print s}')
echo "Panic: $PANIC_COUNTS"
FAIL_COUNTS=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 -print0 | xargs -0 grep -hc '^Fail;' | awk '{s+=$1} END {print s}')
echo "Fail: $FAIL_COUNTS"
echo "Total: $((SUCCESS_COUNTS + PANIC_COUNTS + FAIL_COUNTS))"

echo

if [ "$PANIC_COUNTS" -ne 0 ]; then
  echo "Panic details:"
  output=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 -print0 | xargs -0 grep '^Panic;')
  echo "$output" | while read line; do
    convert_log "$line"
  done
fi

if [ "$FAIL_COUNTS" -ne 0 ]; then
  echo "Fail details:"
  output=$(find "$DIR" -path "*/report/nightly.*.csv" -type f -not -size 0 -print0 | xargs -0 grep '^Fail;')
  echo "$output" | while read line; do
    convert_log "$line"
  done
fi