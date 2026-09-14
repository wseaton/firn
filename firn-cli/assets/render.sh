#!/usr/bin/env bash
# Regenerate the README screenshots by running firn in a real Ghostty
# window and capturing it with macOS screencapture, so the box drawing and
# colors are exactly what a terminal shows. Needs Ghostty, GetWindowID
# (brew install smokris/getwindowid/getwindowid), a working connection
# ($1, default: the default connection), and Screen Recording permission
# for the shell running this.
set -euo pipefail
cd "$(dirname "$0")"

conn="${1:-}"
GHOSTTY=/Applications/Ghostty.app/Contents/MacOS/ghostty

# capture <name> <columns> <rows> <bash script>
capture() {
  local name="$1" cols="$2" rows="$3" script="$4"
  local title="firn" done_marker
  done_marker=$(mktemp -u /tmp/firn-shot.XXXXXX)
  "$GHOSTTY" \
    --title="$title" --window-width="$cols" --window-height="$rows" \
    --window-save-state=never --window-padding-x=18 --window-padding-y=14 \
    --font-size=16 \
    --confirm-close-surface=false --quit-after-last-window-closed=true \
    -e bash -c "
      conn='$conn'
      firn() { command firn \${conn:+-c \"\$conn\"} \"\$@\"; }
      prompt() { printf '\033[32m❯\033[0m %s\n' \"\$1\"; }
      sleep 0.5; printf '\033[2J\033[H'
      $script
      printf '\033[?25l'
      touch '$done_marker'
      while [ -e '$done_marker' ]; do sleep 0.2; done" >/dev/null 2>&1 &
  local id=""
  for _ in $(seq 1 100); do
    [ -e "$done_marker" ] && id=$(GetWindowID Ghostty "$title" 2>/dev/null || true)
    [ -n "$id" ] && break
    sleep 0.2
  done
  [ -n "$id" ] || { echo "no Ghostty window titled $title" >&2; exit 1; }
  sleep 2
  screencapture -x -o -l "$id" "$name.png"
  rm -f "$done_marker"
  sleep 1
  echo "wrote $name.png"
}

Q="SELECT * FROM VALUES
  (1001, 'Acme Corp', 15230.50::number(10,2), '2026-09-01'::date, '2026-09-12 14:03:11.250'::timestamp_ntz, true,  'net 30'),
  (1002, 'Globex',      980.00::number(10,2), '2026-09-03'::date, '2026-09-12 09:41:07.000'::timestamp_ntz, false, NULL),
  (1003, 'Initech',   42117.99::number(10,2), '2026-09-05'::date, NULL,                                         true,  'rush'),
  (1004, 'Umbrella',      7.25::number(10,2), '2026-09-09'::date, '2026-09-13 18:20:45.913'::timestamp_ntz, false, NULL)
  AS t(id, customer, total, ordered, updated, paid, note)"
export Q

capture table 100 11 '
  prompt "firn sql \"SELECT * FROM orders ...\""
  firn sql "$Q"'

capture jsonl 150 12 '
  prompt "firn sql \"SELECT * FROM orders ...\" | jq -c ."
  firn sql "$Q" 2>/dev/null | jq -c .
  echo
  prompt "firn sql --submit \"CALL slow_report()\""
  echo "{\"query_id\":\"01c70e3b-020b-4818-0029-4c872d1b48ee\",\"request_id\":\"8b1f2c9e-...\"}"
  prompt "firn query wait 01c70e3b-020b-4818-0029-4c872d1b48ee"
  echo "{\"query_id\":\"01c70e3b-020b-4818-0029-4c872d1b48ee\",\"status\":\"Success\",\"terminal\":true,\"success\":true}"'

printf 'id,customer,total\n1001,Acme Corp,15230.50\n1002,Globex,980.00\n' > /tmp/orders.csv
capture stage 140 30 '
  cd /tmp
  prompt "firn stage put orders.csv @~/imports/"
  firn stage put orders.csv @~/imports/ --overwrite
  echo
  prompt "firn stage get @~/imports/orders.csv.gz ./restored"
  firn stage get @~/imports/orders.csv.gz ./restored
  echo
  prompt "firn auth status"
  firn auth status'
command firn ${conn:+-c "$conn"} sql 'REMOVE @~/imports/' >/dev/null
rm -rf /tmp/orders.csv /tmp/restored
